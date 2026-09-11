package dex

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"os"
)

// validateHeaderHashes checks the two header checksums ART itself verifies
// before it will load a dex: the adler32 at 0x08 (over everything from 0x0c on,
// i.e. including the signature field) and the SHA-1 at 0x0c (over everything
// from 0x20 on). Emitting the signature after the checksum leaves a stale
// checksum, and ART then rejects the whole dex with "Bad checksum" -- the app
// starts with "Unable to instantiate application <wrapper>". Checking here
// turns that into a build-time failure.
func validateHeaderHashes(v *dexView) error {
	if len(v.data) < dexHeaderSize {
		return fmt.Errorf("dex %s: file is shorter than the header (%d bytes)", v.path, len(v.data))
	}
	want := binary.LittleEndian.Uint32(v.data[0x08:])
	if got := adler32.Checksum(v.data[0x0c:]); got != want {
		return fmt.Errorf("dex %s: bad adler32 checksum (header 0x%08x, computed 0x%08x)", v.path, want, got)
	}
	sum := sha1.Sum(v.data[0x20:])
	if !bytes.Equal(sum[:], v.data[0x0c:0x20]) {
		return fmt.Errorf("dex %s: bad SHA-1 signature (header %x, computed %x)", v.path, v.data[0x0c:0x20], sum)
	}
	return nil
}

// Validate re-reads a dex file and returns an error when it is structurally
// unusable, when one of wantClasses is missing, or when the string table is no
// longer sorted.
//
// The Application-hijack vector renames a class inside the stub dex by patching
// strings and offsets in place; a stale fixture (or a rename that breaks the
// string order ART binary-searches) produces a dex that ART cannot load, and
// the app then dies at start with ClassNotFoundException on the device.
// Validating here turns that into a build-time failure instead of a broken APK.

const (
	dexHeaderSize   = 0x70
	dexClassDefSize = 32
	dexStringIDSize = 4
	dexTypeIDSize   = 4
	dexNoIndex      = 0xffffffff
)

type dexView struct {
	path       string
	data       []byte
	fileSize   uint32
	strCount   uint32
	strOff     uint32
	typeCount  uint32
	typeOff    uint32
	classCount uint32
	classOff   uint32
}

func openDex(path string) (*dexView, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dex read %s: %w", path, err)
	}
	if len(data) < dexHeaderSize {
		return nil, fmt.Errorf("dex %s: truncated header (%d bytes)", path, len(data))
	}
	if string(data[0:4]) != "dex\n" {
		return nil, fmt.Errorf("dex %s: bad magic %q", path, string(data[0:4]))
	}
	le := binary.LittleEndian
	v := &dexView{path: path, data: data}
	v.fileSize = le.Uint32(data[0x20:])
	if int(v.fileSize) != len(data) {
		return nil, fmt.Errorf("dex %s: header file_size=0x%x but file is 0x%x bytes",
			path, v.fileSize, len(data))
	}
	if le.Uint32(data[0x28:]) != 0x12345678 {
		return nil, fmt.Errorf("dex %s: bad endian tag", path)
	}
	if mapOff := le.Uint32(data[0x34:]); mapOff == 0 || mapOff >= v.fileSize {
		return nil, fmt.Errorf("dex %s: invalid map_off=0x%x", path, mapOff)
	}
	v.strCount, v.strOff = le.Uint32(data[0x38:]), le.Uint32(data[0x3c:])
	v.typeCount, v.typeOff = le.Uint32(data[0x40:]), le.Uint32(data[0x44:])
	v.classCount, v.classOff = le.Uint32(data[0x60:]), le.Uint32(data[0x64:])

	if err := checkSection(path, "string_ids", v.strOff, v.strCount, dexStringIDSize, v.fileSize); err != nil {
		return nil, err
	}
	if err := checkSection(path, "type_ids", v.typeOff, v.typeCount, dexTypeIDSize, v.fileSize); err != nil {
		return nil, err
	}
	if err := checkSection(path, "class_defs", v.classOff, v.classCount, dexClassDefSize, v.fileSize); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *dexView) le() binary.ByteOrder { return binary.LittleEndian }

// string returns the content of string_ids[idx].
func (v *dexView) str(idx uint32) (string, error) {
	if idx >= v.strCount {
		return "", fmt.Errorf("string index 0x%x out of bounds (%d)", idx, v.strCount)
	}
	dataOff := v.le().Uint32(v.data[v.strOff+idx*dexStringIDSize:])
	if dataOff >= v.fileSize {
		return "", fmt.Errorf("string data offset 0x%x out of bounds", dataOff)
	}
	p := dataOff
	// string_data_item = uleb128 utf16_size + MUTF-8 bytes + NUL
	for {
		if p >= v.fileSize {
			return "", fmt.Errorf("truncated string length at 0x%x", dataOff)
		}
		b := v.data[p]
		p++
		if b&0x80 == 0 {
			break
		}
	}
	start := p
	for p < v.fileSize && v.data[p] != 0 {
		if v.data[p]&0x80 == 0 {
			p++
			continue
		}
		if p+1 >= v.fileSize {
			return "", fmt.Errorf("truncated string data at 0x%x", dataOff)
		}
		p += 2 // MUTF-8 surrogate pair
	}
	return string(v.data[start:p]), nil
}

// typeDescriptor resolves type_ids[idx] to its descriptor.
func (v *dexView) typeDescriptor(idx uint32) (string, error) {
	if idx == dexNoIndex || idx >= v.typeCount {
		return "", fmt.Errorf("type index 0x%x out of bounds (%d)", idx, v.typeCount)
	}
	strIdx := v.le().Uint32(v.data[v.typeOff+idx*dexTypeIDSize:])
	return v.str(strIdx)
}

// classes returns descriptor -> (class_def offset, superclass index).
func (v *dexView) classes() (map[string]struct {
	off      uint32
	superIdx uint32
}, error) {
	out := map[string]struct {
		off      uint32
		superIdx uint32
	}{}
	for i := uint32(0); i < v.classCount; i++ {
		off := v.classOff + i*dexClassDefSize
		desc, err := v.typeDescriptor(v.le().Uint32(v.data[off:]))
		if err != nil {
			return nil, fmt.Errorf("class_defs[%d]: %w", i, err)
		}
		superIdx := v.le().Uint32(v.data[off+8:]) // superclass_idx
		out[desc] = struct {
			off      uint32
			superIdx uint32
		}{off, superIdx}
	}
	return out, nil
}

// Validate checks header/section sanity, the presence of wantClasses and the
// sortedness of the string table (ART resolves strings by binary search).
func Validate(path string, wantClasses ...string) error {
	v, err := openDex(path)
	if err != nil {
		return err
	}
	if err := validateHeaderHashes(v); err != nil {
		return err
	}
	classes, err := v.classes()
	if err != nil {
		return fmt.Errorf("dex %s: %w", path, err)
	}
	for _, want := range wantClasses {
		desc := "L" + replaceDots(want) + ";"
		if _, ok := classes[desc]; !ok {
			return fmt.Errorf("dex %s: class %s (%s) is not defined", path, want, desc)
		}
	}
	prev := ""
	for i := uint32(0); i < v.strCount; i++ {
		s, err := v.str(i)
		if err != nil {
			return fmt.Errorf("dex %s: string_ids[%d]: %w", path, i, err)
		}
		if i > 0 && s < prev {
			return fmt.Errorf("dex %s: string_ids not sorted at index %d (%q < %q)", path, i, s, prev)
		}
		prev = s
	}
	return nil
}

// ValidateSuperclass returns an error unless the class definition of `class`
// (dotted) extends wantSuper (dotted). The injected Application wrapper must
// extend the host's own Application class, so this catches a rename that
// produced a mangled/non-existent base class name.
func ValidateSuperclass(path, class, wantSuper string) error {
	v, err := openDex(path)
	if err != nil {
		return err
	}
	if err := validateHeaderHashes(v); err != nil {
		return err
	}
	classes, err := v.classes()
	if err != nil {
		return fmt.Errorf("dex %s: %w", path, err)
	}
	desc := "L" + replaceDots(class) + ";"
	entry, ok := classes[desc]
	if !ok {
		return fmt.Errorf("dex %s: class %s (%s) is not defined", path, class, desc)
	}
	got, err := v.typeDescriptor(entry.superIdx)
	if err != nil {
		return fmt.Errorf("dex %s: class %s has no resolvable superclass: %w", path, class, err)
	}
	want := "L" + replaceDots(wantSuper) + ";"
	if got != want {
		return fmt.Errorf("dex %s: class %s extends %s, expected %s (the wrapper must extend the host Application class by its fully-qualified name)",
			path, class, got, want)
	}
	return nil
}

func checkSection(path, name string, off, count, itemSize, fileSize uint32) error {
	if count == 0 {
		if off != 0 {
			return fmt.Errorf("dex %s: %s_off=0x%x with zero size", path, name, off)
		}
		return nil
	}
	if off == 0 || off >= fileSize {
		return fmt.Errorf("dex %s: invalid %s_off=0x%x", path, name, off)
	}
	end := uint64(off) + uint64(count)*uint64(itemSize)
	if end > uint64(fileSize) {
		return fmt.Errorf("dex %s: %s section runs past EOF (0x%x > 0x%x)", path, name, end, fileSize)
	}
	return nil
}

func replaceDots(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == '.' {
			b[i] = '/'
		}
	}
	return string(b)
}
