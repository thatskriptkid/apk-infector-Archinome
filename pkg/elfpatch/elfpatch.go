// Package elfpatch performs in-place edits of the DT_NEEDED table of an ELF
// shared object. It is used by the native injection vector to make the loader
// pull in an extra library, or to divert a library that is opened by name.
//
// Every edit is length-preserving on purpose: the file size, the program
// headers and the layout of the mapped segments are left untouched, so the
// result stays loadable when the library is mapped straight out of the APK
// (android:extractNativeLibs="false").
package elfpatch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	DT_NULL   = 0
	DT_NEEDED = 1
	DT_STRTAB = 5
	DT_STRSZ  = 10
	DT_SONAME = 14

	PT_LOAD    = 1
	PT_DYNAMIC = 2
)

// DynEntry is one Elf_Dyn slot.
type DynEntry struct {
	Tag     int64
	Val     uint64
	FileOff int64
	Index   int
}

// Needed describes one DT_NEEDED entry and how much room it has in place.
type Needed struct {
	Name     string
	DynIndex int
	DynOff   int64
	StrOff   uint64 // offset of the name inside the string table
	Capacity int    // longest name that still fits, excluding the NUL
}

type phdr struct {
	Type                      uint32
	Flags                     uint32
	Off, Vaddr, Filesz, Memsz uint64
}

type section struct {
	NameOff, Type      uint32
	Off, Size, Entsize uint64
}

// File is a parsed ELF object backed by its raw bytes.
type File struct {
	Path string
	Data []byte

	Class int // 32 or 64

	phdrs    []phdr
	sections []section

	DynOff, DynSize int64
	DynEntSize      int
	Dyn             []DynEntry

	StrTabOff int64 // file offset of the dynamic string table
	StrTabVA  uint64
	StrSz     uint64

	Needed []Needed
	Soname string
}

func le16(b []byte, off int64) (uint16, error) {
	if off < 0 || off+2 > int64(len(b)) {
		return 0, fmt.Errorf("read u16 at %#x out of range", off)
	}
	return binary.LittleEndian.Uint16(b[off:]), nil
}

func le32(b []byte, off int64) (uint32, error) {
	if off < 0 || off+4 > int64(len(b)) {
		return 0, fmt.Errorf("read u32 at %#x out of range", off)
	}
	return binary.LittleEndian.Uint32(b[off:]), nil
}

func le64(b []byte, off int64) (uint64, error) {
	if off < 0 || off+8 > int64(len(b)) {
		return 0, fmt.Errorf("read u64 at %#x out of range", off)
	}
	return binary.LittleEndian.Uint64(b[off:]), nil
}

// Open reads and parses an ELF file.
func Open(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.Path = path
	return f, nil
}

// Parse parses an ELF image held in memory.
func Parse(data []byte) (*File, error) {
	if len(data) < 64 {
		return nil, fmt.Errorf("file too small for an ELF header")
	}
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return nil, fmt.Errorf("not an ELF file")
	}
	if data[5] != 1 {
		return nil, fmt.Errorf("only little-endian ELF is supported")
	}
	f := &File{Data: data}
	switch data[4] {
	case 1:
		f.Class = 32
	case 2:
		f.Class = 64
	default:
		return nil, fmt.Errorf("unknown ELF class %d", data[4])
	}
	if err := f.parseHeaders(); err != nil {
		return nil, err
	}
	if err := f.parseDynamic(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *File) parseHeaders() error {
	var phoff, shoff uint64
	var phentsize, phnum, shentsize, shnum uint16
	var err error
	if f.Class == 64 {
		if phoff, err = le64(f.Data, 32); err != nil {
			return err
		}
		if shoff, err = le64(f.Data, 40); err != nil {
			return err
		}
		if phentsize, err = le16(f.Data, 54); err != nil {
			return err
		}
		if phnum, err = le16(f.Data, 56); err != nil {
			return err
		}
		if shentsize, err = le16(f.Data, 58); err != nil {
			return err
		}
		if shnum, err = le16(f.Data, 60); err != nil {
			return err
		}
	} else {
		var v uint32
		if v, err = le32(f.Data, 28); err != nil {
			return err
		}
		phoff = uint64(v)
		if v, err = le32(f.Data, 32); err != nil {
			return err
		}
		shoff = uint64(v)
		if phentsize, err = le16(f.Data, 42); err != nil {
			return err
		}
		if phnum, err = le16(f.Data, 44); err != nil {
			return err
		}
		if shentsize, err = le16(f.Data, 46); err != nil {
			return err
		}
		if shnum, err = le16(f.Data, 48); err != nil {
			return err
		}
	}

	for i := 0; i < int(phnum); i++ {
		base := int64(phoff) + int64(i)*int64(phentsize)
		var p phdr
		var err error
		if p.Type, err = le32(f.Data, base); err != nil {
			return err
		}
		if f.Class == 64 {
			if p.Flags, err = le32(f.Data, base+4); err != nil {
				return err
			}
			if p.Off, err = le64(f.Data, base+8); err != nil {
				return err
			}
			if p.Vaddr, err = le64(f.Data, base+16); err != nil {
				return err
			}
			if p.Filesz, err = le64(f.Data, base+32); err != nil {
				return err
			}
			if p.Memsz, err = le64(f.Data, base+40); err != nil {
				return err
			}
		} else {
			var v uint32
			if v, err = le32(f.Data, base+4); err != nil {
				return err
			}
			p.Off = uint64(v)
			if v, err = le32(f.Data, base+8); err != nil {
				return err
			}
			p.Vaddr = uint64(v)
			if v, err = le32(f.Data, base+16); err != nil {
				return err
			}
			p.Filesz = uint64(v)
			if v, err = le32(f.Data, base+20); err != nil {
				return err
			}
			p.Memsz = uint64(v)
			if p.Flags, err = le32(f.Data, base+24); err != nil {
				return err
			}
		}
		f.phdrs = append(f.phdrs, p)
	}

	for i := 0; i < int(shnum); i++ {
		base := int64(shoff) + int64(i)*int64(shentsize)
		var s section
		var err error
		if s.NameOff, err = le32(f.Data, base); err != nil {
			return err
		}
		if s.Type, err = le32(f.Data, base+4); err != nil {
			return err
		}
		if f.Class == 64 {
			if s.Off, err = le64(f.Data, base+24); err != nil {
				return err
			}
			if s.Size, err = le64(f.Data, base+32); err != nil {
				return err
			}
			if s.Entsize, err = le64(f.Data, base+56); err != nil {
				return err
			}
		} else {
			var v uint32
			if v, err = le32(f.Data, base+16); err != nil {
				return err
			}
			s.Off = uint64(v)
			if v, err = le32(f.Data, base+20); err != nil {
				return err
			}
			s.Size = uint64(v)
			if v, err = le32(f.Data, base+36); err != nil {
				return err
			}
			s.Entsize = uint64(v)
		}
		f.sections = append(f.sections, s)
	}
	return nil
}

func (f *File) parseDynamic() error {
	var ptDyn *phdr
	for i := range f.phdrs {
		if f.phdrs[i].Type == PT_DYNAMIC {
			ptDyn = &f.phdrs[i]
			break
		}
	}
	if ptDyn == nil {
		return fmt.Errorf("no PT_DYNAMIC segment")
	}
	f.DynOff = int64(ptDyn.Off)
	f.DynSize = int64(ptDyn.Filesz)
	ent := 8
	if f.Class == 64 {
		ent = 16
	}
	f.DynEntSize = ent

	for i := 0; int64(i)*int64(ent) < f.DynSize; i++ {
		base := f.DynOff + int64(i)*int64(ent)
		var tag int64
		var val uint64
		if f.Class == 64 {
			t, err := le64(f.Data, base)
			if err != nil {
				return err
			}
			v, err := le64(f.Data, base+8)
			if err != nil {
				return err
			}
			tag, val = int64(t), v
		} else {
			t, err := le32(f.Data, base)
			if err != nil {
				return err
			}
			v, err := le32(f.Data, base+4)
			if err != nil {
				return err
			}
			tag, val = int64(int32(t)), uint64(v)
		}
		e := DynEntry{Tag: tag, Val: val, FileOff: base, Index: i}
		f.Dyn = append(f.Dyn, e)
		switch tag {
		case DT_STRTAB:
			f.StrTabVA = val
		case DT_STRSZ:
			f.StrSz = val
		}
		if tag == DT_NULL {
			break
		}
	}

	// DT_STRTAB holds a virtual address; translate it through the load segments
	// (in practice it equals the file offset for the layouts used on Android).
	f.StrTabOff = int64(f.StrTabVA)
	if off, ok := f.vaToOffset(f.StrTabVA); ok {
		f.StrTabOff = off
	}
	if f.StrTabOff <= 0 {
		return fmt.Errorf("cannot resolve the dynamic string table")
	}

	for _, e := range f.Dyn {
		switch e.Tag {
		case DT_SONAME:
			if s, err := f.readCString(f.StrTabOff + int64(e.Val)); err == nil {
				f.Soname = s
			}
		case DT_NEEDED:
			name, err := f.readCString(f.StrTabOff + int64(e.Val))
			if err != nil {
				return fmt.Errorf("DT_NEEDED[%d]: %w", e.Index, err)
			}
			f.Needed = append(f.Needed, Needed{
				Name:     name,
				DynIndex: e.Index,
				DynOff:   e.FileOff,
				StrOff:   e.Val,
				Capacity: len(name),
			})
		}
	}
	return nil
}

func (f *File) vaToOffset(va uint64) (int64, bool) {
	for _, p := range f.phdrs {
		if p.Type != PT_LOAD {
			continue
		}
		if va >= p.Vaddr && va < p.Vaddr+p.Filesz {
			return int64(p.Off + (va - p.Vaddr)), true
		}
	}
	return 0, false
}

func (f *File) readCString(off int64) (string, error) {
	if off < 0 || off >= int64(len(f.Data)) {
		return "", fmt.Errorf("string offset %#x out of range", off)
	}
	end := bytes.IndexByte(f.Data[off:], 0)
	if end < 0 {
		return "", fmt.Errorf("unterminated string at %#x", off)
	}
	return string(f.Data[off : off+int64(end)]), nil
}

// NeededEntry returns the DT_NEEDED entry with the given name.
func (f *File) NeededEntry(name string) *Needed {
	for i := range f.Needed {
		if f.Needed[i].Name == name {
			return &f.Needed[i]
		}
	}
	return nil
}

// PickNeeded returns the DT_NEEDED entry with the largest capacity, so a
// replacement name can reuse its slot without growing the file.
func (f *File) PickNeeded(want int) *Needed {
	var best *Needed
	for i := range f.Needed {
		n := &f.Needed[i]
		if n.Capacity < want {
			continue
		}
		if best == nil || n.Capacity > best.Capacity {
			best = n
		}
	}
	return best
}

// RewriteNeeded replaces the name of one DT_NEEDED entry in place. The new name
// must not be longer than the old one; the remainder is NUL padded.
func (f *File) RewriteNeeded(entry *Needed, newName string) error {
	if entry == nil {
		return fmt.Errorf("no DT_NEEDED entry selected")
	}
	if len(newName) == 0 {
		return fmt.Errorf("empty library name")
	}
	if len(newName) > entry.Capacity {
		return fmt.Errorf("name %q does not fit into the %d-byte slot of %q",
			newName, entry.Capacity, entry.Name)
	}
	off := f.StrTabOff + int64(entry.StrOff)
	if off < 0 || off+int64(entry.Capacity) > int64(len(f.Data)) {
		return fmt.Errorf("string slot at %#x is outside the file", off)
	}
	for i := 0; i < entry.Capacity; i++ {
		f.Data[off+int64(i)] = 0
	}
	copy(f.Data[off:], newName)
	entry.Name = newName
	return nil
}

// AddNeeded appends a DT_NEEDED entry, reusing free space that the toolchain
// already left in the dynamic table and the string table. It never grows the
// file; when there is no slack it reports exactly what is missing.
func (f *File) AddNeeded(newName string) error {
	slot, strStart, newStrOff, need, err := f.planAddNeeded(newName)
	if err != nil || slot < 0 {
		return err
	}
	f.writeDyn(slot, DT_NEEDED, newStrOff)
	copy(f.Data[strStart:], newName)
	f.Data[strStart+int64(len(newName))] = 0

	// DT_STRSZ must grow so the loader accepts the new index.
	for i := range f.Dyn {
		if f.Dyn[i].Tag == DT_STRSZ {
			f.Dyn[i].Val = f.StrSz + need
			f.writeDyn(f.Dyn[i].FileOff, DT_STRSZ, f.Dyn[i].Val)
			f.StrSz = f.Dyn[i].Val
			break
		}
	}
	nullIdx := int((slot - f.DynOff) / int64(f.DynEntSize))
	f.Dyn = append(f.Dyn[:nullIdx],
		DynEntry{Tag: DT_NEEDED, Val: newStrOff, FileOff: slot, Index: nullIdx})
	f.Needed = append(f.Needed, Needed{
		Name: newName, DynIndex: nullIdx, DynOff: slot,
		StrOff: newStrOff, Capacity: len(newName),
	})
	return nil
}

// CanAddNeeded reports whether AddNeeded could insert newName right now, and if
// not, why. It changes nothing.
func (f *File) CanAddNeeded(newName string) error {
	if f.NeededEntry(newName) != nil {
		return nil
	}
	_, _, _, _, err := f.planAddNeeded(newName)
	return err
}

// planAddNeeded locates the space AddNeeded would use. A negative slot together
// with a nil error means the dependency is already present.
func (f *File) planAddNeeded(newName string) (slot, strStart int64, newStrOff, need uint64, err error) {
	if len(newName) == 0 {
		return -1, 0, 0, 0, fmt.Errorf("empty library name")
	}
	if f.NeededEntry(newName) != nil {
		return -1, 0, 0, 0, nil
	}
	nullIdx := -1
	for _, e := range f.Dyn {
		if e.Tag == DT_NULL {
			nullIdx = e.Index
			break
		}
	}
	if nullIdx < 0 {
		return -1, 0, 0, 0, fmt.Errorf("no DT_NULL terminator in the dynamic table")
	}
	totalSlots := int(f.DynSize) / f.DynEntSize
	if nullIdx+1 >= totalSlots {
		return -1, 0, 0, 0, fmt.Errorf("dynamic table has no free slots after the terminator")
	}
	// The old terminator becomes our DT_NEEDED entry; the slot after it must
	// already be zero, which makes it a valid new DT_NULL (DT_NULL is tag 0).
	// A single spare slot is therefore enough.
	nextSlot := f.DynOff + int64(nullIdx+1)*int64(f.DynEntSize)
	if nextSlot+int64(f.DynEntSize) > int64(len(f.Data)) ||
		!allZero(f.Data[nextSlot:nextSlot+int64(f.DynEntSize)]) {
		return -1, 0, 0, 0, fmt.Errorf("dynamic table has no free slots after the terminator")
	}
	if f.StrSz == 0 {
		return -1, 0, 0, 0, fmt.Errorf("dynamic string table size is unknown")
	}
	newStrOff = f.StrSz
	need = uint64(len(newName)) + 1
	strStart = f.StrTabOff + int64(f.StrSz)
	limit := f.mappedEnd(strStart)
	if limit < 0 {
		return -1, 0, 0, 0, fmt.Errorf("string table is not inside a mapped segment")
	}
	if room := limit - strStart; room < int64(need) {
		return -1, 0, 0, 0, fmt.Errorf("only %d free bytes after the string table, need %d", room, need)
	}
	if !allZero(f.Data[strStart : strStart+int64(need)]) {
		return -1, 0, 0, 0, fmt.Errorf("%d bytes after the string table are not free", need)
	}
	slot = f.DynOff + int64(nullIdx)*int64(f.DynEntSize)
	return slot, strStart, newStrOff, need, nil
}

func (f *File) writeDyn(off int64, tag int64, val uint64) {
	if f.Class == 64 {
		binary.LittleEndian.PutUint64(f.Data[off:], uint64(tag))
		binary.LittleEndian.PutUint64(f.Data[off+8:], val)
		return
	}
	binary.LittleEndian.PutUint32(f.Data[off:], uint32(int32(tag)))
	binary.LittleEndian.PutUint32(f.Data[off+4:], uint32(val))
}

// StrRoom reports where a new name can be appended to the dynamic string table
// and how many bytes are available there. A negative size means the string table
// does not sit inside a mapped segment, so nothing can be appended.
func (f *File) StrRoom() (off, n int64) {
	strStart := f.StrTabOff + int64(f.StrSz)
	limit := f.mappedEnd(strStart)
	if limit < 0 {
		return strStart, -1
	}
	return strStart, limit - strStart
}

// mappedEnd returns the first file offset past the mapped region that holds off.
func (f *File) mappedEnd(off int64) int64 {
	for _, p := range f.phdrs {
		if p.Type != PT_LOAD {
			continue
		}
		start := int64(p.Off)
		end := int64(p.Off + p.Filesz)
		if off >= start && off < end {
			return end
		}
	}
	return -1
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Save writes the (patched) image back to disk, preserving the file mode.
func (f *File) Save(path string) error {
	mode := os.FileMode(0644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(path, f.Data, mode)
}

// ReplaceBytes swaps every occurrence of old for new inside an arbitrary binary
// image. The replacement must not be longer than the original, so the file
// layout - and therefore any signature over the surrounding data - is unchanged
// in size; shorter replacements are NUL padded.
func ReplaceBytes(data []byte, old, new string) (int, error) {
	if len(old) == 0 {
		return 0, fmt.Errorf("empty pattern")
	}
	if len(new) > len(old) {
		return 0, fmt.Errorf("replacement %q is longer than %q", new, old)
	}
	patched := make([]byte, len(old))
	copy(patched, new)
	n := 0
	off := 0
	for {
		i := bytes.Index(data[off:], []byte(old))
		if i < 0 {
			break
		}
		copy(data[off+i:], patched)
		n++
		off += i + len(old)
	}
	if n == 0 {
		return 0, fmt.Errorf("pattern %q not found", old)
	}
	return n, nil
}
