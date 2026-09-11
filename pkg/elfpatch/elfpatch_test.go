package elfpatch

import (
	"bytes"
	"encoding/binary"
	"testing"
)

const (
	synthPhOff    = 0x40
	synthDynstr   = 0xB0
	synthDynOff   = 0xF0
	synthTotal    = 0x200
	synthDynStrsz = 23 // "\0libandroid.so\0libc.so\0"
)

// synthELF builds a minimal but structurally valid ELF64 shared object with
// `dynSlots` Elf_Dyn slots, the last used one being the DT_NULL terminator.
func synthELF(dynSlots int) []byte {
	b := make([]byte, synthTotal)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(b[16:], 3)   // ET_DYN
	binary.LittleEndian.PutUint16(b[18:], 183) // EM_AARCH64
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], synthPhOff)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 2) // two program headers
	binary.LittleEndian.PutUint16(b[58:], 64)
	binary.LittleEndian.PutUint16(b[60:], 0) // no section headers

	// PT_LOAD covering the whole image (vaddr == offset)
	binary.LittleEndian.PutUint32(b[0x40:], PT_LOAD)
	binary.LittleEndian.PutUint64(b[0x40+32:], synthTotal)
	binary.LittleEndian.PutUint64(b[0x40+40:], synthTotal)
	// PT_DYNAMIC
	binary.LittleEndian.PutUint32(b[0x40+56:], PT_DYNAMIC)
	binary.LittleEndian.PutUint64(b[0x40+56+8:], synthDynOff)
	binary.LittleEndian.PutUint64(b[0x40+56+32:], uint64(dynSlots*16))
	binary.LittleEndian.PutUint64(b[0x40+56+40:], uint64(dynSlots*16))

	copy(b[synthDynstr:], "\x00libandroid.so\x00libc.so\x00")

	put := func(i int, tag int64, val uint64) {
		off := synthDynOff + i*16
		binary.LittleEndian.PutUint64(b[off:], uint64(tag))
		binary.LittleEndian.PutUint64(b[off+8:], val)
	}
	put(0, DT_NEEDED, 1)  // libandroid.so
	put(1, DT_NEEDED, 15) // libc.so
	put(2, DT_STRTAB, synthDynstr)
	put(3, DT_STRSZ, synthDynStrsz)
	put(4, DT_NULL, 0)
	return b
}

func parse(t *testing.T, b []byte) *File {
	t.Helper()
	f, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

func TestParseNeeded(t *testing.T) {
	f := parse(t, synthELF(6))
	if len(f.Needed) != 2 {
		t.Fatalf("want 2 DT_NEEDED, got %d", len(f.Needed))
	}
	if f.Needed[0].Name != "libandroid.so" || f.Needed[1].Name != "libc.so" {
		t.Fatalf("unexpected names: %q %q", f.Needed[0].Name, f.Needed[1].Name)
	}
	if f.Needed[0].Capacity != 13 || f.Needed[1].Capacity != 7 {
		t.Fatalf("unexpected capacities: %d %d", f.Needed[0].Capacity, f.Needed[1].Capacity)
	}
	if f.StrTabOff != synthDynstr || f.StrSz != synthDynStrsz {
		t.Fatalf("string table resolved to %#x/%d", f.StrTabOff, f.StrSz)
	}
}

func TestPickNeeded(t *testing.T) {
	f := parse(t, synthELF(6))
	if got := f.PickNeeded(11); got == nil || got.Name != "libandroid.so" {
		t.Fatalf("PickNeeded(11) = %v, want libandroid.so", got)
	}
	if got := f.PickNeeded(14); got != nil {
		t.Fatalf("PickNeeded(14) = %v, want nil (nothing fits)", got)
	}
}

func TestRewriteNeeded(t *testing.T) {
	f := parse(t, synthELF(6))
	e := f.NeededEntry("libandroid.so")
	if e == nil {
		t.Fatal("libandroid.so not found")
	}
	if err := f.RewriteNeeded(e, "libarchin.so"); err != nil {
		t.Fatalf("RewriteNeeded: %v", err)
	}
	// the slot must be NUL padded up to its original length
	got := f.Data[synthDynstr+1 : synthDynstr+1+13]
	if !bytes.Equal(got, []byte("libarchin.so\x00")) {
		t.Fatalf("slot content = %q", got)
	}
	if f.Data[synthDynstr+1+13] != 0 {
		t.Fatal("slot is not NUL terminated")
	}
	// everything else must be untouched
	if !bytes.Equal(f.Data[synthDynstr+15:synthDynstr+22], []byte("libc.so")) {
		t.Fatal("neighbouring string was damaged")
	}
	rep := parse(t, f.Data)
	if rep.NeededEntry("libarchin.so") == nil || rep.NeededEntry("libandroid.so") != nil {
		t.Fatalf("re-parse shows %v", rep.Needed)
	}
}

func TestRewriteNeededTooLong(t *testing.T) {
	f := parse(t, synthELF(6))
	before := append([]byte(nil), f.Data...)
	e := f.NeededEntry("libc.so") // capacity 7
	if err := f.RewriteNeeded(e, "libarchin.so"); err == nil {
		t.Fatal("expected the rewrite to be rejected")
	}
	if !bytes.Equal(before, f.Data) {
		t.Fatal("file was modified on a rejected rewrite")
	}
}

func TestChainRewriteOverBothRelations(t *testing.T) {
	// host library: divert "libandroid.so" to our library
	host := parse(t, synthELF(6))
	if err := host.RewriteNeeded(host.NeededEntry("libandroid.so"), "libarchin.so"); err != nil {
		t.Fatal(err)
	}
	// payload library: the placeholder is re-pointed at the displaced name so
	// the original dependency is still loaded, one hop later
	payload := []byte("\x00libandroid.so\x00libarchinome_dependency_slot.so\x00libc.so\x00")
	n, err := ReplaceBytes(payload, "libarchinome_dependency_slot.so", "libandroid.so")
	if err != nil || n != 1 {
		t.Fatalf("ReplaceBytes = %d, %v", n, err)
	}
	if !bytes.Contains(payload, []byte("\x00libandroid.so\x00libandroid.so\x00")) {
		t.Fatalf("payload slot not re-pointed: %q", payload)
	}
	if bytes.Contains(payload, []byte("dependency_slot")) {
		t.Fatal("placeholder survived")
	}
}

func TestAddNeededWithSlack(t *testing.T) {
	f := parse(t, synthELF(6)) // two spare slots after the terminator
	if err := f.AddNeeded("libextra.so"); err != nil {
		t.Fatalf("AddNeeded: %v", err)
	}
	if f.NeededEntry("libextra.so") == nil {
		t.Fatal("new dependency not registered")
	}
	rep := parse(t, f.Data)
	if rep.NeededEntry("libextra.so") == nil {
		t.Fatal("new dependency missing after re-parse")
	}
	if len(rep.Needed) != 3 {
		t.Fatalf("want 3 DT_NEEDED entries, got %d", len(rep.Needed))
	}
	off := rep.StrTabOff + int64(rep.StrSz) - int64(len("libextra.so")) - 1
	if string(rep.Data[off:off+int64(len("libextra.so"))]) != "libextra.so" {
		t.Fatal("string not where DT_STRSZ says it is")
	}
	// a terminator must still follow our entry
	tag := binary.LittleEndian.Uint64(rep.Data[synthDynOff+5*16:])
	if tag != DT_NULL {
		t.Fatalf("terminator missing, tag = %d", tag)
	}
}

func TestAddNeededWithoutSlack(t *testing.T) {
	f := parse(t, synthELF(5)) // only one slot left: no room for entry + terminator
	err := f.AddNeeded("libextra.so")
	if err == nil {
		t.Fatal("expected failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("free slots")) {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestAddNeededNoStringSpace(t *testing.T) {
	b := synthELF(6)
	// occupy the bytes right after the string table
	copy(b[synthDynstr+synthDynStrsz:], "XXXXXXXXXXXXXXXX")
	f := parse(t, b)
	err := f.AddNeeded("libextra.so")
	if err == nil {
		t.Fatal("expected failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not free")) {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestReplaceBytesPadsShorter(t *testing.T) {
	data := []byte("aa libarchinome_dependency_slot.so bb libarchinome_dependency_slot.so cc")
	n, err := ReplaceBytes(data, "libarchinome_dependency_slot.so", "liblog.so")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	want := "aa liblog.so" + string(make([]byte, len("libarchinome_dependency_slot.so")-len("liblog.so"))) + " bb liblog.so" +
		string(make([]byte, len("libarchinome_dependency_slot.so")-len("liblog.so"))) + " cc"
	if string(data) != want {
		t.Fatalf("got %q", data)
	}
}

func TestReplaceBytesRejectsGrowth(t *testing.T) {
	if _, err := ReplaceBytes([]byte("short"), "short", "muchlongername"); err == nil {
		t.Fatal("expected rejection")
	}
	if _, err := ReplaceBytes([]byte("nothing here"), "absent", "x"); err == nil {
		t.Fatal("expected rejection when the pattern is absent")
	}
}
