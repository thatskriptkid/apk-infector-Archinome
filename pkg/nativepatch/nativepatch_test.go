package nativepatch

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/elfpatch"
)

// testPayloadName is the file name the fake payload is installed under.
const testPayloadName = "libarchin.so"

// synthHost builds a minimal but valid ELF64 shared object whose only dynamic
// entries are "libsomething.so" (15 bytes of name room) and "libc.so".
func synthHost(t *testing.T, dynSlots int) []byte {
	t.Helper()
	const (
		phOff  = 0x40
		dynstr = 0xB0
		dynOff = 0xF0
		total  = 0x200
	)
	b := make([]byte, total)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(b[16:], 3)
	binary.LittleEndian.PutUint16(b[18:], 183)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[32:], phOff)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 2)
	binary.LittleEndian.PutUint16(b[58:], 64)

	binary.LittleEndian.PutUint32(b[phOff:], 1) // PT_LOAD
	binary.LittleEndian.PutUint64(b[phOff+8:], 0)
	binary.LittleEndian.PutUint64(b[phOff+16:], 0)
	binary.LittleEndian.PutUint64(b[phOff+32:], total)
	binary.LittleEndian.PutUint64(b[phOff+40:], total)

	binary.LittleEndian.PutUint32(b[phOff+56:], 2) // PT_DYNAMIC
	binary.LittleEndian.PutUint64(b[phOff+56+8:], dynOff)
	binary.LittleEndian.PutUint64(b[phOff+56+32:], uint64(dynSlots*16))
	binary.LittleEndian.PutUint64(b[phOff+56+40:], uint64(dynSlots*16))

	copy(b[dynstr:], "\x00libsomething.so\x00libc.so\x00")
	put := func(i int, tag, val uint64) {
		off := dynOff + i*16
		binary.LittleEndian.PutUint64(b[off:], tag)
		binary.LittleEndian.PutUint64(b[off+8:], val)
	}
	put(0, 1, 1)  // DT_NEEDED libsomething.so
	put(1, 1, 17) // DT_NEEDED libc.so
	put(2, 5, dynstr)
	put(3, 10, 26) // DT_STRSZ
	put(4, 0, 0)   // DT_NULL
	return b
}

// fakePayload mimics the built payload: it carries the placeholder dependency
// string in two places (the dynamic string table and the forwarding constant).
func fakePayload(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "libarchin.so")
	body := "ELFfake\x00" + Placeholder + "\x00" + Placeholder + "\x00trailing"
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func setup(t *testing.T) (root, payload string) {
	t.Helper()
	root = t.TempDir()
	libDir := filepath.Join(root, "lib", "arm64-v8a")
	if err := os.MkdirAll(libDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(libDir, "libhost.so"), synthHost(t, 6), 0644); err != nil {
		t.Fatal(err)
	}
	return root, fakePayload(t, t.TempDir())
}

func TestChainRepointsHostAndPayload(t *testing.T) {
	root, payload := setup(t)
	libDir := filepath.Join(root, "lib", "arm64-v8a")

	res, err := Apply(root, Options{Mode: ModeChain, Payload: payload})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(res) != 1 || res[0].Displaced != "libsomething.so" {
		t.Fatalf("unexpected result: %+v", res)
	}

	host, err := elfpatch.Open(filepath.Join(libDir, "libhost.so"))
	if err != nil {
		t.Fatal(err)
	}
	if host.NeededEntry(testPayloadName) == nil {
		t.Errorf("host no longer requires %s: %v", testPayloadName, host.Needed)
	}
	if host.NeededEntry("libsomething.so") != nil {
		t.Errorf("the displaced dependency is still required directly")
	}

	// The payload has to keep the displaced dependency in the graph.
	data, err := os.ReadFile(filepath.Join(libDir, testPayloadName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), Placeholder) {
		t.Errorf("placeholder was not re-pointed in the payload")
	}
	if strings.Count(string(data), "libsomething.so") != 2 {
		t.Errorf("expected the displaced name twice in the payload, got %d",
			strings.Count(string(data), "libsomething.so"))
	}
	if host.NeededEntry("libc.so") == nil {
		t.Errorf("unrelated dependencies must be left alone")
	}
}

func TestReplaceInstallsPayloadUnderHostName(t *testing.T) {
	root, payload := setup(t)
	libDir := filepath.Join(root, "lib", "arm64-v8a")

	res, err := Apply(root, Options{Mode: ModeReplace, Payload: payload})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res[0].RenamedTo != "libhost_orig.so" {
		t.Fatalf("unexpected rename: %+v", res[0])
	}
	// The loader looks the library up by the name the app asked for, so the
	// payload must sit exactly there.
	if _, err := os.Stat(filepath.Join(libDir, "libhost.so")); err != nil {
		t.Errorf("payload is not installed as the host name: %v", err)
	}
	orig, err := os.Stat(filepath.Join(libDir, "libhost_orig.so"))
	if err != nil || orig.Size() == 0 {
		t.Fatalf("original was not preserved: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(libDir, "libhost.so"))
	if !strings.Contains(string(data), "libhost_orig.so") {
		t.Errorf("payload does not chain back to the renamed original")
	}
}

func TestAppendAddsDependencyWithoutDisplacing(t *testing.T) {
	root, payload := setup(t)
	libDir := filepath.Join(root, "lib", "arm64-v8a")

	res, err := Apply(root, Options{Mode: ModeAppend, Payload: payload})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res[0].Displaced != "libc.so" {
		t.Errorf("append must not displace a real dependency, got %q", res[0].Displaced)
	}
	host, err := elfpatch.Open(filepath.Join(libDir, "libhost.so"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{testPayloadName, "libsomething.so", "libc.so"} {
		if host.NeededEntry(want) == nil {
			t.Errorf("host lost %q: %v", want, host.Needed)
		}
	}
	// The new name lives past the original string table, so DT_STRSZ must cover it.
	if host.StrSz <= 26 {
		t.Errorf("DT_STRSZ was not extended: %d", host.StrSz)
	}
}

func TestAppendReportsMissingSpace(t *testing.T) {
	root, payload := setup(t)
	libDir := filepath.Join(root, "lib", "arm64-v8a")
	// A dynamic table with no spare slot after the terminator.
	if err := os.WriteFile(filepath.Join(libDir, "libhost.so"), synthHost(t, 5), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Apply(root, Options{Mode: ModeAppend, Payload: payload})
	if err == nil {
		t.Fatal("expected append to fail without free dynamic slots")
	}
	if !strings.Contains(err.Error(), "free slots") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestRejectsMissingHost(t *testing.T) {
	root, payload := setup(t)
	_, err := Apply(root, Options{Mode: ModeChain, Payload: payload, HostLib: "libnope.so"})
	if err == nil || !strings.Contains(err.Error(), "libnope.so") {
		t.Fatalf("expected a clear error about the host library, got %v", err)
	}
}
