package dex

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEncodeEmitsValidHeaderHashes guards a bug that shipped once: the emitter
// wrote the adler32 checksum before the SHA-1 signature, so the checksum was
// computed over a buffer that the signature then modified (bytes 0x0c..0x1f lie
// inside the range the checksum covers). The result was a dex ART refuses to
// load - the app died with "Unable to instantiate application ..." and the
// missing class looked like a packaging problem instead of a header bug.
func TestEncodeEmitsValidHeaderHashes(t *testing.T) {
	raw, err := os.ReadFile(stubFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := RenameDescriptor(f, placeholderDescriptor, "Landroid/app/Application;"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	out, err := f.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	if got, want := binary.LittleEndian.Uint32(out[8:]), adler32.Checksum(out[12:]); got != want {
		t.Fatalf("adler32 in header = %#x, want %#x (stale checksum)", got, want)
	}
	sum := sha1.Sum(out[32:])
	if !bytes.Equal(out[12:32], sum[:]) {
		t.Fatal("sha1 signature in header does not cover the emitted bytes")
	}

	tmp := filepath.Join(t.TempDir(), "emitted.dex")
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Validate(tmp, wrapperClass); err != nil {
		t.Fatalf("Validate rejected writer output: %v", err)
	}
}

// TestValidateRejectsBrokenHeaderHash keeps the barrier honest: a dex whose
// header hashes do not describe its own bytes must never pass validation, no
// matter how valid the rest of the structure looks.
func TestValidateRejectsBrokenHeaderHash(t *testing.T) {
	raw, err := os.ReadFile(stubFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for _, tc := range []struct {
		name   string
		tamper func([]byte)
	}{
		{"zeroed signature", func(b []byte) { copy(b[12:32], make([]byte, 20)) }},
		{"flipped payload byte", func(b []byte) { b[len(b)-1] ^= 0xff }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corrupt := append([]byte(nil), raw...)
			tc.tamper(corrupt)
			tmp := filepath.Join(t.TempDir(), "corrupt.dex")
			if err := os.WriteFile(tmp, corrupt, 0o644); err != nil {
				t.Fatal(err)
			}
			err := Validate(tmp, wrapperClass)
			if err == nil {
				t.Fatal("validator accepted a dex with broken header hashes")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "checksum") &&
				!strings.Contains(strings.ToLower(err.Error()), "signature") {
				t.Fatalf("rejected, but not for the header hash: %v", err)
			}
		})
	}
}
