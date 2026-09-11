package dex

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The tool is repeatable only while the stub source is pristine. Two regressions
// are guarded here:
//  1. The on-disk fixture (InjectedApp.dex) must equal the embedded pristine
//     copy — a run that rewrites it makes the next injection die with
//     `descriptor "Lz/z/z;" not found in the string table`.
//  2. Renaming + encoding the same source twice must produce identical bytes
//     (no hidden state in the writer).
func TestStubFixtureStaysPristine(t *testing.T) {
	onDisk, err := os.ReadFile("../../InjectedApp.dex")
	if err != nil {
		t.Fatalf("read the repo fixture: %v", err)
	}
	if !bytes.Equal(onDisk, pristineStub) {
		t.Fatalf("InjectedApp.dex differs from the embedded pristine stub (%d vs %d bytes): "+
			"a run rewrote the fixture, restore it with `git checkout -- InjectedApp.dex`",
			len(onDisk), len(pristineStub))
	}
}

func TestPatchIsRepeatable(t *testing.T) {
	const target = "Lcom/example/host/App;"
	path := filepath.Join(t.TempDir(), "patched.dex")

	var first []byte
	for i := 0; i < 2; i++ {
		f, err := Parse(pristineStub)
		if err != nil {
			t.Fatalf("parse (pass %d): %v", i, err)
		}
		n, err := RenameDescriptor(f, placeholderDescriptor, target)
		if err != nil {
			t.Fatalf("rename (pass %d): %v", i, err)
		}
		if n != 1 {
			t.Fatalf("pass %d renamed %d strings, want 1", i, n)
		}
		out, err := f.Encode()
		if err != nil {
			t.Fatalf("encode (pass %d): %v", i, err)
		}
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatalf("write (pass %d): %v", i, err)
		}
		// Validate() reads a file, so the emitted bytes go through the same
		// header/section/sortedness gate the CLI applies to a fresh dex.
		if err := Validate(path); err != nil {
			t.Fatalf("pass %d produced an invalid dex: %v", i, err)
		}
		if i == 0 {
			first = out
			// Parsing/encoding must not scratch the source buffer in place.
			if !bytes.Contains(pristineStub, []byte(placeholderDescriptor)) {
				t.Fatal("the pristine stub lost its placeholder during a pass")
			}
			continue
		}
		if !bytes.Equal(first, out) {
			t.Fatalf("second pass differs from the first: %d vs %d bytes", len(first), len(out))
		}
	}
}
