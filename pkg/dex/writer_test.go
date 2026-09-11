package dex

import (
	"os"
	"path/filepath"
	"testing"
)

// The real stub dex shipped in the repo root. The writer must be able to rename
// its placeholder superclass and produce a dex that Validate accepts.
//
// Tests read this pristine snapshot, not ../../InjectedApp.dex: that file is an
// in-place working copy which every injection run rewrites (the placeholder is
// consumed by the rename), so a test pointing at it passes or fails depending
// on whether an injection happened to run before it.
const stubFixture = "testdata/stub_pristine.dex"

const wrapperClass = "aaaaaaaa.aaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaa.InjectedApp"

// TestRenameDescriptorOnRealStub exercises the writer end to end on the actual
// fixture: Parse -> rename Lz/z/z; -> Encode. The emitted dex must have sorted
// string_ids, a valid header/checksum/signature and the wrapper extending the
// requested class.
func TestRenameDescriptorOnRealStub(t *testing.T) {
	raw, err := os.ReadFile(stubFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	n, err := RenameDescriptor(f, placeholderDescriptor, "Landroid/app/Application;")
	if err != nil {
		t.Fatalf("rename: %v", err)
	}
	if n != 1 {
		t.Fatalf("want exactly 1 descriptor renamed, got %d", n)
	}
	out, err := f.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "renamed.dex")
	if err := os.WriteFile(tmp, out, 0644); err != nil {
		t.Fatal(err)
	}
	if err := Validate(tmp, wrapperClass); err != nil {
		t.Fatalf("Validate on writer output: %v", err)
	}
	if err := ValidateSuperclass(tmp, wrapperClass, "android.app.Application"); err != nil {
		t.Fatalf("ValidateSuperclass on writer output: %v", err)
	}
}

// TestRenameDescriptorMissingPlaceholder: a stale/foreign input must fail
// loudly instead of silently producing a dex whose superclass is wrong.
func TestRenameDescriptorMissingPlaceholder(t *testing.T) {
	raw, err := os.ReadFile(stubFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := RenameDescriptor(f, "Ldoes/not/Exist;", "Lx/y/Z;"); err == nil {
		t.Fatal("expected an error for a descriptor absent from the string table")
	}
}

func TestParseRejectsCorruptInput(t *testing.T) {
	if _, err := Parse([]byte("this is definitely not a dex file at all")); err == nil {
		t.Fatal("expected Parse to reject garbage")
	}
	raw, err := os.ReadFile(stubFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if _, err := Parse(raw[:len(raw)/2]); err == nil {
		t.Fatal("expected Parse to reject a truncated dex")
	}
}

func TestValidateRejectsCorruptFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.dex")
	if err := os.WriteFile(tmp, []byte("garbage"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Validate(tmp, wrapperClass); err == nil {
		t.Fatal("expected Validate to reject a corrupt dex")
	}
}
