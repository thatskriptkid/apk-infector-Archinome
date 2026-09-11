package dex

import (
	"os"
	"path/filepath"
	"testing"
)

// The repo ships a small stub dex that the Application-hijack vector rewrites;
// it doubles as a known-good sample for the validator.
func stub(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "payload_custom.dex"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("sample dex not available: %v", err)
	}
	return p
}

func TestValidateAcceptsRealDex(t *testing.T) {
	if err := Validate(stub(t)); err != nil {
		t.Fatalf("valid dex rejected: %v", err)
	}
}

func TestValidateAcceptsKnownPayloadClass(t *testing.T) {
	if err := Validate(stub(t), "aaaaaaaaaaaa.payload"); err != nil {
		t.Fatalf("known class reported missing: %v", err)
	}
}

func TestValidateRejectsMissingClass(t *testing.T) {
	if err := Validate(stub(t), "does.not.Exist"); err == nil {
		t.Fatal("missing class accepted")
	}
}

func TestValidateRejectsTruncatedDex(t *testing.T) {
	data, err := os.ReadFile(stub(t))
	if err != nil {
		t.Fatal(err)
	}
	cut := filepath.Join(t.TempDir(), "cut.dex")
	if err := os.WriteFile(cut, data[:len(data)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Validate(cut); err == nil {
		t.Fatal("truncated dex accepted")
	}
}

// A dex whose header claims a different file size is exactly the failure mode
// the in-place stub patch produced on the device (ART then refuses the file).
func TestValidateRejectsSizeMismatch(t *testing.T) {
	data, err := os.ReadFile(stub(t))
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), data...)
	bad[0x20] = bad[0x20] ^ 0x10 // corrupt file_size
	p := filepath.Join(t.TempDir(), "bad.dex")
	if err := os.WriteFile(p, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Validate(p); err == nil {
		t.Fatal("dex with mismatched file_size accepted")
	}
}
