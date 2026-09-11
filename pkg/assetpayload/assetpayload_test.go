package assetpayload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 16, 4096} {
		plain := make([]byte, n)
		rand.New(rand.NewSource(int64(n))).Read(plain)
		key := KeyFromPassphrase(DefaultPassphrase)

		blob, err := Seal(plain, key)
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", n, err)
		}
		if got, want := len(blob), HeaderSize+n+TagSize; got != want {
			t.Errorf("blob size = %d, want %d", got, want)
		}
		got, err := Open(blob, key)
		if err != nil {
			t.Fatalf("Open(%d bytes): %v", n, err)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("round trip mismatch for %d bytes", n)
		}
	}
}

// The Java loader parses the blob by fixed offsets, so the layout is a contract.
func TestHeaderLayout(t *testing.T) {
	key := KeyFromPassphrase("k")
	blob, err := Seal([]byte("payload"), key)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob[:6]) != Magic {
		t.Errorf("magic = %q, want %q", blob[:6], Magic)
	}
	if len(Magic) != 6 || NonceSize != 12 || HeaderSize != 18 {
		t.Fatalf("layout drifted: magic=%d nonce=%d header=%d", len(Magic), NonceSize, HeaderSize)
	}
	// The nonce sits right after the magic and must differ between seals.
	blob2, _ := Seal([]byte("payload"), key)
	if bytes.Equal(blob[6:HeaderSize], blob2[6:HeaderSize]) {
		t.Error("nonce reused across Seal calls")
	}
	// Ciphertext must not contain the plaintext.
	if bytes.Contains(blob, []byte("payload")) {
		t.Error("plaintext visible in sealed blob")
	}
}

func TestOpenWrongKey(t *testing.T) {
	blob, err := Seal([]byte("top secret"), KeyFromPassphrase("right"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(blob, KeyFromPassphrase("wrong")); err == nil {
		t.Error("Open with the wrong key succeeded")
	}
}

func TestOpenTampered(t *testing.T) {
	key := KeyFromPassphrase(DefaultPassphrase)
	blob, err := Seal([]byte("top secret"), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{HeaderSize, HeaderSize + 3, len(blob) - 1} {
		bad := append([]byte(nil), blob...)
		bad[i] ^= 0x01
		if _, err := Open(bad, key); err == nil {
			t.Errorf("Open accepted a blob tampered at offset %d", i)
		}
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	key := KeyFromPassphrase(DefaultPassphrase)
	if _, err := Open([]byte("short"), key); err == nil {
		t.Error("Open accepted a too-short blob")
	}
	junk := make([]byte, HeaderSize+TagSize)
	if _, err := Open(junk, key); err != ErrNotSealed {
		t.Errorf("Open(junk) error = %v, want ErrNotSealed", err)
	}
}

// The key derivation is shared with Java (SHA-256 of the passphrase), so pin it.
func TestKeyDerivation(t *testing.T) {
	k := KeyFromPassphrase(DefaultPassphrase)
	if len(k) != 32 {
		t.Fatalf("key length = %d, want 32", len(k))
	}
	sum := sha256.Sum256([]byte(DefaultPassphrase))
	if hex.EncodeToString(k) != hex.EncodeToString(sum[:]) {
		t.Error("KeyFromPassphrase is not SHA-256(passphrase)")
	}
}

func TestEncryptFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	dex := filepath.Join(dir, "payload.dex")
	sealed := filepath.Join(dir, AssetName)
	back := filepath.Join(dir, "payload.dex.out")

	plain := append([]byte("dex\n035\x00"), bytes.Repeat([]byte{0xAB}, 512)...)
	if err := os.WriteFile(dex, plain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(dex, sealed, DefaultPassphrase); err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	if err := DecryptFile(sealed, back, DefaultPassphrase); err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}
	got, err := os.ReadFile(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("EncryptFile/DecryptFile round trip mismatch")
	}
	// Wrong passphrase must fail loudly, not silently produce garbage.
	if err := DecryptFile(sealed, back, "nope"); err == nil {
		t.Error("DecryptFile accepted the wrong passphrase")
	}
}

func TestEncryptFileRejectsNonDex(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "notadex.bin")
	if err := os.WriteFile(plain, []byte("PK\x03\x04definitely not a dex file"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(plain, filepath.Join(dir, "out"), DefaultPassphrase); err == nil {
		t.Error("EncryptFile accepted a non-DEX input")
	}
}
