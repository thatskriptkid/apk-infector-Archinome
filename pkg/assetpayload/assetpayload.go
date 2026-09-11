// Package assetpayload seals an arbitrary DEX file into an APK asset, so the
// payload never shows up as classes*.dex on disk. The injected loader stub reads
// the asset back at runtime, decrypts it and loads it with DexClassLoader.
//
// Blob layout (18 bytes of overhead):
//
//	0   6   magic "ARCHN1"
//	6   18  AES-GCM nonce
//	18  ..  ciphertext || 16-byte GCM tag
//
// The key is SHA-256 of a passphrase, so the Go side and the Java loader
// (assets_payload/aaaaaaaaaaaa/AssetLoader.java) derive it identically.
//
// SECURITY NOTE: this is obfuscation, not secrecy. The passphrase is compiled
// into the loader dex, so anyone who can read the APK can recover the payload.
// Its purpose is to keep the payload out of naive `unzip`/`strings`/`classes*.dex`
// triage, not to hide it from a determined analyst.
package assetpayload

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// Magic prefixes every sealed blob.
	Magic = "ARCHN1"
	// NonceSize is the AES-GCM nonce length in bytes.
	NonceSize = 12
	// HeaderSize is magic + nonce.
	HeaderSize = len(Magic) + NonceSize
	// TagSize is the AES-GCM authentication tag length in bytes.
	TagSize = 16
	// AssetName is the asset path the injected loader reads. Must stay in sync
	// with AssetLoader.ASSET_NAME.
	AssetName = "archinome_payload.enc"
	// AssetPath is the path inside the APK.
	AssetPath = "assets/" + AssetName
	// DefaultPassphrase must stay in sync with AssetLoader.DEFAULT_PASSPHRASE.
	DefaultPassphrase = "archinome-assets-key"
)

// ErrNotSealed is returned when a blob does not start with the magic.
var ErrNotSealed = errors.New("assetpayload: blob does not start with the " + Magic + " magic")

// KeyFromPassphrase derives the AES-256 key the Java loader also derives.
func KeyFromPassphrase(passphrase string) []byte {
	sum := sha256.Sum256([]byte(passphrase))
	return sum[:]
}

// Seal encrypts plain with AES-256-GCM and returns magic || nonce || ct||tag.
func Seal(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("assetpayload: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("assetpayload: %w", err)
	}
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("assetpayload: nonce: %w", err)
	}
	out := make([]byte, 0, HeaderSize+len(plain)+TagSize)
	out = append(out, Magic...)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, plain, nil)
	return out, nil
}

// Open reverses Seal. It fails if the blob is truncated, not sealed, or if the
// GCM tag does not verify (tampered ciphertext or wrong key).
func Open(blob, key []byte) ([]byte, error) {
	if len(blob) < HeaderSize+TagSize {
		return nil, fmt.Errorf("assetpayload: blob too short (%d bytes)", len(blob))
	}
	if string(blob[:len(Magic)]) != Magic {
		return nil, ErrNotSealed
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("assetpayload: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("assetpayload: %w", err)
	}
	nonce := blob[len(Magic):HeaderSize]
	plain, err := gcm.Open(nil, nonce, blob[HeaderSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("assetpayload: decryption failed (wrong passphrase or tampered blob): %w", err)
	}
	return plain, nil
}

// EncryptFile seals the contents of src with the passphrase and writes the blob
// to dst.
func EncryptFile(src, dst, passphrase string) error {
	plain, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("assetpayload: %w", err)
	}
	if len(plain) < 8 || string(plain[:4]) != "dex\n" {
		return fmt.Errorf("assetpayload: %s is not a DEX file (bad magic)", src)
	}
	blob, err := Seal(plain, KeyFromPassphrase(passphrase))
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, blob, 0o644); err != nil {
		return fmt.Errorf("assetpayload: %w", err)
	}
	return nil
}

// DecryptFile reverses EncryptFile (used for diagnostics/verification).
func DecryptFile(src, dst, passphrase string) error {
	blob, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("assetpayload: %w", err)
	}
	plain, err := Open(blob, KeyFromPassphrase(passphrase))
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, plain, 0o644); err != nil {
		return fmt.Errorf("assetpayload: %w", err)
	}
	return nil
}
