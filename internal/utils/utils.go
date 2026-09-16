package utils

import (
	"log"
	"os"
	"path/filepath"
)

var ManifestBinaryPath, _ = filepath.Abs("AndroidManifest.xml")
var OldAppNameNormalized string

type Payload_option_type int

const (
	Custom_payload              Payload_option_type = 1
	Frida_payload               Payload_option_type = 2
	Provider_payload            Payload_option_type = 3
	Trampoline_payload          Payload_option_type = 4
	Receiver_payload            Payload_option_type = 5
	AppComponentFactory_payload Payload_option_type = 6
	Native_payload              Payload_option_type = 7
	// Assets_payload ships the real payload encrypted in assets/ and lets a small
	// in-APK stub decrypt and DexClassLoader it at runtime (see pkg/assetpayload).
	Assets_payload Payload_option_type = 8
	// Service_payload patches the code of the services the host declares: the
	// payload call is inserted into the <init> of every class named in a
	// <service android:name> element, so the host's own startService/bind path
	// runs it. Nothing is added to the manifest and no class is renamed.
	Service_payload Payload_option_type = 9
	// Native_sideload_payload ships the payload as a library name the host asks
	// for with System.loadLibrary() but does not ship itself.
	Native_sideload_payload Payload_option_type = 10
	// CodePatchApp_payload patches the code of the host Application class
	// (<clinit>, else <init>): the manifest is left byte-identical.
	CodePatchApp_payload Payload_option_type = 11
	// Instrumentation_payload declares an <instrumentation> the host never had.
	Instrumentation_payload Payload_option_type = 12
	// BackupAgent_payload declares android:backupAgent on <application>.
	BackupAgent_payload Payload_option_type = 13
	// ZygotePreload_payload declares android:zygotePreloadName plus the isolated
	// service that makes the platform fork the app zygote.
	ZygotePreload_payload Payload_option_type = 14
)

var Payload_option int

func WriteChanges(raw []byte, path string) {
	//Open a new file for writing only
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_TRUNC|os.O_CREATE,
		0666,
	)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// Write bytes to file
	_, err = file.Write(raw)
	if err != nil {
		log.Panic("Failed to write changes to disk", err)
	}
}

func isValidFile(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func Cleanup() {
	//delete sample_unzipped - we dont need it

	if _, err := os.Stat("sample_unzipped"); err == nil {
		err := os.RemoveAll("sample_unzipped")
		if err != nil {
			log.Println(err)
		}
	}

	filePaths := []string{
		"AndroidManifest_plaintext.xml",
		"AndroidManifest.xml",
		"manifest_strings.dmp",
		"InjectedApp_patched.dex",
	}

	for _, filePath := range filePaths {
		// Check if file exists
		if _, err := os.Stat(filePath); err == nil {
			// Attempt to delete the file
			err := os.Remove(filePath)
			if err != nil {
				log.Printf("Error deleting file: %v\n", err)
			} else {
				log.Printf("File deleted successfully: %s\n", filePath)
			}
		}
	}
}
