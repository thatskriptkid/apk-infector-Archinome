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
	Custom_payload Payload_option_type = 1
	Frida_payload Payload_option_type = 2
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