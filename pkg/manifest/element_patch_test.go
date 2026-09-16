package manifest

// Tests for the in-place element/attribute vectors:
//
//   service_patch.go        <service> into <application>
//   instrumentation_patch.go <instrumentation> into <manifest>
//   appattr_patch.go        android:backupAgent / android:allowBackup / android:zygotePreloadName
//   components.go           DeclaredServiceClasses (read-only)
//
// Every test works on a synthetic but structurally faithful AXML image (file
// header + string pool + resource map + <manifest><application>.., built with
// the same chunk writers the vectors use), runs the vector against a temp file,
// and then checks three things on the result:
//
//  1. the resolved resource ids of every element's attributes are ascending (the
//     repository invariant - the platform resolves attributes with a binary
//     search over those ids, an out-of-order attribute is dropped silently);
//  2. the new element/attribute is really there, as seen by the package's own
//     parser (ParseXml + a recording ManifestEncoder);
//  3. the chunk layout is still consistent: the pool's stringsStart/count agree
//     with its size, every chunk size walks to the end of the file, and the AXML
//     size field matches the file length. ParseXml itself refuses to parse a
//     chunk that is not fully consumed, so a broken splice fails the test.

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
)

// ---------------------------------------------------------------- AXML builder

// axTag is one synthetic element: its tag-name pool index, its attributes
// (already shaped like aapt2 writes them) and its children.
type axTag struct {
	name  uint32
	attrs []elemAttr
	kids  []axTag
}

func (t axTag) encode() []byte {
	out := buildStartTag(t.name, t.attrs)
	for _, k := range t.kids {
		out = append(out, k.encode()...)
	}
	return append(out, buildEndTag(t.name)...)
}

// buildResMap builds the resource-id chunk (0x0180) aligned with the string pool:
// slot i carries the framework resource id of the string at pool index i, or 0
// for a name that is not a framework attribute.
func buildResMap(resIDs []uint32) []byte {
	buf := make([]byte, 8+4*len(resIDs))
	binary.LittleEndian.PutUint16(buf[0:], chunkResourceIds)
	binary.LittleEndian.PutUint16(buf[2:], 8)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(buf)))
	for i, id := range resIDs {
		binary.LittleEndian.PutUint32(buf[8+i*4:], id)
	}
	return buf
}

// synthManifest assembles a complete binary manifest: file header, string pool,
// resource map, element tree.
func synthManifest(utf8 bool, strs []string, resIDs []uint32, root axTag) []byte {
	body := append(buildPool(utf8, strs), buildResMap(resIDs)...)
	body = append(body, root.encode()...)
	out := make([]byte, 8, 8+len(body))
	binary.LittleEndian.PutUint16(out[0:], chunkAxmlFile)
	binary.LittleEndian.PutUint16(out[2:], 8)
	binary.LittleEndian.PutUint32(out[4:], uint32(8+len(body)))
	return append(out, body...)
}

// Pool indices of the fixture manifest.
const (
	fxNs = iota
	fxManifest
	fxPackage
	fxPkgName
	fxApp
	fxLabel
	fxName
	fxService
	fxSvcAbs
	fxSvcRel
	fxSvcBare
	fxAllowBk
	fxZygote
	fxTargetPkg
	fxFuncTest
	fxInstr
	fxExport
	fxIsolated
	fxUseZygote
	fxBackupAgent
	fxOldBackupAgent
)

const fixturePkg = "com.example.host"

var fixtureStrings = []string{
	androidNamespaceURI,             // fxNs
	"manifest",                      // fxManifest
	"package",                       // fxPackage
	fixturePkg,                      // fxPkgName
	"application",                   // fxApp
	"label",                         // fxLabel
	"name",                          // fxName
	"service",                       // fxService
	fixturePkg + ".ExistingService", // fxSvcAbs
	".RelativeService",              // fxSvcRel
	"KeepMeService",                 // fxSvcBare
	"allowBackup",                   // fxAllowBk
	"zygotePreloadName",             // fxZygote
	"targetPackage",                 // fxTargetPkg
	"functionalTest",                // fxFuncTest
	"instrumentation",               // fxInstr
	"exported",                      // fxExport
	"isolatedProcess",               // fxIsolated
	"useAppZygote",                  // fxUseZygote
	"backupAgent",                   // fxBackupAgent
	"com.example.old.BackupAgent",   // fxOldBackupAgent
}

// fixtureOpts describes the variant of the fixture manifest a test needs.
type fixtureOpts struct {
	utf8         bool
	resSlots     map[int]uint32 // framework ids preset in the resource map
	manifestKids []axTag        // extra <manifest> children, in front of <application>
	appAttrs     []elemAttr
	appKids      []axTag
	extraStrings []string // appended after fixtureStrings (pool + zero map slots)
}

func (o fixtureOpts) bytes() []byte {
	strs := append(append([]string{}, fixtureStrings...), o.extraStrings...)
	resIDs := make([]uint32, len(strs))
	for i, id := range o.resSlots {
		resIDs[i] = id
	}
	kids := append([]axTag{}, o.manifestKids...)
	kids = append(kids, axTag{name: fxApp, attrs: o.appAttrs, kids: o.appKids})
	root := axTag{
		name: fxManifest,
		attrs: []elemAttr{
			{0xFFFFFFFF, fxPackage, fxPkgName, uint8(AttrTypeString), fxPkgName},
		},
		kids: kids,
	}
	return synthManifest(o.utf8, strs, resIDs, root)
}

// svcTag builds <service android:name="<pool index>"/>.
func svcTag(nameIdx uint32) axTag {
	return axTag{name: fxService, attrs: []elemAttr{
		{uint32(fxNs), fxName, nameIdx, uint8(AttrTypeString), nameIdx},
	}}
}

// ---------------------------------------------------------------- test helpers

// isolateGlobals redirects the package-level paths the vectors use, so a test
// never writes AndroidManifest.xml / manifest_strings.dmp into the repository.
func isolateGlobals(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	oldDmp, oldPlain := ManifestStringsDmp, PlainPath
	ManifestStringsDmp = filepath.Join(dir, "manifest_strings.dmp")
	PlainPath = filepath.Join(dir, "AndroidManifest_plaintext.xml")
	t.Cleanup(func() {
		ManifestStringsDmp = oldDmp
		PlainPath = oldPlain
	})
}

// useFixture writes data where the vectors read the binary manifest from.
func useFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "AndroidManifest.xml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	old := utils.ManifestBinaryPath
	utils.ManifestBinaryPath = path
	t.Cleanup(func() { utils.ManifestBinaryPath = old })
	return path
}

// writePlainPackage writes the decoded manifest the package name is read from.
func writePlainPackage(t *testing.T, pkg string) {
	t.Helper()
	plain := `<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="` +
		androidNamespaceURI + `" package="` + pkg + `"><application/></manifest>`
	if err := os.WriteFile(PlainPath, []byte(plain), 0o644); err != nil {
		t.Fatalf("write plaintext manifest: %v", err)
	}
}

func readManifest(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	return data
}

// checkChunks asserts the image is still a chain of self-describing chunks that
// covers the file exactly, and that the AXML size field agrees with the length.
func checkChunks(t *testing.T, data []byte) {
	t.Helper()
	if got := int(leU32(data, axmlSizeOff)); got != len(data) {
		t.Errorf("AXML size field = 0x%x, file length = 0x%x", got, len(data))
	}
	off := 8
	for off < len(data) {
		size := int(leU32(data, off+4))
		if size < 8 || off+size > len(data) {
			t.Fatalf("broken chunk at 0x%x: size 0x%x (file 0x%x)", off, size, len(data))
		}
		off += size
	}
	if off != len(data) {
		t.Fatalf("chunk walk ended at 0x%x, file is 0x%x", off, len(data))
	}
}

// checkPool asserts the grown string pool is internally consistent and that every
// offset in it decodes (a mangled offset table panics on the slice access).
func checkPool(t *testing.T, data []byte) {
	t.Helper()
	pool := parseStringPool(data)
	if want := 0x1c + 4*pool.stringCount; pool.stringsStart != want {
		t.Errorf("string pool stringsStart = 0x%x, expected 0x%x for %d strings",
			pool.stringsStart, want, pool.stringCount)
	}
	if pool.size%4 != 0 {
		t.Errorf("string pool size 0x%x is not 4-byte aligned", pool.size)
	}
	for i := 0; i < pool.stringCount; i++ {
		pool.decode(data, i)
	}
}

// checkAttrOrder walks every tag-start chunk and asserts the resolved resource
// ids of its attributes are non-decreasing - the repository invariant.
func checkAttrOrder(t *testing.T, data []byte) {
	t.Helper()
	pool := parseStringPool(data)
	resIDs, _, _ := readResMap(data)
	for off := 8; off+8 <= len(data); {
		size := int(leU32(data, off+4))
		if size < 8 || off+size > len(data) {
			break
		}
		if leU16(data, off) == chunkTagStart {
			name := pool.decode(data, int(leU32(data, off+20)))
			prev := uint32(0)
			for i, a := range elementAttrs(data, off) {
				id := attrNameResID(resIDs, a.name)
				if i > 0 && id < prev {
					t.Errorf("<%s> attribute %d: resource id 0x%08x < previous 0x%08x",
						name, i, id, prev)
				}
				prev = id
			}
		}
		off += size
	}
}

// tokenRecorder is the test ManifestEncoder: it keeps the token stream ParseXml
// would hand to encoding/xml.
type tokenRecorder struct{ tokens []xml.Token }

func (r *tokenRecorder) EncodeToken(t xml.Token) error {
	r.tokens = append(r.tokens, t)
	return nil
}

func (r *tokenRecorder) Flush() error { return nil }

// parseTokens runs the package's own binary XML parser over data and returns the
// tokens: ParseXml fails on a chunk that is not fully consumed or on an out-of-
// range string/resource index, which is exactly the structural check wanted here.
func parseTokens(t *testing.T, data []byte) []xml.Token {
	t.Helper()
	rec := &tokenRecorder{}
	if err := ParseXml(bytes.NewReader(data), rec, nil); err != nil {
		t.Fatalf("ParseXml failed on the manifest: %v", err)
	}
	if len(rec.tokens) == 0 {
		t.Fatal("ParseXml produced no tokens")
	}
	return rec.tokens
}

func attrsOf(el xml.StartElement) map[string]string {
	m := make(map[string]string, len(el.Attr))
	for _, a := range el.Attr {
		m[a.Name.Local] = a.Value
	}
	return m
}

func elements(tokens []xml.Token, local string) []xml.StartElement {
	var out []xml.StartElement
	for _, tk := range tokens {
		if el, ok := tk.(xml.StartElement); ok && el.Name.Local == local {
			out = append(out, el)
		}
	}
	return out
}

// startTagIndex returns the index in the token stream of the first start tag
// named local carrying attrName=attrValue (attrName empty: name only).
func startTagIndex(tokens []xml.Token, local, attrName, attrValue string) int {
	for i, tk := range tokens {
		el, ok := tk.(xml.StartElement)
		if !ok || el.Name.Local != local {
			continue
		}
		if attrName != "" && attrsOf(el)[attrName] != attrValue {
			continue
		}
		return i
	}
	return -1
}

// parentOf returns the name of the element the first matching start tag lives in.
func parentOf(t *testing.T, tokens []xml.Token, local, attrName, attrValue string) string {
	t.Helper()
	var stack []string
	for _, tk := range tokens {
		switch e := tk.(type) {
		case xml.StartElement:
			if e.Name.Local == local && (attrName == "" || attrsOf(e)[attrName] == attrValue) {
				if len(stack) == 0 {
					return ""
				}
				return stack[len(stack)-1]
			}
			stack = append(stack, e.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	t.Fatalf("<%s> %s=%q not found in the token stream", local, attrName, attrValue)
	return ""
}

// childElementOffset returns the offset of the tag-start chunk of a <manifest>
// child named local.
func childElementOffset(t *testing.T, data []byte, local string) int {
	t.Helper()
	pool := parseStringPool(data)
	root := firstTagStart(data)
	if root < 0 {
		t.Fatal("no <manifest> root tag")
	}
	for _, c := range childElements(data, root) {
		if elementName(pool, data, c) == local {
			return c.startOff
		}
	}
	t.Fatalf("<%s> not found among the <manifest> children", local)
	return -1
}

// attrResIDs returns the resolved resource ids of the element at off, in order.
func attrResIDs(t *testing.T, data []byte, off int) []uint32 {
	t.Helper()
	resIDs, _, _ := readResMap(data)
	var out []uint32
	for _, a := range elementAttrs(data, off) {
		out = append(out, attrNameResID(resIDs, a.name))
	}
	return out
}

// elementAttrCount is the attributeCount field of the start tag at off.
func elementAttrCount(data []byte, off int) int { return int(leU16(data, off+28)) }

// elementSize is the size field of the chunk at off.
func elementSize(data []byte, off int) int { return int(leU32(data, off+4)) }

func svcNames(tokens []xml.Token) []string {
	var out []string
	for _, el := range elements(tokens, "service") {
		out = append(out, attrsOf(el)["name"])
	}
	return out
}

func containsStr(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- fixtures

func TestFixtureShape(t *testing.T) {
	isolateGlobals(t)
	if len(fixtureStrings) != fxOldBackupAgent+1 {
		t.Fatalf("fixtureStrings has %d entries, the fx* indices assume %d",
			len(fixtureStrings), fxOldBackupAgent+1)
	}
	// the resource map is index-aligned with the pool, so the fixture has to be
	// parseable before it is patched
	original := fixtureOpts{
		resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName},
		appKids:  []axTag{svcTag(fxSvcAbs)},
	}.bytes()
	checkChunks(t, original)
	checkPool(t, original)
	parseTokens(t, original)
}

// ---------------------------------------------------------------- <service>

func TestPatchZygoteService(t *testing.T) {
	for _, utf8 := range []bool{false, true} {
		name := "utf16-pool"
		if utf8 {
			name = "utf8-pool"
		}
		t.Run(name, func(t *testing.T) {
			isolateGlobals(t)
			original := fixtureOpts{
				utf8: utf8,
				resSlots: map[int]uint32{
					fxLabel:   idLabel,
					fxName:    resIDName,
					fxAllowBk: resIDAllowBackup,
					fxExport:  resIDExported,
				},
				appKids: []axTag{svcTag(fxSvcAbs), svcTag(fxSvcRel), svcTag(fxSvcBare)},
			}.bytes()
			path := useFixture(t, original)

			PatchZygoteService()

			patched := readManifest(t, path)
			checkChunks(t, patched)
			checkPool(t, patched)
			checkAttrOrder(t, patched)

			if len(patched) <= len(original) {
				t.Errorf("manifest did not grow: 0x%x -> 0x%x", len(original), len(patched))
			}

			tokens := parseTokens(t, patched)
			if got := len(elements(tokens, "service")); got != 4 {
				t.Fatalf("<service> count = %d, expected 4 (3 host + 1 injected); names %v",
					got, svcNames(tokens))
			}
			// the host's own services are still declared
			names := svcNames(tokens)
			for _, want := range []string{fixturePkg + ".ExistingService", ".RelativeService", "KeepMeService"} {
				if !containsStr(names, want) {
					t.Errorf("host <service android:name=%q> disappeared (got %v)", want, names)
				}
			}

			// the injected element carries android:name + the three booleans
			var injected map[string]string
			for _, el := range elements(tokens, "service") {
				if attrsOf(el)["name"] == serviceClassName {
					injected = attrsOf(el)
				}
			}
			if injected == nil {
				t.Fatalf("injected <service %s> not found (got %v)", serviceClassName, names)
			}
			for _, a := range []string{"exported", "isolatedProcess", "useAppZygote"} {
				if injected[a] != "true" {
					t.Errorf("android:%s = %q, expected \"true\"", a, injected[a])
				}
			}
			if p := parentOf(t, tokens, "service", "name", serviceClassName); p != "application" {
				t.Errorf("injected <service> sits in <%s>, expected <application>", p)
			}

			// the element is the first child of <application> and carries exactly
			// the four framework attributes, ascending by resource id
			appOff := childElementOffset(t, patched, "application")
			services := 0
			for _, c := range childElements(patched, appOff) {
				if elementName(parseStringPool(patched), patched, c) != "service" {
					continue
				}
				ids := attrResIDs(t, patched, c.startOff)
				if !containsU32(ids, resIDUseAppZygote) {
					continue
				}
				services++
				want := []uint32{resIDName, resIDExported, resIDIsolatedProcess, resIDUseAppZygote}
				if !reflect.DeepEqual(ids, want) {
					t.Errorf("injected <service> attribute resource ids = %#x, expected %#x", ids, want)
				}
			}
			if services != 1 {
				t.Errorf("found %d injected <service> elements, expected 1", services)
			}

			// string values of the injected element point at real pool entries
			pool := parseStringPool(patched)
			a, ok := findAttrByResID(patched, childElements(patched, appOff)[0].startOff, mustResIDs(patched), resIDName)
			if !ok {
				t.Fatal("injected <service> has no android:name")
			}
			if v := attrStringValue(pool, patched, a); v != serviceClassName {
				t.Errorf("android:name = %q, expected %q", v, serviceClassName)
			}
		})
	}
}

func containsU32(hay []uint32, needle uint32) bool {
	for _, v := range hay {
		if v == needle {
			return true
		}
	}
	return false
}

func mustResIDs(data []byte) []uint32 {
	ids, _, _ := readResMap(data)
	return ids
}

// ---------------------------------------------------------------- <instrumentation>

func TestPatchInstrumentation(t *testing.T) {
	isolateGlobals(t)
	writePlainPackage(t, fixturePkg)
	original := fixtureOpts{
		resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName},
		appKids:  []axTag{svcTag(fxSvcAbs)},
	}.bytes()
	path := useFixture(t, original)

	PatchInstrumentation()

	patched := readManifest(t, path)
	checkChunks(t, patched)
	checkPool(t, patched)
	checkAttrOrder(t, patched)
	tokens := parseTokens(t, patched)

	if got := elements(tokens, "instrumentation"); len(got) != 1 {
		t.Fatalf("<instrumentation> count = %d, expected 1", len(got))
	}
	got := attrsOf(elements(tokens, "instrumentation")[0])
	for k, want := range map[string]string{
		"name":           instrumentationClassName,
		"targetPackage":  fixturePkg,
		"functionalTest": "true",
	} {
		if got[k] != want {
			t.Errorf("android:%s = %q, expected %q", k, got[k], want)
		}
	}
	if p := parentOf(t, tokens, "instrumentation", "name", instrumentationClassName); p != "manifest" {
		t.Errorf("<instrumentation> sits in <%s>, expected <manifest>", p)
	}
	ii := startTagIndex(tokens, "instrumentation", "name", instrumentationClassName)
	ai := startTagIndex(tokens, "application", "", "")
	if ii < 0 || ai < 0 || ii > ai {
		t.Errorf("<instrumentation> (token %d) must precede <application> (token %d)", ii, ai)
	}
	if !containsStr(svcNames(tokens), fixturePkg+".ExistingService") {
		t.Error("host <service> disappeared")
	}

	// name < targetPackage < functionalTest, resolved through the resource map
	instrOff := childElementOffset(t, patched, "instrumentation")
	wantIDs := []uint32{resIDName, resIDTargetPackage, resIDFunctionalTest}
	if ids := attrResIDs(t, patched, instrOff); !reflect.DeepEqual(ids, wantIDs) {
		t.Errorf("<instrumentation> attribute resource ids = %#x, expected %#x", ids, wantIDs)
	}

	// a second run must not add a second element
	before := len(patched)
	PatchInstrumentation()
	after := readManifest(t, path)
	if len(after) != before {
		t.Errorf("second run changed the manifest size 0x%x -> 0x%x", before, len(after))
	}
	if got := elements(parseTokens(t, after), "instrumentation"); len(got) != 1 {
		t.Errorf("second run produced %d <instrumentation> elements", len(got))
	}
}

// ---------------------------------------------------------------- <application attributes>

func TestPatchBackupAgentInsertsAttributes(t *testing.T) {
	isolateGlobals(t)
	original := fixtureOpts{
		resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName},
		// any pool string can serve as the app label; the point is that
		// <application> already has an attribute before the vector runs
		appAttrs: []elemAttr{{uint32(fxNs), fxLabel, fxPkgName, uint8(AttrTypeString), fxPkgName}},
		appKids:  []axTag{svcTag(fxSvcAbs)},
	}.bytes()
	path := useFixture(t, original)

	PatchBackupAgent()

	patched := readManifest(t, path)
	checkChunks(t, patched)
	checkPool(t, patched)
	checkAttrOrder(t, patched)
	tokens := parseTokens(t, patched)

	apps := elements(tokens, "application")
	if len(apps) != 1 {
		t.Fatalf("<application> count = %d, expected 1", len(apps))
	}
	got := attrsOf(apps[0])
	if got["backupAgent"] != backupAgentClassName {
		t.Errorf("android:backupAgent = %q, expected %q", got["backupAgent"], backupAgentClassName)
	}
	if got["allowBackup"] != "true" {
		t.Errorf("android:allowBackup = %q, expected \"true\"", got["allowBackup"])
	}

	// both attributes were spliced in as fresh 20-byte slots, ascending
	origAppOff := childElementOffset(t, original, "application")
	if got, want := elementSize(patched, childElementOffset(t, patched, "application")), elementSize(original, origAppOff)+40; got != want {
		t.Errorf("<application> size = 0x%x, expected 0x%x (+2 attributes)", got, want)
	}
	if n := elementAttrCount(patched, childElementOffset(t, patched, "application")); n != 3 {
		t.Errorf("<application> attributeCount = %d, expected 3 (label + backupAgent + allowBackup)", n)
	}
	ids := attrResIDs(t, patched, childElementOffset(t, patched, "application"))
	want := []uint32{idLabel, resIDBackupAgent, resIDAllowBackup}
	if !reflect.DeepEqual(ids, want) {
		t.Errorf("<application> attribute resource ids = %#x, expected %#x", ids, want)
	}
}

func TestPatchBackupAgentRewritesAllowBackupInPlace(t *testing.T) {
	isolateGlobals(t)
	original := fixtureOpts{
		resSlots: map[int]uint32{
			fxLabel:       idLabel,
			fxName:        resIDName,
			fxAllowBk:     resIDAllowBackup,
			fxBackupAgent: resIDBackupAgent,
		},
		appAttrs: []elemAttr{
			{uint32(fxNs), fxBackupAgent, fxOldBackupAgent, uint8(AttrTypeString), fxOldBackupAgent},
			{uint32(fxNs), fxAllowBk, attrBoolTrue, uint8(AttrTypeIntBool), 0},
		},
		appKids: []axTag{svcTag(fxSvcAbs)},
	}.bytes()
	path := useFixture(t, original)
	origAppOff := childElementOffset(t, original, "application")

	PatchBackupAgent()

	patched := readManifest(t, path)
	checkChunks(t, patched)
	checkPool(t, patched)
	checkAttrOrder(t, patched)
	tokens := parseTokens(t, patched)

	got := attrsOf(elements(tokens, "application")[0])
	if got["backupAgent"] != backupAgentClassName {
		t.Errorf("android:backupAgent = %q, expected %q (value must be repointed)", got["backupAgent"], backupAgentClassName)
	}
	if got["allowBackup"] != "true" {
		t.Errorf("android:allowBackup = %q, expected \"true\"", got["allowBackup"])
	}

	// no attribute was added: the slot kept its size, only its value changed
	newAppOff := childElementOffset(t, patched, "application")
	if got, want := elementSize(patched, newAppOff), elementSize(original, origAppOff); got != want {
		t.Errorf("<application> size = 0x%x, expected the untouched 0x%x", got, want)
	}
	if got, want := elementAttrCount(patched, newAppOff), elementAttrCount(original, origAppOff); got != want {
		t.Errorf("<application> attributeCount = %d, expected %d", got, want)
	}
	a, ok := findAttrByResID(patched, newAppOff, mustResIDs(patched), resIDAllowBackup)
	if !ok {
		t.Fatal("android:allowBackup disappeared")
	}
	if a.dataType != uint8(AttrTypeIntBool) || a.data != attrBoolTrue {
		t.Errorf("android:allowBackup typed value = (0x%02x, 0x%08x), expected (0x12, 0xffffffff)", a.dataType, a.data)
	}
}

func TestPatchBackupAgentAlreadySatisfiedIsNoOp(t *testing.T) {
	isolateGlobals(t)
	original := fixtureOpts{
		resSlots: map[int]uint32{
			fxLabel:       idLabel,
			fxName:        resIDName,
			fxAllowBk:     resIDAllowBackup,
			fxBackupAgent: resIDBackupAgent,
		},
		appAttrs: []elemAttr{
			{uint32(fxNs), fxBackupAgent, fxClassIdx, uint8(AttrTypeString), fxClassIdx},
			{uint32(fxNs), fxAllowBk, attrBoolTrue, uint8(AttrTypeIntBool), attrBoolTrue},
		},
		appKids:      []axTag{svcTag(fxSvcAbs)},
		extraStrings: []string{backupAgentClassName},
	}.bytes()
	path := useFixture(t, original)

	PatchBackupAgent()

	patched := readManifest(t, path)
	if !bytes.Equal(patched, original) {
		t.Errorf("manifest changed although android:backupAgent already points at the injected class and android:allowBackup is true (0x%x -> 0x%x)",
			len(original), len(patched))
	}
}

// fxClassIdx is the pool index of backupAgentClassName in the fixture that appends
// it through fixtureOpts.extraStrings.
const fxClassIdx = fxOldBackupAgent + 1

func TestPatchZygotePreload(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		isolateGlobals(t)
		original := fixtureOpts{
			resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName},
			appAttrs: []elemAttr{{uint32(fxNs), fxLabel, fxPkgName, uint8(AttrTypeString), fxPkgName}},
			appKids:  []axTag{svcTag(fxSvcAbs)},
		}.bytes()
		path := useFixture(t, original)
		origAppOff := childElementOffset(t, original, "application")

		PatchZygotePreload()

		patched := readManifest(t, path)
		checkChunks(t, patched)
		checkPool(t, patched)
		checkAttrOrder(t, patched)

		got := attrsOf(elements(parseTokens(t, patched), "application")[0])
		if got["zygotePreloadName"] != zygotePreloadClassName {
			t.Errorf("android:zygotePreloadName = %q, expected %q", got["zygotePreloadName"], zygotePreloadClassName)
		}
		newAppOff := childElementOffset(t, patched, "application")
		if got, want := elementSize(patched, newAppOff), elementSize(original, origAppOff)+20; got != want {
			t.Errorf("<application> size = 0x%x, expected 0x%x (+1 attribute)", got, want)
		}
		ids := attrResIDs(t, patched, newAppOff)
		want := []uint32{idLabel, resIDZygotePreloadName}
		if !reflect.DeepEqual(ids, want) {
			t.Errorf("<application> attribute resource ids = %#x, expected %#x", ids, want)
		}
	})

	t.Run("present with another value", func(t *testing.T) {
		isolateGlobals(t)
		original := fixtureOpts{
			resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName, fxZygote: resIDZygotePreloadName},
			appAttrs: []elemAttr{
				{uint32(fxNs), fxLabel, fxSvcAbs, uint8(AttrTypeString), fxSvcAbs},
				{uint32(fxNs), fxZygote, fxSvcAbs, uint8(AttrTypeString), fxSvcAbs},
			},
			appKids: []axTag{svcTag(fxSvcAbs)},
		}.bytes()
		path := useFixture(t, original)
		origAppOff := childElementOffset(t, original, "application")

		PatchZygotePreload()

		patched := readManifest(t, path)
		checkChunks(t, patched)
		checkPool(t, patched)
		checkAttrOrder(t, patched)

		got := attrsOf(elements(parseTokens(t, patched), "application")[0])
		if got["zygotePreloadName"] != zygotePreloadClassName {
			t.Errorf("android:zygotePreloadName = %q, expected %q (value must be repointed)",
				got["zygotePreloadName"], zygotePreloadClassName)
		}
		newAppOff := childElementOffset(t, patched, "application")
		if got, want := elementSize(patched, newAppOff), elementSize(original, origAppOff); got != want {
			t.Errorf("<application> size = 0x%x, expected the untouched 0x%x", got, want)
		}
	})
}

// ---------------------------------------------------------------- DeclaredServiceClasses

func TestDeclaredServiceClasses(t *testing.T) {
	isolateGlobals(t)
	original := fixtureOpts{
		resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName},
		// the last <service> repeats the first one: duplicates collapse
		appKids: []axTag{svcTag(fxSvcAbs), svcTag(fxSvcRel), svcTag(fxSvcBare), svcTag(fxSvcAbs)},
	}.bytes()
	useFixture(t, original)

	want := []string{
		fixturePkg + ".ExistingService",
		fixturePkg + ".RelativeService",
		fixturePkg + ".KeepMeService",
	}
	if got := DeclaredServiceClasses(); !reflect.DeepEqual(got, want) {
		t.Errorf("DeclaredServiceClasses() = %v, expected %v", got, want)
	}

	// after the service vector the injected class is part of the list too
	PatchZygoteService()
	got := DeclaredServiceClasses()
	if !containsStr(got, serviceClassName) {
		t.Errorf("injected %s missing from %v", serviceClassName, got)
	}
	if len(got) != len(want)+1 {
		t.Errorf("DeclaredServiceClasses() = %v, expected %d entries", got, len(want)+1)
	}
}

func TestDeclaredServiceClassesRelativeResolution(t *testing.T) {
	isolateGlobals(t)
	// a <service> whose name has no dot at all is resolved against the package
	// as well (PackageParser semantics)
	original := fixtureOpts{
		resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName},
		appKids:  []axTag{svcTag(fxSvcBare)},
	}.bytes()
	useFixture(t, original)

	got := DeclaredServiceClasses()
	want := []string{fixturePkg + ".KeepMeService"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("DeclaredServiceClasses() = %v, expected %v", got, want)
	}
}

func TestDeclaredServiceClassesMissingManifest(t *testing.T) {
	isolateGlobals(t)
	old := utils.ManifestBinaryPath
	utils.ManifestBinaryPath = filepath.Join(t.TempDir(), "missing.xml")
	t.Cleanup(func() { utils.ManifestBinaryPath = old })

	if got := DeclaredServiceClasses(); got != nil {
		t.Errorf("DeclaredServiceClasses() = %v, expected nil for a missing manifest", got)
	}
}

// ------------------------------------------------- independent cross-check

// aapt2Path locates aapt2: PATH first, then the usual SDK layouts. The
// cross-check below is skipped when no Android SDK is installed.
func aapt2Path(t *testing.T) string {
	t.Helper()
	if p, err := exec.LookPath("aapt2"); err == nil {
		return p
	}
	roots := []string{
		os.Getenv("ANDROID_HOME"),
		os.Getenv("ANDROID_SDK_ROOT"),
		filepath.Join(os.Getenv("HOME"), "Library/Android/sdk"),
		filepath.Join(os.Getenv("HOME"), "Android/Sdk"),
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		matches, _ := filepath.Glob(filepath.Join(root, "build-tools", "*", "aapt2"))
		if len(matches) == 0 {
			continue
		}
		sort.Strings(matches)
		return matches[len(matches)-1]
	}
	t.Skip("aapt2 not found (no Android SDK): skipping the independent AXML cross-check")
	return ""
}

// writeSingleEntryAPK packs the binary manifest the way aapt2 dump expects to
// find it: a zip holding AndroidManifest.xml.
func writeSingleEntryAPK(path string, manifest []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		return err
	}
	if _, err := w.Write(manifest); err != nil {
		return err
	}
	return zw.Close()
}

// TestPatchedManifestReadsBackWithAapt2 runs all four vectors on the fixture and
// has aapt2 print the resulting tree. aapt2 resolves attributes through the same
// resource map logic the platform uses, so a wrong resource id, a broken string
// pool or an out-of-order attribute list is visible here as a missing or garbled
// element - this is the only check in the file that does not go through this
// package's own parser.
func TestPatchedManifestReadsBackWithAapt2(t *testing.T) {
	aapt2 := aapt2Path(t)
	isolateGlobals(t)
	writePlainPackage(t, fixturePkg)
	original := fixtureOpts{
		resSlots: map[int]uint32{fxLabel: idLabel, fxName: resIDName},
		appAttrs: []elemAttr{{uint32(fxNs), fxLabel, fxPkgName, uint8(AttrTypeString), fxPkgName}},
		appKids:  []axTag{svcTag(fxSvcAbs), svcTag(fxSvcRel), svcTag(fxSvcBare)},
	}.bytes()
	path := useFixture(t, original)

	PatchZygoteService()
	PatchInstrumentation()
	PatchBackupAgent()
	PatchZygotePreload()

	patched := readManifest(t, path)
	apk := filepath.Join(t.TempDir(), "probe.apk")
	if err := writeSingleEntryAPK(apk, patched); err != nil {
		t.Fatalf("pack manifest: %v", err)
	}
	out, err := exec.Command(aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk).CombinedOutput()
	if err != nil {
		t.Fatalf("aapt2 dump xmltree failed: %v\n%s", err, out)
	}
	tree := string(out)
	for _, want := range []string{
		":name(0x01010003)=\"" + serviceClassName + "\"",
		":exported(0x01010010)=true",
		":isolatedProcess(0x010103a9)=true",
		":useAppZygote(0x01010597)=true",
		":name(0x01010003)=\"" + instrumentationClassName + "\"",
		":targetPackage(0x01010021)=\"" + fixturePkg + "\"",
		":functionalTest(0x01010023)=true",
		":backupAgent(0x0101027f)=\"" + backupAgentClassName + "\"",
		":allowBackup(0x01010280)=true",
		":zygotePreloadName(0x0101059d)=\"" + zygotePreloadClassName + "\"",
	} {
		if !strings.Contains(tree, want) {
			t.Errorf("aapt2 does not see %s\n--- aapt2 output ---\n%s", want, tree)
		}
	}
	if strings.Count(tree, "E: service") != 4 {
		t.Errorf("aapt2 sees %d <service> elements, expected 4\n%s", strings.Count(tree, "E: service"), tree)
	}
	// the injected <service> must be a child of <application>
	if strings.Index(tree, serviceClassName) < strings.Index(tree, "E: application") {
		t.Errorf("aapt2 places the injected <service> outside <application>\n%s", tree)
	}
	// and <instrumentation> a child of <manifest>, in front of <application>
	if strings.Index(tree, instrumentationClassName) > strings.Index(tree, "E: application") {
		t.Errorf("aapt2 places <instrumentation> after <application>\n%s", tree)
	}
}
