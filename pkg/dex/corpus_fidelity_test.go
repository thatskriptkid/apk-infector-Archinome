package dex

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestCorpusRoundTripFidelity measures the one property vectors 9 and 11 rest on:
// a host dex can be parsed, re-encoded and parsed again without losing anything.
// The injector rewrites a host dex to splice a call into an existing method, so a
// host whose dex cannot survive a *plain* round-trip (no splice at all) is a host
// where the code-patch vectors must be reported as inapplicable instead of
// producing a broken dex.
//
// Gated on ARCHINOME_CORPUS_DIR (the same variable the corpus harness uses), so a
// hermetic `go test ./...` skips it:
//
//	ARCHINOME_CORPUS_DIR=/tmp/corpus go test ./pkg/dex/ -run TestCorpusRoundTripFidelity -v
func TestCorpusRoundTripFidelity(t *testing.T) {
	dir := os.Getenv("ARCHINOME_CORPUS_DIR")
	if dir == "" {
		t.Skip("ARCHINOME_CORPUS_DIR is not set: corpus measurement skipped")
	}
	apks, err := filepath.Glob(filepath.Join(dir, "apk", "*.apk"))
	if err != nil || len(apks) == 0 {
		t.Fatalf("no APKs under %s/apk (err=%v)", dir, err)
	}
	sort.Strings(apks)

	dexRe := regexp.MustCompile(`^classes\d*\.dex$`)
	var hosts, dexes, failed, totalInsns, totalStrings int
	for _, apk := range apks {
		host := strings.TrimSuffix(filepath.Base(apk), ".apk")
		zr, err := zip.OpenReader(apk)
		if err != nil {
			t.Errorf("%s: open: %v", host, err)
			failed++
			continue
		}
		hostDexes := 0
		for _, e := range zr.File {
			if !dexRe.MatchString(e.Name) {
				continue
			}
			hostDexes++
			dexes++
			raw, err := readZipEntry(e)
			if err != nil {
				t.Errorf("%s/%s: read: %v", host, e.Name, err)
				failed++
				continue
			}
			// Validate the pristine dex first: if *it* is rejected, the fault
			// is in our validator, not in the encoder, and the two must never
			// be conflated in the report.
			pristinePath := filepath.Join(t.TempDir(), "pristine.dex")
			if err := os.WriteFile(pristinePath, raw, 0o600); err != nil {
				t.Errorf("FIDELITY FAIL %s/%s: writing pristine copy: %v", host, e.Name, err)
				failed++
				continue
			}
			if err := Validate(pristinePath); err != nil {
				t.Errorf("PRISTINE REJECTED %s/%s: %v", host, e.Name, err)
				failed++
				continue
			}
			res, err := roundTripFidelity(t, raw)
			if err != nil {
				t.Errorf("FIDELITY FAIL %s/%s: %v", host, e.Name, err)
				failed++
				continue
			}
			totalInsns += res.insns
			totalStrings += res.strings
			t.Logf("FIDELITY OK %s/%s strings=%d methods=%d insns=%d bytes=%d",
				host, e.Name, res.strings, res.methods, res.insns, res.bytes)
		}
		zr.Close()
		if hostDexes == 0 {
			t.Errorf("%s: no classes.dex inside", host)
			failed++
		}
		hosts++
	}
	t.Logf("corpus fidelity: %d hosts, %d dexes, %d failed, %d strings and %d instructions compared",
		hosts, dexes, failed, totalStrings, totalInsns)
	if failed != 0 {
		t.Errorf("%d of %d dexes did not survive a plain round-trip", failed, dexes)
	}
}

func readZipEntry(e *zip.File) ([]byte, error) {
	rc, err := e.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

type fidelityResult struct {
	strings, methods, insns, bytes int
}

// roundTripFidelity parses, re-encodes, re-parses and validates one dex, then
// compares the two models.
func roundTripFidelity(t *testing.T, raw []byte) (fidelityResult, error) {
	t.Helper()
	before, err := Parse(raw)
	if err != nil {
		return fidelityResult{}, fmt.Errorf("parse: %w", err)
	}
	out, err := before.Encode()
	if err != nil {
		return fidelityResult{}, fmt.Errorf("encode: %w", err)
	}
	after, err := Parse(out)
	if err != nil {
		return fidelityResult{}, fmt.Errorf("reparse of our own output: %w", err)
	}
	tmp := filepath.Join(t.TempDir(), "roundtrip.dex")
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return fidelityResult{}, err
	}
	if err := Validate(tmp); err != nil {
		return fidelityResult{}, fmt.Errorf("validate: %w", err)
	}
	if err := compareModels(before, after); err != nil {
		return fidelityResult{}, err
	}
	n := 0
	for _, c := range after.Classes {
		if c.ClassData == nil {
			continue
		}
		for _, m := range c.ClassData.DirectMethods {
			if m.Code != nil {
				n += len(m.Code.Insns)
			}
		}
		for _, m := range c.ClassData.VirtualMethods {
			if m.Code != nil {
				n += len(m.Code.Insns)
			}
		}
	}
	if n == 0 {
		// Legitimate for a pure-interface dex (org.cryptomator.lite's
		// classes3.dex is four j$/util/concurrent/Flow interfaces with no
		// bodies at all), but not for a dex that did have code: that would
		// mean the encoder dropped every body and the comparison above saw
		// nothing to check.
		for _, c := range before.Classes {
			if c.ClassData == nil {
				continue
			}
			for _, m := range append(append([]EncMethod{}, c.ClassData.DirectMethods...), c.ClassData.VirtualMethods...) {
				if m.Code != nil {
					return fidelityResult{}, fmt.Errorf("%d methods have code in the source but no body came back", 1)
				}
			}
		}
	}
	return fidelityResult{strings: len(after.Strings), methods: len(after.Methods), insns: n, bytes: len(out)}, nil
}

// compareModels reports the first structural difference between two models. The
// identifier tables must come back identical -- a plain re-encode adds no ids, so
// the encoder has no reason to move anything -- and every method body must be
// byte-identical, try items and catch handler addresses included.
func compareModels(before, after *DexFile) error {
	if len(before.Strings) != len(after.Strings) {
		return fmt.Errorf("strings %d -> %d", len(before.Strings), len(after.Strings))
	}
	for i := range before.Strings {
		if before.Strings[i] != after.Strings[i] {
			return fmt.Errorf("string[%d] %q -> %q", i, before.Strings[i], after.Strings[i])
		}
	}
	for _, tc := range []struct {
		name string
		a, b int
	}{
		{"types", len(before.Types), len(after.Types)},
		{"protos", len(before.Protos), len(after.Protos)},
		{"fields", len(before.Fields), len(after.Fields)},
		{"methods", len(before.Methods), len(after.Methods)},
		{"classes", len(before.Classes), len(after.Classes)},
	} {
		if tc.a != tc.b {
			return fmt.Errorf("%s %d -> %d", tc.name, tc.a, tc.b)
		}
	}
	for i := range before.Types {
		if before.Types[i] != after.Types[i] {
			return fmt.Errorf("type_ids[%d] %d -> %d", i, before.Types[i], after.Types[i])
		}
	}
	for i := range before.Methods {
		if before.Methods[i] != after.Methods[i] {
			return fmt.Errorf("method_ids[%d] differs: %+v -> %+v", i, before.Methods[i], after.Methods[i])
		}
	}
	for i := range before.Fields {
		if before.Fields[i] != after.Fields[i] {
			return fmt.Errorf("field_ids[%d] differs: %+v -> %+v", i, before.Fields[i], after.Fields[i])
		}
	}
	if !reflect.DeepEqual(before.Protos, after.Protos) {
		return fmt.Errorf("proto_ids differ")
	}
	// class_defs is ordered, so compare positionally.
	for i := range before.Classes {
		bc, ac := before.Classes[i], after.Classes[i]
		if bc.ClassIdx != ac.ClassIdx || bc.Superclass != ac.Superclass || bc.AccessFlags != ac.AccessFlags {
			return fmt.Errorf("class_defs[%d]: type/super/access %d/%d/%#x -> %d/%d/%#x",
				i, bc.ClassIdx, bc.Superclass, bc.AccessFlags, ac.ClassIdx, ac.Superclass, ac.AccessFlags)
		}
		if !reflect.DeepEqual(bc.Interfaces, ac.Interfaces) {
			return fmt.Errorf("class_defs[%d]: interfaces differ", i)
		}
		if bc.SourceFile != ac.SourceFile {
			return fmt.Errorf("class_defs[%d]: source_file %d -> %d", i, bc.SourceFile, ac.SourceFile)
		}
		if !reflect.DeepEqual(bc.StaticValues, ac.StaticValues) {
			return fmt.Errorf("class_defs[%d]: static values differ", i)
		}
		bcd, acd := bc.ClassData, ac.ClassData
		switch {
		case bcd == nil && acd == nil:
			continue
		case bcd == nil || acd == nil:
			return fmt.Errorf("class_defs[%d]: class_data presence changed", i)
		}
		if !reflect.DeepEqual(bcd.StaticFields, acd.StaticFields) ||
			!reflect.DeepEqual(bcd.InstanceFields, acd.InstanceFields) {
			return fmt.Errorf("class_defs[%d]: encoded fields differ", i)
		}
		if len(bcd.DirectMethods) != len(acd.DirectMethods) || len(bcd.VirtualMethods) != len(acd.VirtualMethods) {
			return fmt.Errorf("class_defs[%d]: method counts %d/%d -> %d/%d", i,
				len(bcd.DirectMethods), len(bcd.VirtualMethods), len(acd.DirectMethods), len(acd.VirtualMethods))
		}
		for j := range bcd.DirectMethods {
			if err := compareMethod(i, "direct", j, bcd.DirectMethods[j], acd.DirectMethods[j]); err != nil {
				return err
			}
		}
		for j := range bcd.VirtualMethods {
			if err := compareMethod(i, "virtual", j, bcd.VirtualMethods[j], acd.VirtualMethods[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

func compareMethod(classIdx int, kind string, j int, bm, am EncMethod) error {
	if bm.Method != am.Method || bm.Access != am.Access {
		return fmt.Errorf("class_defs[%d] %s[%d]: id/access %d/%#x -> %d/%#x",
			classIdx, kind, j, bm.Method, bm.Access, am.Method, am.Access)
	}
	switch {
	case bm.Code == nil && am.Code == nil:
		return nil
	case bm.Code == nil || am.Code == nil:
		return fmt.Errorf("class_defs[%d] %s[%d]: body presence changed", classIdx, kind, j)
	}
	bc, ac := bm.Code, am.Code
	if bc.Registers != ac.Registers || bc.Ins != ac.Ins || bc.Outs != ac.Outs {
		return fmt.Errorf("class_defs[%d] %s[%d]: registers/ins/outs %d/%d/%d -> %d/%d/%d",
			classIdx, kind, j, bc.Registers, bc.Ins, bc.Outs, ac.Registers, ac.Ins, ac.Outs)
	}
	if !reflect.DeepEqual(bc.Insns, ac.Insns) {
		for k := range bc.Insns {
			if k < len(ac.Insns) && bc.Insns[k] != ac.Insns[k] {
				return fmt.Errorf("class_defs[%d] %s[%d]: insns[%d] %#04x -> %#04x",
					classIdx, kind, j, k, bc.Insns[k], ac.Insns[k])
			}
		}
		return fmt.Errorf("class_defs[%d] %s[%d]: insns length %d -> %d",
			classIdx, kind, j, len(bc.Insns), len(ac.Insns))
	}
	if !reflect.DeepEqual(bc.Tries, ac.Tries) {
		return fmt.Errorf("class_defs[%d] %s[%d]: try items differ", classIdx, kind, j)
	}
	if !reflect.DeepEqual(bc.Handlers, ac.Handlers) {
		return fmt.Errorf("class_defs[%d] %s[%d]: catch handlers differ", classIdx, kind, j)
	}
	return nil
}
