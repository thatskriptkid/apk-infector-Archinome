package dex

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The tests build their inputs through the model and the encoder, so they read
// exactly the bytes the production path produces: Parse -> patch -> Encode.

const (
	cpHostDesc    = "Ltest/Host;"
	cpPayloadDesc = "Ltest/Payload;"
	cpObjectDesc  = "Ljava/lang/Object;"
	cpCatchDesc   = "Ljava/lang/Throwable;"
	cpPayloadRun  = "run"

	// The payload the injector ships for the two code-patch vectors
	// (payload_apppatch.dex / payload_service.dex, built by d8).
	cpRealPayloadClass  = "Laaaaaaaaaaaa/AppPatch;"
	cpRealPayloadMethod = "run"
)

// entryMethodPriority mirrors what internal/injector passes in.
var entryMethodPriority = []string{"<clinit>", "<init>"}

// --------------------------------------------------------------- model builder

// fixture builds a dex file through the model.
type fixture struct {
	f *DexFile

	str map[string]uint32
	typ map[string]uint32
}

func newFixture() *fixture {
	return &fixture{f: &DexFile{Version: "035"}, str: map[string]uint32{}, typ: map[string]uint32{}}
}

// s interns a string and returns its model index (the "old" space).
func (x *fixture) s(v string) uint32 {
	if i, ok := x.str[v]; ok {
		return i
	}
	i := uint32(len(x.f.Strings))
	x.f.Strings = append(x.f.Strings, v)
	x.str[v] = i
	return i
}

// t interns a type for a descriptor and returns its model index.
func (x *fixture) t(desc string) uint32 {
	if i, ok := x.typ[desc]; ok {
		return i
	}
	i := uint32(len(x.f.Types))
	x.f.Types = append(x.f.Types, x.s(desc))
	x.typ[desc] = i
	return i
}

// p interns the prototype return(params...).
func (x *fixture) p(ret string, params ...string) uint32 {
	key := shortyOf(ret, params)
	for i, pr := range x.f.Protos {
		if x.f.Strings[pr.Shorty] != key || len(pr.Params) != len(params) ||
			x.f.Types[pr.Return] != x.s(ret) {
			continue
		}
		match := true
		for j, ps := range params {
			if x.f.Types[pr.Params[j]] != x.s(ps) {
				match = false
			}
		}
		if match {
			return uint32(i)
		}
	}
	var ps []uint32 // nil, not empty: parameters_off stays 0
	for _, d := range params {
		ps = append(ps, x.t(d))
	}
	i := uint32(len(x.f.Protos))
	x.f.Protos = append(x.f.Protos, Proto{Shorty: x.s(key), Return: x.t(ret), Params: ps})
	return i
}

// m interns a method id.
func (x *fixture) m(class string, proto uint32, name string) uint32 {
	for i, mm := range x.f.Methods {
		if mm.Class == x.t(class) && mm.Proto == proto && mm.Name == x.s(name) {
			return uint32(i)
		}
	}
	i := uint32(len(x.f.Methods))
	x.f.Methods = append(x.f.Methods, Method{Class: x.t(class), Proto: proto, Name: x.s(name)})
	return uint32(i)
}

func shortyOf(ret string, params []string) string {
	b := []byte{shortyChar(ret)}
	for _, p := range params {
		b = append(b, shortyChar(p))
	}
	return string(b)
}

func shortyChar(desc string) byte {
	if desc == "" {
		return 'V'
	}
	switch desc {
	case "V", "I", "Z", "J":
		return desc[0]
	}
	if strings.HasPrefix(desc, "L") || strings.HasPrefix(desc, "[") {
		return 'L'
	}
	return desc[0]
}

// addClass appends a class_def with the given direct/virtual methods.
func (x *fixture) addClass(desc string, access uint32, super string, direct, virtual []EncMethod) {
	x.f.Classes = append(x.f.Classes, ClassDef{
		ClassIdx:    x.t(desc),
		AccessFlags: access,
		Superclass:  x.t(super),
		SourceFile:  NoIndex,
		ClassData:   &ClassData{DirectMethods: direct, VirtualMethods: virtual},
	})
}

// ------------------------------------------------------------ fixture contents

// codePatchFixture emits the dex used by most tests. The Host class mirrors what
// the vectors meet in the field:
//
//	Host.<clinit>   const/4 v0,#0 ; return-void     <- protected by try 0..1
//	                move-exception v0 ; return-void  (catch handler at unit 2)
//	Host.<init>     invoke-direct {v0}, Object.<init>()V ; return-void
//	Host.go         return-void
func codePatchFixture(t *testing.T) []byte {
	t.Helper()
	return encodeFixture(t, newFixture())
}

// encodeFixture adds the Host class on top of x and returns the encoded dex.
func encodeFixture(t *testing.T, x *fixture) []byte {
	t.Helper()
	objInit := x.m(cpObjectDesc, x.p("V"), "<init>")
	clinit := x.m(cpHostDesc, x.p("V"), "<clinit>")
	init := x.m(cpHostDesc, x.p("V"), "<init>")
	virtual := x.m(cpHostDesc, x.p("V"), "go")

	clinitCode := &CodeItem{
		Registers: 1,
		Insns: []uint16{
			0x0012, // const/4 v0, #0
			0x000e, // return-void
			0x000d, // move-exception v0 -- catch handler target, unit 2
			0x000e, // return-void
		},
		Tries:    []TryItem{{StartAddr: 0, InsnCount: 2, HandlerIdx: 0}},
		Handlers: [][]CatchHandler{{{Type: x.t(cpCatchDesc), Addr: 2}}},
	}
	initCode := &CodeItem{
		Registers: 1,
		Ins:       1,
		Insns:     []uint16{0x1070, uint16(objInit), 0x0000, 0x000e},
	}
	goCode := &CodeItem{Registers: 1, Ins: 1, Insns: []uint16{0x000e}}

	x.addClass(cpHostDesc, 0x0001, cpObjectDesc,
		[]EncMethod{
			{Method: clinit, Access: 0x0009, Code: clinitCode},
			{Method: init, Access: 0x0001, Code: initCode},
		},
		[]EncMethod{{Method: virtual, Access: 0x0001, Code: goCode}},
	)

	raw, err := x.f.Encode()
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	if _, err := Parse(raw); err != nil {
		t.Fatalf("the fixture dex does not even parse: %v", err)
	}
	return raw
}

func mustParse(t *testing.T, raw []byte) *DexFile {
	t.Helper()
	f, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

func classDef(t *testing.T, f *DexFile, desc string) *ClassDef {
	t.Helper()
	for i := range f.Classes {
		got, err := f.typeDescriptor(f.Classes[i].ClassIdx)
		if err != nil {
			t.Fatalf("typeDescriptor: %v", err)
		}
		if got == desc {
			return &f.Classes[i]
		}
	}
	t.Fatalf("class %s not in the dex", desc)
	return nil
}

func codeOf(t *testing.T, f *DexFile, desc, name string) *CodeItem {
	t.Helper()
	cd := classDef(t, f, desc)
	if cd.ClassData == nil {
		t.Fatalf("class %s has no class_data", desc)
	}
	all := append(append([]EncMethod{}, cd.ClassData.DirectMethods...), cd.ClassData.VirtualMethods...)
	for _, m := range all {
		got, err := f.methodName(m.Method)
		if err != nil {
			t.Fatalf("methodName: %v", err)
		}
		if got == name {
			if m.Code == nil {
				t.Fatalf("method %s->%s has no code", desc, name)
			}
			return m.Code
		}
	}
	t.Fatalf("method %s->%s not found", desc, name)
	return nil
}

// resolveMethod decodes a method_ids entry into class descriptor, name, return
// type descriptor and parameter count -- exactly what a 35c operand means.
func resolveMethod(t *testing.T, f *DexFile, idx uint32) (class, name, ret string, nparams int) {
	t.Helper()
	if int(idx) >= len(f.Methods) {
		t.Fatalf("method index %d out of range (%d methods)", idx, len(f.Methods))
	}
	m := f.Methods[idx]
	var err error
	if class, err = f.typeDescriptor(m.Class); err != nil {
		t.Fatalf("class of method %d: %v", idx, err)
	}
	if name, err = f.methodName(idx); err != nil {
		t.Fatalf("name of method %d: %v", idx, err)
	}
	if int(m.Proto) >= len(f.Protos) {
		t.Fatalf("proto index %d out of range", m.Proto)
	}
	p := f.Protos[m.Proto]
	if ret, err = f.typeDescriptor(p.Return); err != nil {
		t.Fatalf("return type of method %d: %v", idx, err)
	}
	return class, name, ret, len(p.Params)
}

// payloadMethodIds counts method_ids entries that mean class->name()V, so a
// duplicated id (or a call that resolves elsewhere) is visible.
func payloadMethodIds(f *DexFile, class, name string) int {
	n := 0
	for i := range f.Methods {
		m := f.Methods[i]
		c, err := f.typeDescriptor(m.Class)
		if err != nil {
			continue
		}
		nm, err := f.methodName(uint32(i))
		if err != nil {
			continue
		}
		ret := ""
		params := -1
		if int(m.Proto) < len(f.Protos) {
			p := f.Protos[m.Proto]
			params = len(p.Params)
			ret, _ = f.typeDescriptor(p.Return)
		}
		if c == class && nm == name && ret == "V" && params == 0 {
			n++
		}
	}
	return n
}

// bodyWithoutDebug copies a code_item with debug info stripped, so two parses of
// the same method can be compared field by field (debug pointers differ per
// parse even when their contents match).
func bodyWithoutDebug(ci *CodeItem) CodeItem {
	cp := *ci
	cp.Debug = nil
	return cp
}

// --------------------------------------------------------------------- tests

// TestCodePatchPrependsInvokeStatic is the main assertion set: the payload call
// is the first instruction of <clinit>, it points at a method id resolving to
// the payload class/method/(), the try table and catch handler moved by exactly
// the 3 code units the insert added, and nothing else in the file moved.
func TestCodePatchPrependsInvokeStatic(t *testing.T) {
	raw := codePatchFixture(t)
	before := mustParse(t, raw)
	beforeClinit := codeOf(t, before, cpHostDesc, "<clinit>")

	out, patched, err := InsertPayloadCall(raw, []string{cpHostDesc}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	if err != nil {
		t.Fatalf("InsertPayloadCall: %v", err)
	}
	if want := []string{cpHostDesc + "-><clinit>"}; !reflect.DeepEqual(patched, want) {
		t.Fatalf("patched = %v, want %v", patched, want)
	}

	after := mustParse(t, out)
	clinit := codeOf(t, after, cpHostDesc, "<clinit>")

	if len(clinit.Insns) != len(beforeClinit.Insns)+3 {
		t.Fatalf("clinit insns = %d units, want %d", len(clinit.Insns), len(beforeClinit.Insns)+3)
	}
	// 35c invoke-static {}, Lpayload;->run()V
	if clinit.Insns[0] != 0x0071 || clinit.Insns[2] != 0x0000 {
		t.Fatalf("first instruction = %#04x %#04x %#04x, want 0x0071 <payload id> 0x0000 (35c invoke-static, no args)",
			clinit.Insns[0], clinit.Insns[1], clinit.Insns[2])
	}
	class, name, ret, nparams := resolveMethod(t, after, uint32(clinit.Insns[1]))
	if class != cpPayloadDesc || name != cpPayloadRun || ret != "V" || nparams != 0 {
		t.Fatalf("operand %d resolves to %s->%s(%d params)%s, want %s->%s()V",
			clinit.Insns[1], class, name, nparams, ret, cpPayloadDesc, cpPayloadRun)
	}
	if n := payloadMethodIds(after, cpPayloadDesc, cpPayloadRun); n != 1 {
		t.Fatalf("the payload method id appears %d times, want exactly 1", n)
	}
	// The original body follows the inserted call, unchanged.
	if !reflect.DeepEqual(clinit.Insns[3:], beforeClinit.Insns) {
		t.Fatalf("clinit body changed: %#v, want %#v", clinit.Insns[3:], beforeClinit.Insns)
	}

	// Try ranges and catch handlers shift with the code they cover.
	if got := clinit.Tries[0].StartAddr; got != 3 {
		t.Errorf("try StartAddr = %d, want 3", got)
	}
	if got := clinit.Tries[0].InsnCount; got != 2 {
		t.Errorf("try InsnCount = %d, want 2 (unchanged)", got)
	}
	if len(clinit.Handlers) != 1 || len(clinit.Handlers[0]) != 1 {
		t.Fatalf("handlers = %v, want one typed handler", clinit.Handlers)
	}
	if got := clinit.Handlers[0][0].Addr; got != 5 {
		t.Errorf("catch handler Addr = %d, want 5", got)
	}
	hdesc, err := after.typeDescriptor(clinit.Handlers[0][0].Type)
	if err != nil {
		t.Fatalf("handler type: %v", err)
	}
	if hdesc != cpCatchDesc {
		t.Errorf("handler type = %s, want %s", hdesc, cpCatchDesc)
	}

	// A zero-argument invoke needs no outgoing arguments and no new registers.
	if clinit.Registers != beforeClinit.Registers || clinit.Ins != beforeClinit.Ins || clinit.Outs != beforeClinit.Outs {
		t.Errorf("clinit registers=%d ins=%d outs=%d, want %d/%d/%d",
			clinit.Registers, clinit.Ins, clinit.Outs,
			beforeClinit.Registers, beforeClinit.Ins, beforeClinit.Outs)
	}

	// Every other method is untouched.
	for _, m := range []struct{ desc, name string }{
		{cpHostDesc, "<init>"},
		{cpHostDesc, "go"},
	} {
		got := bodyWithoutDebug(codeOf(t, after, m.desc, m.name))
		want := bodyWithoutDebug(codeOf(t, before, m.desc, m.name))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s->%s changed:\n got %+v\nwant %+v", m.desc, m.name, got, want)
		}
	}
	if len(after.Classes) != len(before.Classes) {
		t.Errorf("class count changed: %d -> %d", len(before.Classes), len(after.Classes))
	}
}

// TestCodePatchKeeps35cRegisterWords guards the format of the instruction this
// file splices. A 35c instruction is [op|A|G] [BBBB index] [F|E|D|C registers]:
// the operand lives in the *second* code unit (dexdump ground truth, see
// insns.go). A writer that looked for it in the third unit would rewrite the
// register list of every invoke-* in the file and leave the real index alone --
// invisible while the identifier tables happen to be an identity permutation,
// corrupt as soon as a new id shifts them (the whole point of this vector).
//
// The fixture forces a non-identity permutation: the payload method id is added
// last and sorts before Ltest/Zzz;->go, so the tail of the method table moves.
func TestCodePatchKeeps35cRegisterWords(t *testing.T) {
	const (
		callDesc = "Ltest/Call;"
		zzzDesc  = "Ltest/Zzz;"
	)
	x := newFixture()
	objInit := x.m(cpObjectDesc, x.p("V"), "<init>")
	callInit := x.m(callDesc, x.p("V"), "<init>")
	zzzGo := x.m(zzzDesc, x.p("V"), "go")
	// invoke-direct {}, Object.<init>()V with the register word 0x1000: a value
	// far outside any method id in this dex, so remapping it as an operand is
	// visible immediately.
	invoke := []uint16{0x1070, uint16(objInit), 0x1000, 0x000e}
	x.addClass(callDesc, 0x0001, cpObjectDesc,
		[]EncMethod{{Method: callInit, Access: 0x0001, Code: &CodeItem{Registers: 2, Ins: 1, Insns: invoke}}}, nil)
	x.addClass(zzzDesc, 0x0001, cpObjectDesc, nil,
		[]EncMethod{{Method: zzzGo, Access: 0x0001, Code: &CodeItem{Registers: 1, Ins: 1, Insns: []uint16{0x000e}}}})
	raw := encodeFixture(t, x)

	before := mustParse(t, raw)
	beforeInit := codeOf(t, before, callDesc, "<init>")
	if !reflect.DeepEqual(beforeInit.Insns, invoke) {
		t.Fatalf("fixture RoundTrip changed the invoke: %#v", beforeInit.Insns)
	}

	out, patched, err := InsertPayloadCall(raw, []string{callDesc}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	if err != nil {
		t.Fatalf("InsertPayloadCall: %v", err)
	}
	if len(patched) != 1 {
		t.Fatalf("patched = %v, want one entry", patched)
	}
	after := mustParse(t, out)
	got := codeOf(t, after, callDesc, "<init>")

	if len(got.Insns) != len(invoke)+3 {
		t.Fatalf("insns = %#v, want %d units", got.Insns, len(invoke)+3)
	}
	// Spliced invoke-static: op, payload id, empty register word.
	if got.Insns[0] != 0x0071 || got.Insns[2] != 0x0000 {
		t.Errorf("spliced invoke = %#04x %#04x %#04x, want 0x0071 <payload id> 0x0000",
			got.Insns[0], got.Insns[1], got.Insns[2])
	}
	class, name, _, _ := resolveMethod(t, after, uint32(got.Insns[1]))
	if class != cpPayloadDesc || name != cpPayloadRun {
		t.Errorf("payload operand %d resolves to %s->%s", got.Insns[1], class, name)
	}
	// The register word of the original invoke must survive untouched.
	if got.Insns[5] != 0x1000 {
		t.Errorf("invoke register word = %#04x, want 0x1000 (the register list was remapped as an index)", got.Insns[5])
	}
	class, name, ret, _ := resolveMethod(t, after, uint32(got.Insns[4]))
	if class != cpObjectDesc || name != "<init>" || ret != "V" {
		t.Errorf("original invoke operand %d resolves to %s->%s%s", got.Insns[4], class, name, ret)
	}
	// The two index operands are the only fields allowed to differ from the
	// source: the payload call (inserted) and Object.<init> (remapped).
	if got.Insns[6] != 0x000e {
		t.Errorf("tail of the body changed: %#v", got.Insns[6:])
	}
}

// TestCodePatchSkipsDescriptorsNotInDex: a foreign descriptor is not an error
// (the injector runs this per dex), and a class with no usable body is skipped
// without appearing in the result.
func TestCodePatchSkipsDescriptorsNotInDex(t *testing.T) {
	raw := codePatchFixture(t)

	out, patched, err := InsertPayloadCall(raw, []string{"Lnot/in/This/Dex;"}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	if err != nil {
		t.Fatalf("InsertPayloadCall on a foreign descriptor: %v", err)
	}
	if len(patched) != 0 {
		t.Fatalf("patched = %v, want none", patched)
	}
	if !bytes.Equal(out, raw) {
		t.Fatal("a dex with nothing to patch must come back unchanged")
	}

	// Empty inputs are a caller bug, not a "nothing to do here".
	if _, _, err := InsertPayloadCall(raw, []string{cpHostDesc}, nil, "", cpPayloadRun); err == nil {
		t.Error("expected an error for an empty payload class")
	}
	if _, _, err := InsertPayloadCall(raw, []string{cpHostDesc}, nil, cpPayloadDesc, ""); err == nil {
		t.Error("expected an error for an empty payload method")
	}
}

// TestCodePatchReusesExistingIds: when the dex already carries the string, type,
// proto and method id, an extra patch must not grow any table.
func TestCodePatchReusesExistingIds(t *testing.T) {
	x := newFixture()
	// Seed the ids the payload call needs before the Host class body is added.
	x.t(cpPayloadDesc)
	x.m(cpPayloadDesc, x.p("V"), cpPayloadRun)
	raw := encodeFixture(t, x)

	before := mustParse(t, raw)
	out, patched, err := InsertPayloadCall(raw, []string{cpHostDesc}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	if err != nil {
		t.Fatalf("InsertPayloadCall: %v", err)
	}
	if len(patched) != 1 {
		t.Fatalf("patched = %v, want one entry", patched)
	}
	after := mustParse(t, out)

	for _, tc := range []struct {
		name      string
		got, want int
	}{
		{"strings", len(after.Strings), len(before.Strings)},
		{"types", len(after.Types), len(before.Types)},
		{"protos", len(after.Protos), len(before.Protos)},
		{"methods", len(after.Methods), len(before.Methods)},
	} {
		if tc.got != tc.want {
			t.Errorf("%s table grew: %d -> %d (the ids existed, they must be reused)", tc.name, tc.want, tc.got)
		}
	}
	if n := payloadMethodIds(after, cpPayloadDesc, cpPayloadRun); n != 1 {
		t.Errorf("the payload method id appears %d times, want 1", n)
	}
	clinit := codeOf(t, after, cpHostDesc, "<clinit>")
	class, name, ret, nparams := resolveMethod(t, after, uint32(clinit.Insns[1]))
	if class != cpPayloadDesc || name != cpPayloadRun || ret != "V" || nparams != 0 {
		t.Errorf("operand resolves to %s->%s(%d)%s", class, name, nparams, ret)
	}
}

// TestCodePatchFallsBackToInit: a missing <clinit>, a code-less <clinit>, a
// class without class_data and a class with only virtual methods are all
// skipped or fall back to <init>. The code-less <clinit> is synthetic (an
// abstract method the model accepts) and exists only to reach that branch.
func TestCodePatchFallsBackToInit(t *testing.T) {
	const (
		noClinitDesc    = "Ltest/NoClinit;"
		codeLessDesc    = "Ltest/CodeLess;"
		markerDesc      = "Ltest/Marker;"
		virtualOnlyDesc = "Ltest/VirtualOnly;"
	)

	x := newFixture()
	objInit := x.m(cpObjectDesc, x.p("V"), "<init>")
	initNoClinit := x.m(noClinitDesc, x.p("V"), "<init>")
	clinitCodeLess := x.m(codeLessDesc, x.p("V"), "<clinit>")
	initCodeLess := x.m(codeLessDesc, x.p("V"), "<init>")
	virtualOnly := x.m(virtualOnlyDesc, x.p("V"), "go")

	initBody := func() *CodeItem {
		return &CodeItem{Registers: 1, Ins: 1, Insns: []uint16{0x1070, 0x0000, uint16(objInit), 0x000e}}
	}

	// The extra classes go in before the encoder runs; encodeFixture adds Host.
	x.addClass(noClinitDesc, 0x0001, cpObjectDesc,
		[]EncMethod{{Method: initNoClinit, Access: 0x0001, Code: initBody()}}, nil)
	x.addClass(codeLessDesc, 0x0001, cpObjectDesc,
		[]EncMethod{
			{Method: clinitCodeLess, Access: 0x0409, Code: nil},
			{Method: initCodeLess, Access: 0x0001, Code: initBody()},
		}, nil)
	x.f.Classes = append(x.f.Classes, ClassDef{
		ClassIdx: x.t(markerDesc), AccessFlags: 0x0001, Superclass: x.t(cpObjectDesc), SourceFile: NoIndex,
	})
	x.addClass(virtualOnlyDesc, 0x0001, cpObjectDesc, nil,
		[]EncMethod{{Method: virtualOnly, Access: 0x0001, Code: &CodeItem{Registers: 1, Ins: 1, Insns: []uint16{0x000e}}}})
	raw := encodeFixture(t, x)

	out, patched, err := InsertPayloadCall(raw,
		[]string{noClinitDesc, codeLessDesc, markerDesc, virtualOnlyDesc, "Ltest/Absent;"},
		entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	if err != nil {
		t.Fatalf("InsertPayloadCall: %v", err)
	}
	want := []string{
		noClinitDesc + "-><init>",
		codeLessDesc + "-><init>",
	}
	if !reflect.DeepEqual(patched, want) {
		t.Fatalf("patched = %v, want %v", patched, want)
	}

	after := mustParse(t, out)
	for _, tc := range []struct{ desc, name string }{
		{noClinitDesc, "<init>"},
		{codeLessDesc, "<init>"},
	} {
		code := codeOf(t, after, tc.desc, tc.name)
		if len(code.Insns) < 3 || code.Insns[0] != 0x0071 {
			t.Fatalf("%s->%s does not start with the payload call: %#v", tc.desc, tc.name, code.Insns)
		}
		class, name, _, _ := resolveMethod(t, after, uint32(code.Insns[1]))
		if class != cpPayloadDesc || name != cpPayloadRun {
			t.Fatalf("%s->%s call targets %s->%s", tc.desc, tc.name, class, name)
		}
	}
	// The code-less <clinit> did not grow a body.
	cd := classDef(t, after, codeLessDesc)
	for _, m := range cd.ClassData.DirectMethods {
		n, _ := after.methodName(m.Method)
		if n == "<clinit>" && m.Code != nil {
			t.Errorf("the code-less <clinit> grew a body")
		}
	}
}

// TestCodePatchMultipleClassesNoDoublePatch: repeated descriptors are deduped,
// each class is patched exactly once, and two different classes are patched in
// one pass.
func TestCodePatchMultipleClassesNoDoublePatch(t *testing.T) {
	const otherDesc = "Ltest/Other;"
	x := newFixture()
	otherInit := x.m(otherDesc, x.p("V"), "<init>")
	x.addClass(otherDesc, 0x0001, cpObjectDesc,
		[]EncMethod{{Method: otherInit, Access: 0x0001, Code: &CodeItem{Registers: 1, Ins: 1, Insns: []uint16{0x000e}}}}, nil)
	raw := encodeFixture(t, x)

	out, patched, err := InsertPayloadCall(raw,
		[]string{cpHostDesc, otherDesc, cpHostDesc}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	if err != nil {
		t.Fatalf("InsertPayloadCall: %v", err)
	}
	want := []string{cpHostDesc + "-><clinit>", otherDesc + "-><init>"}
	if !reflect.DeepEqual(patched, want) {
		t.Fatalf("patched = %v, want %v", patched, want)
	}
	after := mustParse(t, out)
	// 4 units before, 3 inserted once, not twice.
	if got := len(codeOf(t, after, cpHostDesc, "<clinit>").Insns); got != 4+3 {
		t.Fatalf("clinit insns = %d, want 7 (patched once)", got)
	}
	if got := len(codeOf(t, after, otherDesc, "<init>").Insns); got != 1+3 {
		t.Fatalf("Other.<init> insns = %d, want 4", got)
	}
	if n := payloadMethodIds(after, cpPayloadDesc, cpPayloadRun); n != 1 {
		t.Fatalf("the payload method id appears %d times, want 1", n)
	}
}

// TestCodePatchRejectsMalformedInput: broken input is an error, never a panic.
func TestCodePatchRejectsMalformedInput(t *testing.T) {
	raw := codePatchFixture(t)
	inputs := map[string][]byte{
		"nil":              nil,
		"empty":            {},
		"text":             []byte("this is definitely not a dex file"),
		"header only":      raw[:0x70],
		"truncated half":   raw[:len(raw)/2],
		"truncated tail":   raw[:len(raw)-8],
		"zeroed file_size": func() []byte { b := append([]byte(nil), raw...); copy(b[0x20:0x24], []byte{0, 0, 0, 0}); return b }(),
		"bad magic":        func() []byte { b := append([]byte(nil), raw...); copy(b[0:4], []byte("dexX")); return b }(),
		"huge class count": func() []byte {
			b := append([]byte(nil), raw...)
			for i := 0x60; i < 0x64; i++ {
				b[i] = 0xff
			}
			return b
		}(),
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			out, patched, err := InsertPayloadCall(in, []string{cpHostDesc}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
			if err == nil {
				t.Fatalf("expected an error for %s input", name)
			}
			if out != nil || patched != nil {
				t.Fatalf("a failed patch returned data (%d bytes) or result %v", len(out), patched)
			}
		})
	}

	// Every prefix of the file, and a few flipped bytes: no panic anywhere.
	for n := 0; n <= len(raw); n += 37 {
		InsertPayloadCall(raw[:n], []string{cpHostDesc}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	}
	for off := 0; off < len(raw); off += 61 {
		b := append([]byte(nil), raw...)
		b[off] ^= 0xff
		InsertPayloadCall(b, []string{cpHostDesc}, entryMethodPriority, cpPayloadDesc, cpPayloadRun)
	}
}

// TestCodePatchRealDexPassesDexdump patches real classes.dex files out of the
// corpus (read-only: everything happens on the in-memory copy) and has the
// Android SDK tooling accept the result. That is the check the synthetic
// fixtures cannot give: annotation sections, debug tables and real instruction
// streams only exist in a real host dex.
//
// The target class is taken from the APK's own manifest -- the application
// class and then the declared services, resolved to descriptors -- because those
// are exactly the classes vectors 9 and 11 splice into; the dex is only used as
// the source of bytes. If the manifest names no class present in the dex, the
// test falls back to the first class with a patchable <clinit>/<init>.
func TestCodePatchRealDexPassesDexdump(t *testing.T) {
	buildTools := filepath.Join(os.Getenv("HOME"), "Library/Android/sdk/build-tools/35.0.0")
	dexdump := filepath.Join(buildTools, "dexdump")
	if _, err := os.Stat(dexdump); err != nil {
		t.Skipf("dexdump not available at %s", dexdump)
	}
	aapt2 := filepath.Join(buildTools, "aapt2")
	if _, err := os.Stat(aapt2); err != nil {
		aapt2 = ""
	}
	apks, _ := filepath.Glob("/tmp/corpus/apk/*.apk")
	if len(apks) == 0 {
		t.Skip("no corpus APKs in /tmp/corpus/apk")
	}
	sort.Strings(apks)

	type candidate struct {
		apk, entry, desc, source string
		data                     []byte
	}
	var candidates []*candidate // manifest-declared targets first
	parsed, rejected := 0, 0

	for _, apk := range apks {
		manifests := manifestTargets(aapt2, apk)
		zr, err := zip.OpenReader(apk)
		if err != nil {
			continue
		}
		for _, e := range zr.File {
			if !strings.HasSuffix(e.Name, ".dex") {
				continue
			}
			// dexdump -d on multi-megabyte dexes buys nothing here.
			if e.UncompressedSize64 > 2<<20 {
				continue
			}
			rc, err := e.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}
			f, err := Parse(data)
			if err != nil {
				rejected++
				continue
			}
			parsed++
			desc, source := pickTargetInDex(f, manifests)
			if desc == "" {
				continue
			}
			candidates = append(candidates, &candidate{
				apk: filepath.Base(apk), entry: e.Name, desc: desc, source: source, data: data,
			})
		}
		zr.Close()
		if len(candidates) >= 4 && candidates[0].source == "manifest" {
			break
		}
	}
	if len(candidates) == 0 {
		t.Skipf("no patchable corpus dex found (parsed=%d rejected=%d)", parsed, rejected)
	}
	// Smallest dex first, manifest-declared targets first: fast and faithful.
	sort.SliceStable(candidates, func(i, j int) bool {
		mi, mj := candidates[i].source == "manifest", candidates[j].source == "manifest"
		if mi != mj {
			return mi
		}
		return len(candidates[i].data) < len(candidates[j].data)
	})
	if len(candidates) > 3 {
		candidates = candidates[:3]
	}

	for _, c := range candidates {
		// The corpus APKs are read-only material; only the in-memory copy is
		// rewritten and written out to a temp dir.
		out, patched, err := InsertPayloadCall(c.data, []string{c.desc}, entryMethodPriority, cpRealPayloadClass, cpRealPayloadMethod)
		if err != nil {
			t.Errorf("%s/%s (%s, from %s): InsertPayloadCall: %v", c.apk, c.entry, c.desc, c.source, err)
			continue
		}
		if len(patched) != 1 {
			t.Errorf("%s/%s: patched = %v, want one entry", c.apk, c.entry, patched)
			continue
		}
		dir := t.TempDir()
		patchedPath := filepath.Join(dir, "patched.dex")
		if err := os.WriteFile(patchedPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := Validate(patchedPath); err != nil {
			t.Errorf("%s/%s: our own Validate rejected the patched dex: %v", c.apk, c.entry, err)
		}

		// -f: the full structural dump. It must come out clean and report the
		// class and the method that was modified.
		full, err := runTool(dexdump, "-f", patchedPath)
		if err != nil {
			t.Errorf("dexdump -f rejected %s/%s patched at %s: %v\n%s", c.apk, c.entry, c.desc, err, full)
			continue
		}
		if !strings.Contains(full, c.desc) {
			t.Errorf("dexdump -f output does not mention the patched class %s", c.desc)
		}
		method := strings.TrimPrefix(patched[0], c.desc+"->")
		if !strings.Contains(full, method) {
			t.Errorf("dexdump -f output does not mention the patched method %s", method)
		}

		// -d: the disassembly, which names the invoke target. This is the
		// assertion that the spliced call is really there and really points at
		// the payload class.
		dis, err := runTool(dexdump, "-d", patchedPath)
		if err != nil {
			t.Errorf("dexdump -d rejected %s/%s patched at %s: %v\n%s", c.apk, c.entry, c.desc, err, dis)
			continue
		}
		wantCall := "invoke-static {}, " + cpRealPayloadClass + "." + cpRealPayloadMethod + ":()V"
		if !strings.Contains(dis, wantCall) {
			t.Errorf("dexdump -d output does not contain %q", wantCall)
		}
		t.Logf("dexdump accepted %s/%s, %s (%s) patched at %s, payload call present",
			c.apk, c.entry, c.desc, c.source, patched[0])
	}
}

// runTool runs an SDK tool and returns its combined output.
func runTool(path string, args ...string) (string, error) {
	cmd := exec.Command(path, args...)
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err
}

// manifestTargets reads the APK's binary manifest with aapt2 and returns the
// descriptors of its application class and declared services, application
// first. An unavailable aapt2 or an unreadable manifest yields nil.
func manifestTargets(aapt2, apk string) []string {
	if aapt2 == "" {
		return nil
	}
	out, err := exec.Command(aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk).Output()
	if err != nil {
		return nil
	}
	var (
		pkg      string
		app      string
		services []string
		tag      string
	)
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "E: "):
			tag = strings.TrimSpace(strings.TrimPrefix(line, "E: "))
			if i := strings.IndexByte(tag, ' '); i > 0 {
				tag = tag[:i]
			}
		case strings.HasPrefix(line, "A: "):
			name, val, ok := xmltreeAttr(line)
			if !ok {
				continue
			}
			switch {
			case tag == "manifest" && name == "package":
				pkg = val
			case tag == "application" && name == "name":
				app = val
			case tag == "service" && name == "name":
				services = append(services, val)
			}
		}
	}
	qualify := func(n string) string {
		switch {
		case n == "":
			return ""
		case strings.HasPrefix(n, "."):
			return pkg + n
		case !strings.Contains(n, "."):
			return pkg + "." + n
		}
		return n
	}
	var out2 []string
	if d := classDescriptor(qualify(app)); d != "" {
		out2 = append(out2, d)
	}
	for _, s := range services {
		if d := classDescriptor(qualify(s)); d != "" {
			out2 = append(out2, d)
		}
	}
	return out2
}

// xmltreeAttr splits aapt2's `A: <ns>:<name>(0x…)?=<value>` attribute line.
func xmltreeAttr(line string) (name, value string, ok bool) {
	rest := strings.TrimPrefix(line, "A: ")
	eq := strings.IndexByte(rest, '=')
	if eq < 0 {
		return "", "", false
	}
	key := rest[:eq]
	if i := strings.LastIndexByte(key, ':'); i >= 0 {
		key = key[i+1:]
	}
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}
	v := rest[eq+1:]
	open := strings.IndexByte(v, '"')
	if open < 0 {
		return key, strings.TrimSpace(v), true
	}
	close := strings.IndexByte(v[open+1:], '"')
	if close < 0 {
		return key, v[open+1:], true
	}
	return key, v[open+1 : open+1+close], true
}

func classDescriptor(className string) string {
	if className == "" || className[0] == '[' {
		return ""
	}
	return "L" + strings.ReplaceAll(className, ".", "/") + ";"
}

// pickTargetInDex returns the descriptor of a class in f that InsertPayloadCall
// can patch: the first manifest-declared class that has a usable body, else the
// first class with one (application-like classes preferred).
func pickTargetInDex(f *DexFile, manifest []string) (desc, source string) {
	patchable := map[string]bool{}
	for i := range f.Classes {
		cd := &f.Classes[i]
		if cd.ClassData == nil {
			continue
		}
		em, _, err := entryMethod(f, cd, entryMethodPriority)
		if err != nil || em == nil {
			continue
		}
		d, err := f.typeDescriptor(cd.ClassIdx)
		if err != nil {
			continue
		}
		patchable[d] = true
	}
	for _, d := range manifest {
		if patchable[d] {
			return d, "manifest"
		}
	}
	var app, svc, any string
	for i := range f.Classes {
		cd := &f.Classes[i]
		d, err := f.typeDescriptor(cd.ClassIdx)
		if err != nil || !patchable[d] {
			continue
		}
		super := ""
		if cd.Superclass != NoIndex {
			super, _ = f.typeDescriptor(cd.Superclass)
		}
		switch super {
		case "Landroid/app/Application;":
			if app == "" {
				app = d
			}
		case "Landroid/app/Service;", "Landroid/app/IntentService;":
			if svc == "" {
				svc = d
			}
		}
		if any == "" {
			any = d
		}
	}
	switch {
	case app != "":
		return app, "application subclass"
	case svc != "":
		return svc, "service subclass"
	}
	if any != "" {
		return any, "first patchable class"
	}
	return "", ""
}
