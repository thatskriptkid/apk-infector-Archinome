package dex

import "fmt"

// Access flags that mean "this method has no code_item to splice into".
const (
	accessNative   = 0x0100
	accessAbstract = 0x0400
)

// The spliced instruction is `invoke-static {}, L<payload>;-><method>()V`,
// format 35c (3 code units).
//
//   - unit0 = opcode in the low byte, A(15:12) = argument count = 0 and
//     G(11:8) = 0, i.e. 0x0071.
//   - unit1 = C|D|E|F = 0, the (unused) argument registers.
//   - unit2 = method_ids index of the payload method.
const (
	invokeStaticUnit0 = uint16(0x0071) // 35c invoke-static, A=0: no arguments
	invokeStaticRegs  = uint16(0x0000) // F|E|D|C register word of that invoke
	invokeStaticSize  = 3
)

// InsertPayloadCall splices `invoke-static {}, L<payloadClass>;-><payloadMethod>()V`
// into an existing method body of a class the host already runs, so the payload
// executes without any manifest change (vectors 9 and 11).
//
// The host dex is decoded into the model (Parse), the payload's method_id is
// added to it, the call is prepended to the body of the entry method of each
// requested class and the file is re-emitted with Encode. Going through the full
// model is what makes this safe: the encoder rebuilds every identifier table
// (deduplicated and sorted), recomputes every offset from a freshly laid out
// file and rewrites map_list, the SHA-1 signature and the adler32 checksum.
// Hand-editing a fixed-offset file could not add a method_id without moving
// every later item.
//
// The call is *prepended*, not appended: constructors and static initialisers
// routinely contain an early return-void, which would make an appended call
// unreachable. Prepending shifts every code-unit address in that one body by 3,
// so the method's try_items and catch handlers are shifted with it.
//
// classDescriptors are dex form descriptors (Lcom/foo/Bar;). A descriptor that
// is not present in this dex is skipped silently: the injector calls this for
// every classesN.dex of the APK and only the one carrying the class has work to
// do. Classes without class_data, or with no method from methodNames having a
// code_item, are skipped as well and are not listed in the result.
//
// The returned slice names what was patched, e.g. ["Lcom/foo/Bar;-><clinit>"].
// An error is returned only for structural failure (unparseable input, missing
// code, or an added id the encoder cannot represent).
func InsertPayloadCall(data []byte, classDescriptors []string, methodNames []string, payloadClass, payloadMethod string) ([]byte, []string, error) {
	if payloadClass == "" || payloadMethod == "" {
		return nil, nil, fmt.Errorf("dex: code patch needs both a payload class and a payload method name")
	}
	if len(methodNames) == 0 {
		methodNames = []string{"<clinit>", "<init>"}
	}

	f, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}

	// class_def class index -> descriptor, for the classes of *this* dex that
	// actually carry a body. class_defs are unique per class index, so a
	// descriptor matches at most one of them.
	patchable := map[string]*ClassDef{}
	for i := range f.Classes {
		cd := &f.Classes[i]
		if cd.ClassData == nil {
			continue
		}
		desc, err := f.typeDescriptor(cd.ClassIdx)
		if err != nil {
			return nil, nil, err
		}
		patchable[desc] = cd
	}

	var (
		patched []string
		bodies  []*CodeItem
		seen    = map[string]bool{}
	)
	for _, desc := range classDescriptors {
		if seen[desc] {
			continue
		}
		seen[desc] = true
		cd, ok := patchable[desc]
		if !ok {
			continue
		}
		em, name, err := entryMethod(f, cd, methodNames)
		if err != nil {
			return nil, nil, err
		}
		if em == nil {
			continue
		}
		bodies = append(bodies, em.Code)
		patched = append(patched, desc+"->"+name)
	}
	if len(patched) == 0 {
		// Nothing this dex can take. Returning the input untouched keeps the
		// injector's "not in this dex" case free of a pointless re-encode.
		return data, nil, nil
	}

	// The call needs a method_id pointing at the payload class, and that id has
	// to be added to the host's tables. Reuse every id that is already there so
	// an untouched behaviour stays untouched (a second run over an
	// already-patched dex must not grow the tables again).
	payloadStr, err := f.internString(payloadClass)
	if err != nil {
		return nil, nil, err
	}
	payloadType, err := f.internType(payloadStr)
	if err != nil {
		return nil, nil, err
	}
	// ()V: the shorty of an empty->void prototype is the string "V", and its
	// return type is the void type (descriptor "V").
	voidStr, err := f.internString("V")
	if err != nil {
		return nil, nil, err
	}
	voidType, err := f.internType(voidStr)
	if err != nil {
		return nil, nil, err
	}
	proto, err := f.internProto(voidStr, voidType)
	if err != nil {
		return nil, nil, err
	}
	methodNameStr, err := f.internString(payloadMethod)
	if err != nil {
		return nil, nil, err
	}
	methodIdx, err := f.internMethod(payloadType, proto, methodNameStr)
	if err != nil {
		return nil, nil, err
	}

	// Do not rely on the encoder's dedup: resolve the id we just interned
	// through the exact maps Encode will build, and refuse to emit a call that
	// does not land on the intended class/method/proto.
	if err := f.checkMethodId(methodIdx, payloadClass, voidType, payloadMethod); err != nil {
		return nil, nil, err
	}
	if methodIdx > 0xffff {
		return nil, nil, fmt.Errorf("dex: payload method index %d does not fit in a 35c operand", methodIdx)
	}

	for _, ci := range bodies {
		prependPayloadCall(ci, uint32(methodIdx))
	}

	out, err := f.Encode()
	if err != nil {
		return nil, nil, err
	}
	return out, patched, nil
}

// entryMethod returns the first method of methodNames that exists in the
// class's DirectMethods, has a code_item and is neither abstract nor native.
// A nil result means the class has no usable body (normal, not an error).
func entryMethod(f *DexFile, cd *ClassDef, methodNames []string) (*EncMethod, string, error) {
	for _, want := range methodNames {
		for i := range cd.ClassData.DirectMethods {
			em := &cd.ClassData.DirectMethods[i]
			if em.Code == nil || em.Access&(accessAbstract|accessNative) != 0 {
				continue
			}
			name, err := f.methodName(em.Method)
			if err != nil {
				return nil, "", err
			}
			if name == want {
				return em, want, nil
			}
		}
	}
	return nil, "", nil
}

// prependPayloadCall puts the three-unit invoke-static in front of the body.
//
// Registers, Ins and Outs are left alone: a zero-argument invoke reads no
// argument registers, starts no outgoing-argument frame (Outs stays as is, so
// the invoke reuses the frame the method already declared) and needs no new
// register. Debug info is left alone as well, which means the line table of
// this one method now maps addresses that are 3 code units off: a
// debug_info_item's address deltas are interleaved with the opcode stream and
// shifting them by a constant is only correct when no instruction was split or
// resized inside a delta run. That is debug-only data -- it changes no
// behaviour, only the line numbers a stack trace or a debugger reports -- so it
// is accepted here rather than silently claimed to be exact. Try ranges and
// catch handler addresses are *not* debug data and are shifted, otherwise an
// exception thrown in the original body would be caught outside its range.
func prependPayloadCall(ci *CodeItem, methodIdx uint32) {
	// 35c is [op|A|G] [BBBB index] [F|E|D|C registers]: the callee id goes in the
	// second code unit, the (empty) register list in the third.
	head := []uint16{invokeStaticUnit0, uint16(methodIdx), invokeStaticRegs}
	insns := make([]uint16, 0, len(ci.Insns)+invokeStaticSize)
	insns = append(insns, head...)
	insns = append(insns, ci.Insns...)
	ci.Insns = insns

	for i := range ci.Tries {
		ci.Tries[i].StartAddr += invokeStaticSize
	}
	for h := range ci.Handlers {
		for c := range ci.Handlers[h] {
			ci.Handlers[h][c].Addr += invokeStaticSize
		}
	}
}

// ------------------------------------------------------------------ id helpers
//
// Every helper below returns an existing *model* index when the entry is
// already present and appends to the model otherwise. Indices are the "old"
// (as-parsed) spaces the rest of the model uses; the encoder translates them.

func (d *DexFile) typeDescriptor(t uint32) (string, error) {
	if int(t) >= len(d.Types) {
		return "", fmt.Errorf("dex: type index %d out of range", t)
	}
	si := d.Types[t]
	if int(si) >= len(d.Strings) {
		return "", fmt.Errorf("dex: type[%d] descriptor index %d out of range", t, si)
	}
	return d.Strings[si], nil
}

func (d *DexFile) methodName(m uint32) (string, error) {
	if int(m) >= len(d.Methods) {
		return "", fmt.Errorf("dex: method index %d out of range", m)
	}
	si := d.Methods[m].Name
	if int(si) >= len(d.Strings) {
		return "", fmt.Errorf("dex: method[%d] name index %d out of range", m, si)
	}
	return d.Strings[si], nil
}

func (d *DexFile) internString(s string) (uint32, error) {
	if s == "" || !mutf8Valid(s) {
		return 0, fmt.Errorf("dex: cannot intern %q as a string", s)
	}
	for i, e := range d.Strings {
		if e == s {
			return uint32(i), nil
		}
	}
	d.Strings = append(d.Strings, s)
	return uint32(len(d.Strings) - 1), nil
}

func (d *DexFile) internType(strIdx uint32) (uint32, error) {
	if int(strIdx) >= len(d.Strings) {
		return 0, fmt.Errorf("dex: descriptor string index %d out of range", strIdx)
	}
	for i, t := range d.Types {
		if t == strIdx {
			return uint32(i), nil
		}
	}
	d.Types = append(d.Types, strIdx)
	return uint32(len(d.Types) - 1), nil
}

// internProto finds or adds the zero-parameter prototype with return type
// retType and shorty string shorty.
func (d *DexFile) internProto(shorty, retType uint32) (uint32, error) {
	if int(retType) >= len(d.Types) {
		return 0, fmt.Errorf("dex: proto return type index %d out of range", retType)
	}
	for i, p := range d.Protos {
		if p.Return == retType && len(p.Params) == 0 {
			return uint32(i), nil
		}
	}
	d.Protos = append(d.Protos, Proto{Shorty: shorty, Return: retType})
	return uint32(len(d.Protos) - 1), nil
}

func (d *DexFile) internMethod(class, proto, name uint32) (uint32, error) {
	if int(class) >= len(d.Types) {
		return 0, fmt.Errorf("dex: method class index %d out of range", class)
	}
	if int(proto) >= len(d.Protos) {
		return 0, fmt.Errorf("dex: method proto index %d out of range", proto)
	}
	if int(name) >= len(d.Strings) {
		return 0, fmt.Errorf("dex: method name index %d out of range", name)
	}
	for i, m := range d.Methods {
		if m.Class == class && m.Proto == proto && m.Name == name {
			return uint32(i), nil
		}
	}
	d.Methods = append(d.Methods, Method{Class: class, Proto: proto, Name: name})
	return uint32(len(d.Methods) - 1), nil
}

// checkMethodId builds the same index maps Encode builds and asserts that the
// interned method id resolves to exactly descriptor/method/()V, with a
// readable class name in the error. The encoder would happily dedup its way to
// some entry -- this makes the assumption explicit instead of implicit.
func (d *DexFile) checkMethodId(methodIdx uint32, wantClass string, wantVoidType uint32, wantName string) error {
	maps, err := d.buildMaps()
	if err != nil {
		return err
	}
	if int(methodIdx) >= len(maps.methMap) {
		return fmt.Errorf("dex: payload method index %d out of range", methodIdx)
	}
	newIdx := maps.methMap[methodIdx]
	if int(newIdx) >= len(maps.methods) {
		return fmt.Errorf("dex: payload method index %d resolves outside the emitted method table", methodIdx)
	}
	got := maps.methods[newIdx]

	class := ""
	if int(got.Class) < len(maps.types) {
		if si := maps.types[got.Class]; int(si) < len(maps.strings) {
			class = maps.strings[si]
		}
	}
	name := ""
	if int(got.Name) < len(maps.strings) {
		name = maps.strings[got.Name]
	}
	ret := ""
	params := -1
	if int(got.Proto) < len(maps.protos) {
		p := maps.protos[got.Proto]
		params = len(p.Params)
		if int(p.Return) < len(maps.types) {
			if si := maps.types[p.Return]; int(si) < len(maps.strings) {
				ret = maps.strings[si]
			}
		}
	}
	if class != wantClass || name != wantName || ret != "V" || params != 0 {
		return fmt.Errorf("dex: payload method id %d resolves to %s->%s(...)%s (%d params), want %s->%s()V",
			methodIdx, class, name, ret, params, wantClass, wantName)
	}
	return nil
}
