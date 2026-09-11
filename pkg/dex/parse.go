package dex

import (
	"encoding/binary"
	"fmt"
)

// Header field offsets (dex-format.md).
const (
	hdrFileSize      = 0x20
	hdrHeaderSize    = 0x24
	hdrEndianTag     = 0x28
	hdrLinkSize      = 0x2c
	hdrLinkOff       = 0x30
	hdrMapOff        = 0x34
	hdrStringIdsSize = 0x38
	hdrStringIdsOff  = 0x3c
	hdrTypeIdsSize   = 0x40
	hdrTypeIdsOff    = 0x44
	hdrProtoIdsSize  = 0x48
	hdrProtoIdsOff   = 0x4c
	hdrFieldIdsSize  = 0x50
	hdrFieldIdsOff   = 0x54
	hdrMethodIdsSize = 0x58
	hdrMethodIdsOff  = 0x5c
	hdrClassDefsSize = 0x60
	hdrClassDefsOff  = 0x64
	hdrDataSize      = 0x68
	hdrDataOff       = 0x6c
)

const endianTag = 0x12345678

func alignUp(n, align int) int {
	if align <= 1 {
		return n
	}
	if r := n % align; r != 0 {
		return n + align - r
	}
	return n
}

// ---------------------------------------------------------------- primitives

func rdU16(d []byte, off int) (uint16, error) {
	if off < 0 || off+2 > len(d) {
		return 0, fmt.Errorf("dex: u16 read out of bounds at 0x%x", off)
	}
	return binary.LittleEndian.Uint16(d[off:]), nil
}

func rdU32(d []byte, off int) (uint32, error) {
	if off < 0 || off+4 > len(d) {
		return 0, fmt.Errorf("dex: u32 read out of bounds at 0x%x", off)
	}
	return binary.LittleEndian.Uint32(d[off:]), nil
}

func rdU8(d []byte, off int) (byte, error) {
	if off < 0 || off >= len(d) {
		return 0, fmt.Errorf("dex: u8 read out of bounds at 0x%x", off)
	}
	return d[off], nil
}

func rdULEB(d []byte, off int) (uint32, int, error) {
	var out uint32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(d) {
			return 0, 0, fmt.Errorf("dex: truncated uleb128 at 0x%x", off)
		}
		b := d[off+i]
		out |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return out, off + i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("dex: uleb128 too long at 0x%x", off)
}

func rdSLEB(d []byte, off int) (int32, int, error) {
	var out int32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(d) {
			return 0, 0, fmt.Errorf("dex: truncated sleb128 at 0x%x", off)
		}
		b := d[off+i]
		out |= int32(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 32 && b&0x40 != 0 {
				out |= -1 << shift
			}
			return out, off + i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("dex: sleb128 too long at 0x%x", off)
}

func unsupported(what string) error {
	return fmt.Errorf("dex: unsupported %s (writer refuses rather than emit a broken file)", what)
}

// ------------------------------------------------------------------- parsing

type parser struct {
	d []byte
}

func (p *parser) u16(off int) uint16 {
	v, _ := rdU16(p.d, off)
	return v
}

func (p *parser) u32(off int) uint32 {
	v, _ := rdU32(p.d, off)
	return v
}

// Parse decodes a dex file into the writer's model.
func Parse(data []byte) (*DexFile, error) {
	if len(data) < 0x70 {
		return nil, fmt.Errorf("dex: file shorter than the 112-byte header (%d bytes)", len(data))
	}
	if string(data[0:4]) != "dex\n" || data[7] != 0x00 {
		return nil, fmt.Errorf("dex: bad magic %q", data[0:8])
	}
	version := string(data[4:7])
	p := &parser{d: data}
	if got := p.u32(hdrHeaderSize); got != 0x70 {
		return nil, fmt.Errorf("dex: unexpected header_size %d", got)
	}
	if got := p.u32(hdrEndianTag); got != endianTag {
		return nil, fmt.Errorf("dex: unexpected endian_tag 0x%x", got)
	}
	if got := p.u32(hdrFileSize); int(got) != len(data) {
		return nil, fmt.Errorf("dex: file_size %d != actual %d", got, len(data))
	}
	if p.u32(hdrLinkSize) != 0 {
		return nil, unsupported("link section")
	}
	f := &DexFile{Version: version}

	strSize, strOff := p.u32(hdrStringIdsSize), p.u32(hdrStringIdsOff)
	typeSize, typeOff := p.u32(hdrTypeIdsSize), p.u32(hdrTypeIdsOff)
	protoSize, protoOff := p.u32(hdrProtoIdsSize), p.u32(hdrProtoIdsOff)
	fieldSize, fieldOff := p.u32(hdrFieldIdsSize), p.u32(hdrFieldIdsOff)
	methSize, methOff := p.u32(hdrMethodIdsSize), p.u32(hdrMethodIdsOff)
	clsSize, clsOff := p.u32(hdrClassDefsSize), p.u32(hdrClassDefsOff)

	if err := checkSectionBounds("string_ids", strOff, strSize, 4, len(data)); err != nil {
		return nil, err
	}
	if err := checkSectionBounds("type_ids", typeOff, typeSize, 4, len(data)); err != nil {
		return nil, err
	}
	if err := checkSectionBounds("proto_ids", protoOff, protoSize, 12, len(data)); err != nil {
		return nil, err
	}
	if err := checkSectionBounds("field_ids", fieldOff, fieldSize, 8, len(data)); err != nil {
		return nil, err
	}
	if err := checkSectionBounds("method_ids", methOff, methSize, 8, len(data)); err != nil {
		return nil, err
	}
	if err := checkSectionBounds("class_defs", clsOff, clsSize, 32, len(data)); err != nil {
		return nil, err
	}
	if p.u32(hdrDataOff)+p.u32(hdrDataSize) != p.u32(hdrFileSize) {
		return nil, fmt.Errorf("dex: data_size/off does not add up to file_size")
	}

	// Reject sections the writer cannot reproduce faithfully.
	if err := p.checkMap(); err != nil {
		return nil, err
	}

	// --- strings
	f.Strings = make([]string, 0, strSize)
	for i := uint32(0); i < strSize; i++ {
		off := p.u32(int(strOff + 4*i))
		s, err := p.stringAt(off)
		if err != nil {
			return nil, fmt.Errorf("dex: string[%d]: %w", i, err)
		}
		f.Strings = append(f.Strings, s)
	}
	inRange := func(i uint32, n int) bool { return int(i) < n }

	// --- types
	f.Types = make([]uint32, 0, typeSize)
	for i := uint32(0); i < typeSize; i++ {
		si := p.u32(int(typeOff + 4*i))
		if !inRange(si, len(f.Strings)) {
			return nil, fmt.Errorf("dex: type[%d] descriptor index %d out of range", i, si)
		}
		f.Types = append(f.Types, si)
	}

	// --- protos
	for i := uint32(0); i < protoSize; i++ {
		base := int(protoOff + 12*i)
		pr := Proto{Shorty: p.u32(base), Return: p.u32(base + 4)}
		if !inRange(pr.Shorty, len(f.Strings)) {
			return nil, fmt.Errorf("dex: proto[%d] shorty index out of range", i)
		}
		if !inRange(pr.Return, len(f.Types)) {
			return nil, fmt.Errorf("dex: proto[%d] return type index out of range", i)
		}
		params, err := p.typeList(p.u32(base + 8))
		if err != nil {
			return nil, fmt.Errorf("dex: proto[%d] parameters: %w", i, err)
		}
		for _, t := range params {
			if !inRange(t, len(f.Types)) {
				return nil, fmt.Errorf("dex: proto[%d] parameter type index out of range", i)
			}
		}
		pr.Params = params
		f.Protos = append(f.Protos, pr)
	}

	// --- fields
	for i := uint32(0); i < fieldSize; i++ {
		base := int(fieldOff + 8*i)
		fd := Field{Class: uint32(p.u16(base)), Type: uint32(p.u16(base + 2)), Name: p.u32(base + 4)}
		if !inRange(fd.Class, len(f.Types)) || !inRange(fd.Type, len(f.Types)) || !inRange(fd.Name, len(f.Strings)) {
			return nil, fmt.Errorf("dex: field[%d] reference out of range", i)
		}
		f.Fields = append(f.Fields, fd)
	}

	// --- methods
	for i := uint32(0); i < methSize; i++ {
		base := int(methOff + 8*i)
		m := Method{Class: uint32(p.u16(base)), Proto: uint32(p.u16(base + 2)), Name: p.u32(base + 4)}
		if !inRange(m.Class, len(f.Types)) || !inRange(m.Proto, len(f.Protos)) || !inRange(m.Name, len(f.Strings)) {
			return nil, fmt.Errorf("dex: method[%d] reference out of range", i)
		}
		f.Methods = append(f.Methods, m)
	}

	// --- class defs
	for i := uint32(0); i < clsSize; i++ {
		base := int(clsOff + 32*i)
		cd := ClassDef{
			ClassIdx:    p.u32(base),
			AccessFlags: p.u32(base + 4),
			Superclass:  p.u32(base + 8),
			SourceFile:  p.u32(base + 16),
		}
		if !inRange(cd.ClassIdx, len(f.Types)) {
			return nil, fmt.Errorf("dex: class_def[%d] class index out of range", i)
		}
		if cd.Superclass != NoIndex && !inRange(cd.Superclass, len(f.Types)) {
			return nil, fmt.Errorf("dex: class_def[%d] superclass index out of range", i)
		}
		if cd.SourceFile != NoIndex && !inRange(cd.SourceFile, len(f.Strings)) {
			return nil, fmt.Errorf("dex: class_def[%d] source file index out of range", i)
		}
		ifaces, err := p.typeList(p.u32(base + 12))
		if err != nil {
			return nil, fmt.Errorf("dex: class_def[%d] interfaces: %w", i, err)
		}
		for _, t := range ifaces {
			if !inRange(t, len(f.Types)) {
				return nil, fmt.Errorf("dex: class_def[%d] interface index out of range", i)
			}
		}
		cd.Interfaces = ifaces

		if off := p.u32(base + 20); off != 0 {
			dir, err := p.annotationsDirectory(off)
			if err != nil {
				return nil, fmt.Errorf("dex: class_def[%d] annotations: %w", i, err)
			}
			cd.Annotations = dir
		}
		if off := p.u32(base + 24); off != 0 {
			dataCD, err := p.classData(off, len(f.Fields), len(f.Methods))
			if err != nil {
				return nil, fmt.Errorf("dex: class_def[%d] class_data: %w", i, err)
			}
			cd.ClassData = dataCD
		}
		if off := p.u32(base + 28); off != 0 {
			vals, err := p.encodedArray(off)
			if err != nil {
				return nil, fmt.Errorf("dex: class_def[%d] static values: %w", i, err)
			}
			cd.StaticValues = vals
		}
		f.Classes = append(f.Classes, cd)
	}
	return f, nil
}

func checkSectionBounds(name string, off, count uint32, itemSize, fileSize int) error {
	if count == 0 {
		if off != 0 && int(off) > fileSize {
			return fmt.Errorf("dex: %s offset 0x%x out of range", name, off)
		}
		return nil
	}
	need := uint64(off) + uint64(count)*uint64(itemSize)
	if need > uint64(fileSize) {
		return fmt.Errorf("dex: %s section [0x%x,+%d) exceeds file size %d", name, off, uint64(count)*uint64(itemSize), fileSize)
	}
	return nil
}

// checkMap walks the map_list and rejects section types the writer does not
// know how to rebuild (call sites, method handles, hiddenapi, ...).
func (p *parser) checkMap() error {
	off := p.u32(hdrMapOff)
	if off == 0 {
		return nil
	}
	size := p.u32(int(off))
	for i := uint32(0); i < size; i++ {
		base := int(off) + 4 + int(i)*12
		if base+12 > len(p.d) {
			return fmt.Errorf("dex: map_list truncated")
		}
		t := p.u16(base)
		switch t {
		case 0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006,
			0x1000, 0x1001, 0x1002, 0x1003,
			0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006:
			// supported
		default:
			return fmt.Errorf("dex: unsupported map section 0x%04x at 0x%x", t, p.u32(base+8))
		}
	}
	return nil
}

// stringAt reads a string_data_item: utf16_size uleb, MUTF-8 bytes, NUL.
func (p *parser) stringAt(off uint32) (string, error) {
	_, pos, err := rdULEB(p.d, int(off))
	if err != nil {
		return "", err
	}
	end := pos
	for end < len(p.d) && p.d[end] != 0x00 {
		end++
	}
	if end >= len(p.d) {
		return "", fmt.Errorf("unterminated string_data_item at 0x%x", off)
	}
	return mutf8Decode(p.d[pos:end])
}

// typeList reads a type_list; a zero offset means "no list".
func (p *parser) typeList(off uint32) ([]uint32, error) {
	if off == 0 {
		return nil, nil
	}
	size := p.u32(int(off))
	out := make([]uint32, 0, size)
	for i := uint32(0); i < size; i++ {
		v, err := rdU32(p.d, int(off)+4+int(i)*4)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (p *parser) classData(off uint32, nFields, nMethods int) (*ClassData, error) {
	pos := int(off)
	readCount := func(what string) (uint32, error) {
		v, next, err := rdULEB(p.d, pos)
		if err != nil {
			return 0, err
		}
		pos = next
		return v, nil
	}
	nsf, err := readCount("static_fields_size")
	if err != nil {
		return nil, err
	}
	nif, err := readCount("instance_fields_size")
	if err != nil {
		return nil, err
	}
	ndm, err := readCount("direct_methods_size")
	if err != nil {
		return nil, err
	}
	nvm, err := readCount("virtual_methods_size")
	if err != nil {
		return nil, err
	}
	cd := &ClassData{}
	readFields := func(n uint32) ([]EncField, error) {
		out := make([]EncField, 0, n)
		var idx uint32
		for i := uint32(0); i < n; i++ {
			diff, next, err := rdULEB(p.d, pos)
			if err != nil {
				return nil, err
			}
			pos = next
			if i == 0 {
				idx = diff
			} else {
				idx += diff
			}
			access, next, err := rdULEB(p.d, pos)
			if err != nil {
				return nil, err
			}
			pos = next
			if int(idx) >= nFields {
				return nil, fmt.Errorf("field index %d out of range (field_ids=%d)", idx, nFields)
			}
			out = append(out, EncField{Field: idx, Access: access})
		}
		return out, nil
	}
	readMethods := func(n uint32) ([]EncMethod, error) {
		out := make([]EncMethod, 0, n)
		var idx uint32
		for i := uint32(0); i < n; i++ {
			diff, next, err := rdULEB(p.d, pos)
			if err != nil {
				return nil, err
			}
			pos = next
			if i == 0 {
				idx = diff
			} else {
				idx += diff
			}
			access, next, err := rdULEB(p.d, pos)
			if err != nil {
				return nil, err
			}
			pos = next
			codeOff, next, err := rdULEB(p.d, pos)
			if err != nil {
				return nil, err
			}
			pos = next
			if int(idx) >= nMethods {
				return nil, fmt.Errorf("method index %d out of range (method_ids=%d)", idx, nMethods)
			}
			em := EncMethod{Method: idx, Access: access}
			if codeOff != 0 {
				code, err := p.codeItem(codeOff)
				if err != nil {
					return nil, err
				}
				em.Code = code
			}
			out = append(out, em)
		}
		return out, nil
	}
	if cd.StaticFields, err = readFields(nsf); err != nil {
		return nil, err
	}
	if cd.InstanceFields, err = readFields(nif); err != nil {
		return nil, err
	}
	if cd.DirectMethods, err = readMethods(ndm); err != nil {
		return nil, err
	}
	if cd.VirtualMethods, err = readMethods(nvm); err != nil {
		return nil, err
	}
	return cd, nil
}

func (p *parser) codeItem(off uint32) (*CodeItem, error) {
	base := int(off)
	if base+16 > len(p.d) {
		return nil, fmt.Errorf("code_item at 0x%x truncated", off)
	}
	ci := &CodeItem{
		Registers: p.u16(base),
		Ins:       p.u16(base + 2),
		Outs:      p.u16(base + 4),
	}
	tries := p.u16(base + 6)
	debugOff := p.u32(base + 8)
	insnsSize := p.u32(base + 12)
	insnBytes := int(insnsSize) * 2
	if base+16+insnBytes > len(p.d) {
		return nil, fmt.Errorf("code_item at 0x%x: insns_size %d out of range", off, insnsSize)
	}
	if err := p.checkInsns(base+16, insnsSize); err != nil {
		return nil, fmt.Errorf("code_item at 0x%x: %w", off, err)
	}
	ci.Insns = make([]uint16, insnsSize)
	for i := uint32(0); i < insnsSize; i++ {
		ci.Insns[i] = p.u16(base + 16 + int(i)*2)
	}
	cursor := base + 16 + insnBytes
	if tries > 0 {
		cursor = alignUp(cursor, 4)
		if cursor+int(tries)*8 > len(p.d) {
			return nil, fmt.Errorf("code_item at 0x%x: try_item table out of range", off)
		}
		for i := 0; i < int(tries); i++ {
			b := cursor + i*8
			ci.Tries = append(ci.Tries, TryItem{
				StartAddr:  p.u32(b),
				InsnCount:  p.u16(b + 4),
				HandlerIdx: p.u16(b + 6),
			})
		}
		cursor += int(tries) * 8
		hlistOff := cursor
		size, next, err := rdULEB(p.d, hlistOff)
		if err != nil {
			return nil, err
		}
		byOffset := map[uint32]int{}
		for h := uint32(0); h < size; h++ {
			hOff := uint32(next - hlistOff)
			byOffset[hOff] = len(ci.Handlers)
			handler, after, err := p.catchHandler(next)
			if err != nil {
				return nil, err
			}
			ci.Handlers = append(ci.Handlers, handler)
			next = after
		}
		for i := range ci.Tries {
			idx, ok := byOffset[uint32(ci.Tries[i].HandlerIdx)]
			if !ok {
				return nil, fmt.Errorf("code_item at 0x%x: try_item handler_off %d does not point at a handler", off, ci.Tries[i].HandlerIdx)
			}
			ci.Tries[i].HandlerIdx = uint16(idx)
		}
	}
	if debugOff != 0 {
		dbg, err := p.debugInfo(debugOff)
		if err != nil {
			return nil, err
		}
		ci.Debug = dbg
	}
	return ci, nil
}

// checkInsns walks the instruction stream and rejects opcodes whose index
// operands the writer cannot remap (invoke-custom / const-method-handle).
func (p *parser) checkInsns(off int, size uint32) error {
	for i := uint32(0); i < size; {
		unit := p.u16(off + int(i)*2)
		f := insnTable[unit>>8]
		if f.kind == ikCallSite || f.kind == ikMethodHandle {
			return unsupported("invoke-custom/const-method-handle instruction")
		}
		if f.width <= 0 || i+uint32(f.width) > size {
			return fmt.Errorf("instruction at code unit %d overruns the instruction stream", i)
		}
		i += uint32(f.width)
	}
	return nil
}

// catchHandler reads an encoded_catch_handler (not including its list header).
func (p *parser) catchHandler(off int) ([]CatchHandler, int, error) {
	size, next, err := rdSLEB(p.d, off)
	if err != nil {
		return nil, 0, err
	}
	typed := 0
	hasCatchAll := false
	switch {
	case size == 0:
	case size > 0:
		typed = int(size) - 1
		hasCatchAll = true
	default:
		typed = int(-size)
	}
	out := make([]CatchHandler, 0, typed+1)
	for i := 0; i < typed; i++ {
		t, n, err := rdULEB(p.d, next)
		if err != nil {
			return nil, 0, err
		}
		a, n2, err := rdULEB(p.d, n)
		if err != nil {
			return nil, 0, err
		}
		next = n2
		out = append(out, CatchHandler{Type: t, Addr: a})
	}
	if hasCatchAll {
		a, n, err := rdULEB(p.d, next)
		if err != nil {
			return nil, 0, err
		}
		next = n
		out = append(out, CatchHandler{Type: NoIndex, Addr: a})
	}
	return out, next, nil
}

func (p *parser) debugInfo(off uint32) (*DebugInfo, error) {
	pos := int(off)
	lineStart, next, err := rdULEB(p.d, pos)
	if err != nil {
		return nil, err
	}
	pos = next
	paramCount, next, err := rdULEB(p.d, pos)
	if err != nil {
		return nil, err
	}
	pos = next
	dbg := &DebugInfo{LineStart: lineStart}
	for i := uint32(0); i < paramCount; i++ {
		v, n, err := rdULEB(p.d, pos)
		if err != nil {
			return nil, err
		}
		pos = n
		dbg.Params = append(dbg.Params, v)
	}
	for {
		op, next, err := rdULEB(p.d, pos)
		if err != nil {
			return nil, err
		}
		pos = next
		e := DbgOp{Op: op}
		read := func(k dbgKind) error {
			var (
				v   uint32
				n   int
				err error
			)
			if k == dbgSigned {
				sv, n2, err2 := rdSLEB(p.d, pos)
				v, n, err = uint32(sv), n2, err2
			} else {
				v, n, err = rdULEB(p.d, pos)
			}
			if err != nil {
				return err
			}
			pos = n
			e.Args = append(e.Args, v)
			e.Kind = append(e.Kind, k)
			return nil
		}
		switch op {
		case 0x00: // end_sequence
		case 0x01:
			err = read(dbgPlain)
		case 0x02:
			err = read(dbgSigned)
		case 0x03:
			err = read(dbgPlain)
			if err == nil {
				err = read(dbgString)
			}
			if err == nil {
				err = read(dbgType)
			}
		case 0x04:
			err = read(dbgPlain)
			if err == nil {
				err = read(dbgString)
			}
			if err == nil {
				err = read(dbgType)
			}
			if err == nil {
				err = read(dbgString)
			}
		case 0x05, 0x06:
			err = read(dbgPlain)
		case 0x07, 0x08: // prologue_end / epilogue_begin
		case 0x09:
			err = read(dbgString)
		default: // special opcodes carry no operands
		}
		if err != nil {
			return nil, err
		}
		dbg.Ops = append(dbg.Ops, e)
		if op == 0x00 {
			break
		}
	}
	return dbg, nil
}

// --------------------------------------------------------------- annotations

func (p *parser) annotationsDirectory(off uint32) (*AnnotationsDirectory, error) {
	base := int(off)
	if base+16 > len(p.d) {
		return nil, fmt.Errorf("annotations_directory at 0x%x truncated", off)
	}
	dir := &AnnotationsDirectory{}
	classOff := p.u32(base)
	nFields := int(p.u32(base + 4))
	nMethods := int(p.u32(base + 8))
	nParams := int(p.u32(base + 12))
	cursor := base + 16
	var err error
	if classOff != 0 {
		if dir.Class, err = p.annotationSet(classOff); err != nil {
			return nil, err
		}
	}
	readPairs := func(n int) ([][2]uint32, error) {
		out := make([][2]uint32, 0, n)
		for i := 0; i < n; i++ {
			if cursor+8 > len(p.d) {
				return nil, fmt.Errorf("annotations_directory at 0x%x truncated", off)
			}
			out = append(out, [2]uint32{p.u32(cursor), p.u32(cursor + 4)})
			cursor += 8
		}
		return out, nil
	}
	if pairs, err := readPairs(nFields); err != nil {
		return nil, err
	} else {
		for _, pr := range pairs {
			anns, err := p.annotationSet(pr[1])
			if err != nil {
				return nil, err
			}
			dir.Fields = append(dir.Fields, AnnotatedField{Field: pr[0], Anns: anns})
		}
	}
	if pairs, err := readPairs(nMethods); err != nil {
		return nil, err
	} else {
		for _, pr := range pairs {
			anns, err := p.annotationSet(pr[1])
			if err != nil {
				return nil, err
			}
			dir.Methods = append(dir.Methods, AnnotatedMethod{Method: pr[0], Anns: anns})
		}
	}
	if pairs, err := readPairs(nParams); err != nil {
		return nil, err
	} else {
		for _, pr := range pairs {
			lists, err := p.annotationSetRefList(pr[1])
			if err != nil {
				return nil, err
			}
			dir.Parameters = append(dir.Parameters, AnnotatedParameter{Method: pr[0], Anns: lists})
		}
	}
	return dir, nil
}

func (p *parser) annotationSet(off uint32) ([]AnnotationItem, error) {
	if off == 0 {
		return nil, nil
	}
	size := p.u32(int(off))
	out := make([]AnnotationItem, 0, size)
	for i := uint32(0); i < size; i++ {
		itemOff := p.u32(int(off) + 4 + int(i)*4)
		if itemOff == 0 {
			continue // spec allows a zero offset as "no annotation"
		}
		vis, err := rdU8(p.d, int(itemOff))
		if err != nil {
			return nil, err
		}
		ann, _, err := p.encodedAnnotation(int(itemOff) + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, AnnotationItem{Visibility: vis, Ann: ann})
	}
	return out, nil
}

func (p *parser) annotationSetRefList(off uint32) ([][]AnnotationItem, error) {
	if off == 0 {
		return nil, nil
	}
	size := p.u32(int(off))
	out := make([][]AnnotationItem, 0, size)
	for i := uint32(0); i < size; i++ {
		setOff := p.u32(int(off) + 4 + int(i)*4)
		anns, err := p.annotationSet(setOff)
		if err != nil {
			return nil, err
		}
		out = append(out, anns)
	}
	return out, nil
}

func (p *parser) encodedArray(off uint32) ([]EncodedValue, error) {
	size, pos, err := rdULEB(p.d, int(off))
	if err != nil {
		return nil, err
	}
	out := make([]EncodedValue, 0, size)
	for i := uint32(0); i < size; i++ {
		v, next, err := p.encodedValue(pos)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		pos = next
	}
	return out, nil
}

func (p *parser) encodedAnnotation(off int) (EncodedAnnotation, int, error) {
	typeIdx, pos, err := rdULEB(p.d, off)
	if err != nil {
		return EncodedAnnotation{}, 0, err
	}
	size, pos, err := rdULEB(p.d, pos)
	if err != nil {
		return EncodedAnnotation{}, 0, err
	}
	ann := EncodedAnnotation{Type: typeIdx, Elements: make([]AnnotationElement, 0, size)}
	for i := uint32(0); i < size; i++ {
		name, p2, err := rdULEB(p.d, pos)
		if err != nil {
			return EncodedAnnotation{}, 0, err
		}
		val, p3, err := p.encodedValue(p2)
		if err != nil {
			return EncodedAnnotation{}, 0, err
		}
		ann.Elements = append(ann.Elements, AnnotationElement{Name: name, Value: val})
		pos = p3
	}
	return ann, pos, nil
}

func (p *parser) encodedValue(off int) (EncodedValue, int, error) {
	tag, err := rdU8(p.d, off)
	if err != nil {
		return EncodedValue{}, 0, err
	}
	pos := off + 1
	valueType := tag & 0x1f
	arg := int(tag>>5) + 1
	ev := EncodedValue{Type: valueType}
	switch valueType {
	case 0x00: // byte
		b, err := rdU8(p.d, pos)
		if err != nil {
			return EncodedValue{}, 0, err
		}
		ev.Int = uint64(int64(int8(b)))
		pos++
	case 0x02, 0x03, 0x04, 0x06: // short, char, int, long
		raw, err := p.readBytes(pos, arg)
		if err != nil {
			return EncodedValue{}, 0, err
		}
		ev.Int = signedFrom(raw)
		pos += arg
	case 0x10, 0x11: // float, double: keep the raw bit pattern
		raw, err := p.readBytes(pos, arg)
		if err != nil {
			return EncodedValue{}, 0, err
		}
		ev.Int = raw
		pos += arg
	case 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b: // index-valued
		raw, err := p.readBytes(pos, arg)
		if err != nil {
			return EncodedValue{}, 0, err
		}
		ev.Int = raw
		pos += arg
	case 0x1c: // array
		size, npos, err := rdULEB(p.d, pos)
		if err != nil {
			return EncodedValue{}, 0, err
		}
		pos = npos
		ev.Arr = make([]EncodedValue, 0, size)
		for i := uint32(0); i < size; i++ {
			v, n, err := p.encodedValue(pos)
			if err != nil {
				return EncodedValue{}, 0, err
			}
			ev.Arr = append(ev.Arr, v)
			pos = n
		}
	case 0x1d: // annotation
		ann, n, err := p.encodedAnnotation(pos)
		if err != nil {
			return EncodedValue{}, 0, err
		}
		ev.Ann = &ann
		pos = n
	case 0x1e: // null
		ev.Int = 0
	case 0x1f: // boolean: value lives in value_arg
		ev.Int = uint64(tag >> 5)
	default:
		return EncodedValue{}, 0, fmt.Errorf("dex: unknown encoded_value type 0x%02x at 0x%x", valueType, off)
	}
	return ev, pos, nil
}

func (p *parser) readBytes(off, n int) (uint64, error) {
	if n < 1 || n > 8 || off < 0 || off+n > len(p.d) {
		return 0, fmt.Errorf("dex: encoded_value payload of %d bytes out of bounds at 0x%x", n, off)
	}
	var out uint64
	for i := 0; i < n; i++ {
		out |= uint64(p.d[off+i]) << (8 * i)
	}
	return out, nil
}

// signedFrom sign-extends the little-endian value stored in raw.
func signedFrom(raw uint64) uint64 {
	n := uint64(0)
	for _, shift := range []uint{8, 16, 24, 32, 40, 48, 56} {
		if raw < (uint64(1) << shift) {
			n = uint64(shift)
			break
		}
	}
	if n == 0 {
		return raw
	}
	if raw&(uint64(1)<<(n-1)) == 0 {
		return raw
	}
	return raw | ^((uint64(1) << n) - 1)
}
