package dex

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"sort"
)

// Map section item types (map_list entry type codes).
const (
	mapHeader               = 0x0000
	mapStringID             = 0x0001
	mapTypeID               = 0x0002
	mapProtoID              = 0x0003
	mapFieldID              = 0x0004
	mapMethodID             = 0x0005
	mapClassDef             = 0x0006
	mapMapList              = 0x1000
	mapTypeList             = 0x1001
	mapAnnotationSetRefList = 0x1002
	mapAnnotationSetItem    = 0x1003
	mapClassData            = 0x2000
	mapCode                 = 0x2001
	mapStringData           = 0x2002
	mapDebugInfo            = 0x2003
	mapAnnotation           = 0x2004
	mapEncodedArray         = 0x2005
	mapAnnotationsDirectory = 0x2006
)

// indexMaps translates old indices into the new, canonical index spaces.
type indexMaps struct {
	strings []string // new string pool, sorted by UTF-16 code unit order
	types   []uint32 // new type_ids values (string index)
	protos  []Proto
	fields  []Field
	methods []Method

	strMap   []uint32 // old string index -> new
	typMap   []uint32
	protoMap []uint32
	fieldMap []uint32
	methMap  []uint32

	// classOrder sorts class_defs by class_idx; classRank is its inverse.
	classOrder []int
	classRank  []uint32
}

func remap(table []uint32, old uint32, what string) (uint32, error) {
	if old == NoIndex {
		return NoIndex, nil
	}
	if int(old) >= len(table) {
		return 0, fmt.Errorf("dex: %s index %d out of range", what, old)
	}
	return table[old], nil
}

func (m *indexMaps) str(v uint32) (uint32, error)   { return remap(m.strMap, v, "string") }
func (m *indexMaps) typ(v uint32) (uint32, error)   { return remap(m.typMap, v, "type") }
func (m *indexMaps) proto(v uint32) (uint32, error) { return remap(m.protoMap, v, "proto") }
func (m *indexMaps) field(v uint32) (uint32, error) { return remap(m.fieldMap, v, "field") }
func (m *indexMaps) method(v uint32) (uint32, error) {
	return remap(m.methMap, v, "method")
}

// buildMaps canonicalises the index spaces: it drops duplicates (renaming a
// descriptor can make two previously distinct entries identical), sorts every
// table the way the format requires and returns the old->new permutations.
// This is what makes a moved string safe: every reference in the file is
// translated through these maps instead of being patched in place.
func (d *DexFile) buildMaps() (*indexMaps, error) {
	m := &indexMaps{}

	// --- strings: dedupe, then sort by UTF-16 code units.
	uniqIdx := map[string]int{}
	canon := make([]int, len(d.Strings))
	var uniq []string
	for i, s := range d.Strings {
		if !mutf8Valid(s) {
			return nil, fmt.Errorf("dex: string[%d] is not valid UTF-8 after MUTF-8 decoding", i)
		}
		ci, ok := uniqIdx[s]
		if !ok {
			ci = len(uniq)
			uniqIdx[s] = ci
			uniq = append(uniq, s)
		}
		canon[i] = ci
	}
	order := make([]int, len(uniq))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return utf16Less(uniq[order[a]], uniq[order[b]]) })
	rank := make([]int, len(uniq))
	m.strings = make([]string, len(uniq))
	for newIdx, ci := range order {
		rank[ci] = newIdx
		m.strings[newIdx] = uniq[ci]
	}
	m.strMap = make([]uint32, len(d.Strings))
	for i := range d.Strings {
		m.strMap[i] = uint32(rank[canon[i]])
	}

	// --- types: keyed by their (new) descriptor string index.
	typeKeys := make([]uint32, len(d.Types))
	for i, t := range d.Types {
		k, err := m.str(t)
		if err != nil {
			return nil, err
		}
		typeKeys[i] = k
	}
	typeOrder, typeRank, _ := dedupeSorted(len(d.Types), func(i int) []uint32 { return []uint32{typeKeys[i]} })
	m.typMap = typeRank
	m.types = make([]uint32, len(typeOrder))
	for newIdx, old := range typeOrder {
		m.types[newIdx] = typeKeys[old]
	}

	// --- protos: key = (return type, parameter type list).
	protoKeys := make([][]uint32, len(d.Protos))
	for i, p := range d.Protos {
		ret, err := m.typ(p.Return)
		if err != nil {
			return nil, err
		}
		key := []uint32{ret}
		for _, pt := range p.Params {
			np, err := m.typ(pt)
			if err != nil {
				return nil, err
			}
			key = append(key, np)
		}
		protoKeys[i] = key
	}
	protoOrder, protoRank, _ := dedupeSorted(len(d.Protos), func(i int) []uint32 { return protoKeys[i] })
	m.protoMap = protoRank
	m.protos = make([]Proto, len(protoOrder))
	for newIdx, old := range protoOrder {
		shorty, err := m.str(d.Protos[old].Shorty)
		if err != nil {
			return nil, err
		}
		var params []uint32
		if len(protoKeys[old]) > 1 {
			params = protoKeys[old][1:]
		}
		m.protos[newIdx] = Proto{Shorty: shorty, Return: protoKeys[old][0], Params: params}
	}

	// --- fields: key = (class, name, type).
	fieldKeys := make([][]uint32, len(d.Fields))
	for i, f := range d.Fields {
		c, err := m.typ(f.Class)
		if err != nil {
			return nil, err
		}
		t, err := m.typ(f.Type)
		if err != nil {
			return nil, err
		}
		n, err := m.str(f.Name)
		if err != nil {
			return nil, err
		}
		fieldKeys[i] = []uint32{c, n, t}
	}
	fieldOrder, fieldRank, _ := dedupeSorted(len(d.Fields), func(i int) []uint32 { return fieldKeys[i] })
	m.fieldMap = fieldRank
	m.fields = make([]Field, len(fieldOrder))
	for newIdx, old := range fieldOrder {
		m.fields[newIdx] = Field{Class: fieldKeys[old][0], Name: fieldKeys[old][1], Type: fieldKeys[old][2]}
	}

	// --- methods: key = (class, name, proto).
	methodKeys := make([][]uint32, len(d.Methods))
	for i, mm := range d.Methods {
		c, err := m.typ(mm.Class)
		if err != nil {
			return nil, err
		}
		n, err := m.str(mm.Name)
		if err != nil {
			return nil, err
		}
		pr, err := m.proto(mm.Proto)
		if err != nil {
			return nil, err
		}
		methodKeys[i] = []uint32{c, n, pr}
	}
	methodOrder, methodRank, _ := dedupeSorted(len(d.Methods), func(i int) []uint32 { return methodKeys[i] })
	m.methMap = methodRank
	m.methods = make([]Method, len(methodOrder))
	for newIdx, old := range methodOrder {
		m.methods[newIdx] = Method{Class: methodKeys[old][0], Name: methodKeys[old][1], Proto: methodKeys[old][2]}
	}

	// --- class_defs must be sorted by class_idx: ART binary searches them.
	classKeys := make([]uint32, len(d.Classes))
	for i, cd := range d.Classes {
		k, err := m.typ(cd.ClassIdx)
		if err != nil {
			return nil, err
		}
		classKeys[i] = k
	}
	m.classOrder = make([]int, len(d.Classes))
	for i := range m.classOrder {
		m.classOrder[i] = i
	}
	sort.SliceStable(m.classOrder, func(a, b int) bool {
		return classKeys[m.classOrder[a]] < classKeys[m.classOrder[b]]
	})
	for i := 1; i < len(m.classOrder); i++ {
		if classKeys[m.classOrder[i]] == classKeys[m.classOrder[i-1]] {
			return nil, fmt.Errorf("dex: two class_defs share class index %d", classKeys[m.classOrder[i]])
		}
	}
	m.classRank = make([]uint32, len(d.Classes))
	for newIdx, old := range m.classOrder {
		m.classRank[old] = uint32(newIdx)
	}
	return m, nil
}

// dedupeSorted stable-sorts [0,n) by the given key slices, merges entries with
// identical keys, and returns the surviving order plus the old->new ranks.
func dedupeSorted(n int, key func(int) []uint32) ([]int, []uint32, error) {
	if n == 0 {
		return nil, nil, nil
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ka, kb := key(order[a]), key(order[b])
		for i := 0; i < len(ka) && i < len(kb); i++ {
			if ka[i] != kb[i] {
				return ka[i] < kb[i]
			}
		}
		return len(ka) < len(kb)
	})
	out := make([]int, 0, n)
	rank := make([]uint32, n)
	for _, old := range order {
		if len(out) > 0 {
			if equalKeys(key(out[len(out)-1]), key(old)) {
				rank[old] = uint32(len(out) - 1)
				continue
			}
		}
		out = append(out, old)
		rank[old] = uint32(len(out) - 1)
	}
	return out, rank, nil
}

func equalKeys(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ layout

// tableLayout is the offset of every identifier table plus the start of the
// data section. Sections with a zero count get offset 0 and occupy no space.
type tableLayout struct {
	strOff, typOff, protoOff, fieldOff, methodOff, classOff int
	dataStart                                               int
}

func newTableLayout(nStr, nTyp, nProto, nField, nMethod, nClass int) tableLayout {
	var t tableLayout
	off := 0x70
	take := func(count, itemSize int) int {
		if count == 0 {
			return 0
		}
		start := off
		off += count * itemSize
		return start
	}
	t.strOff = take(nStr, 4)
	t.typOff = take(nTyp, 4)
	t.protoOff = take(nProto, 12)
	t.fieldOff = take(nField, 8)
	t.methodOff = take(nMethod, 8)
	t.classOff = take(nClass, 32)
	t.dataStart = alignUp(off, 4)
	return t
}

// ------------------------------------------------------------------ emitting

// dataEmitter appends data-section items to a buffer while tracking the map
// sections and the absolute offset of each item.
type dataEmitter struct {
	m  *indexMaps
	f  *DexFile
	lo tableLayout
	// base is the absolute offset of buf[0] (== lo.dataStart).
	base int
	buf  []byte

	sections  []mapSection
	sectionIx map[uint16]int
}

type mapSection struct {
	typ    uint16
	count  uint32
	offset int
}

func (e *dataEmitter) tell() int { return e.base + len(e.buf) }

func (e *dataEmitter) align(n int) {
	want := alignUp(e.tell(), n)
	for e.tell() < want {
		e.buf = append(e.buf, 0)
	}
}

func (e *dataEmitter) raw(p []byte) { e.buf = append(e.buf, p...) }
func (e *dataEmitter) u8(v byte)    { e.buf = append(e.buf, v) }
func (e *dataEmitter) u16(v uint16) { e.buf = binary.LittleEndian.AppendUint16(e.buf, v) }
func (e *dataEmitter) u32(v uint32) { e.buf = binary.LittleEndian.AppendUint32(e.buf, v) }

func (e *dataEmitter) uleb(v uint32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		e.buf = append(e.buf, b)
		if v == 0 {
			return
		}
	}
}

func (e *dataEmitter) sleb(v int32) {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			e.buf = append(e.buf, b)
			return
		}
		e.buf = append(e.buf, b|0x80)
	}
}

// touch records that an item of the given section starts at off.
func (e *dataEmitter) touch(typ uint16, off int) {
	if e.sectionIx == nil {
		e.sectionIx = map[uint16]int{}
	}
	if ix, ok := e.sectionIx[typ]; ok {
		e.sections[ix].count++
		return
	}
	e.sectionIx[typ] = len(e.sections)
	e.sections = append(e.sections, mapSection{typ: typ, count: 1, offset: off})
}

type annFieldEntry struct {
	field uint32 // old field index
	set   int
}

type annMethodEntry struct {
	method uint32 // old method index
	set    int
}

type annParamEntry struct {
	method uint32 // old method index
	ref    int
}

type encoder struct {
	d  *DexFile
	m  *indexMaps
	e  *dataEmitter
	lo tableLayout

	protoParamsOff []uint32
	ifaceOff       []uint32
	classDirOff    []uint32
	staticOff      []uint32
	debugOff       map[*DebugInfo]uint32
	codeOff        map[*CodeItem]uint32
	classDataOff   []uint32
	stringDataOff  []uint32
}

// Encode rebuilds a complete, structurally valid dex file from the model.
//
// Emitted layout: header, the six identifier tables, then the data section
// (type lists, annotations, encoded arrays, debug info, code, class data,
// string data) and finally the map list. Every offset -- in the tables and
// inside the data items -- is recomputed from that layout, and the header's
// file_size/data_size, the adler32 checksum and the SHA-1 signature are
// recomputed last, so the result is a dex ART will load.
func (d *DexFile) Encode() ([]byte, error) {
	m, err := d.buildMaps()
	if err != nil {
		return nil, err
	}
	lo := newTableLayout(len(m.strings), len(m.types), len(m.protos), len(m.fields), len(m.methods), len(d.Classes))
	e := &dataEmitter{m: m, f: d, lo: lo, base: lo.dataStart}
	x := &encoder{d: d, m: m, e: e, lo: lo}

	if x.protoParamsOff, x.ifaceOff, err = x.emitTypeLists(); err != nil {
		return nil, err
	}
	if x.classDirOff, err = x.emitAnnotations(); err != nil {
		return nil, err
	}
	if x.staticOff, err = x.emitStaticValues(); err != nil {
		return nil, err
	}
	if x.debugOff, err = x.emitDebugInfo(); err != nil {
		return nil, err
	}
	if x.codeOff, err = x.emitCode(); err != nil {
		return nil, err
	}
	if x.classDataOff, err = x.emitClassData(); err != nil {
		return nil, err
	}
	if x.stringDataOff, err = x.emitStringData(); err != nil {
		return nil, err
	}

	e.align(4)
	mapOff := e.tell()
	e.emitMapList(mapOff)
	total := e.tell()

	out := make([]byte, total)
	if err := x.writeHeaderAndTables(out, mapOff); err != nil {
		return nil, err
	}
	copy(out[lo.dataStart:], e.buf)

	// Order matters: the SHA-1 signature lives at 0x0c..0x1f, i.e. inside the
	// range the adler32 checksum covers (everything from 0x0c on). Writing the
	// signature after the checksum leaves a stale checksum in the header and
	// ART rejects the whole dex ("Bad checksum"), so the checksum must be
	// computed last, over the finished image.
	h := sha1.Sum(out[32:])
	copy(out[0x0c:0x20], h[:])
	sum := adler32.Checksum(out[12:])
	binary.LittleEndian.PutUint32(out[0x08:], sum)
	return out, nil
}

// emitMapList writes the map_list. Entries are sorted by offset, which the
// emission order already guarantees.
func (e *dataEmitter) emitMapList(mapOff int) {
	e.touch(mapMapList, mapOff)
	var entries []mapSection
	add := func(typ uint16, count uint32, offset int) {
		if count == 0 {
			return
		}
		entries = append(entries, mapSection{typ: typ, count: count, offset: offset})
	}
	add(mapHeader, 1, 0)
	add(mapStringID, uint32(len(e.m.strings)), e.lo.strOff)
	add(mapTypeID, uint32(len(e.m.types)), e.lo.typOff)
	add(mapProtoID, uint32(len(e.m.protos)), e.lo.protoOff)
	add(mapFieldID, uint32(len(e.m.fields)), e.lo.fieldOff)
	add(mapMethodID, uint32(len(e.m.methods)), e.lo.methodOff)
	add(mapClassDef, uint32(len(e.f.Classes)), e.lo.classOff)
	for _, s := range e.sections {
		if s.typ == mapMapList {
			continue
		}
		add(s.typ, s.count, s.offset)
	}
	add(mapMapList, 1, mapOff)
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].offset < entries[j].offset })

	e.u32(uint32(len(entries)))
	for _, s := range entries {
		e.u16(s.typ)
		e.u16(0)
		e.u32(s.count)
		e.u32(uint32(s.offset))
	}
}

// writeHeaderAndTables writes the header and the identifier tables.
func (x *encoder) writeHeaderAndTables(out []byte, mapOff int) error {
	// header
	copy(out[0:8], []byte("dex\n"+x.d.Version+"\x00"))
	// checksum (0x08) and signature (0x0c) are filled in by the caller.
	le := binary.LittleEndian
	le.PutUint32(out[hdrFileSize:], uint32(len(out)))
	le.PutUint32(out[hdrHeaderSize:], 0x70)
	le.PutUint32(out[hdrEndianTag:], endianTag)
	le.PutUint32(out[hdrLinkSize:], 0)
	le.PutUint32(out[hdrLinkOff:], 0)
	le.PutUint32(out[hdrMapOff:], uint32(mapOff))
	le.PutUint32(out[hdrStringIdsSize:], uint32(len(x.m.strings)))
	le.PutUint32(out[hdrStringIdsOff:], uint32(x.lo.strOff))
	le.PutUint32(out[hdrTypeIdsSize:], uint32(len(x.m.types)))
	le.PutUint32(out[hdrTypeIdsOff:], uint32(x.lo.typOff))
	le.PutUint32(out[hdrProtoIdsSize:], uint32(len(x.m.protos)))
	le.PutUint32(out[hdrProtoIdsOff:], uint32(x.lo.protoOff))
	le.PutUint32(out[hdrFieldIdsSize:], uint32(len(x.m.fields)))
	le.PutUint32(out[hdrFieldIdsOff:], uint32(x.lo.fieldOff))
	le.PutUint32(out[hdrMethodIdsSize:], uint32(len(x.m.methods)))
	le.PutUint32(out[hdrMethodIdsOff:], uint32(x.lo.methodOff))
	le.PutUint32(out[hdrClassDefsSize:], uint32(len(x.d.Classes)))
	le.PutUint32(out[hdrClassDefsOff:], uint32(x.lo.classOff))
	le.PutUint32(out[hdrDataOff:], uint32(x.lo.dataStart))
	le.PutUint32(out[hdrDataSize:], uint32(len(out)-x.lo.dataStart))

	// string_ids
	for i, off := range x.stringDataOff {
		le.PutUint32(out[x.lo.strOff+4*i:], off)
	}
	// type_ids
	for i, v := range x.m.types {
		le.PutUint32(out[x.lo.typOff+4*i:], v)
	}
	// proto_ids
	for i, p := range x.m.protos {
		base := x.lo.protoOff + 12*i
		le.PutUint32(out[base:], p.Shorty)
		le.PutUint32(out[base+4:], p.Return)
		le.PutUint32(out[base+8:], x.protoParamsOff[i])
	}
	// field_ids
	for i, f := range x.m.fields {
		base := x.lo.fieldOff + 8*i
		if f.Class > 0xffff || f.Type > 0xffff {
			return fmt.Errorf("dex: field[%d] class/type index does not fit in u16", i)
		}
		le.PutUint16(out[base:], uint16(f.Class))
		le.PutUint16(out[base+2:], uint16(f.Type))
		le.PutUint32(out[base+4:], f.Name)
	}
	// method_ids
	for i, mm := range x.m.methods {
		base := x.lo.methodOff + 8*i
		if mm.Class > 0xffff || mm.Proto > 0xffff {
			return fmt.Errorf("dex: method[%d] class/proto index does not fit in u16", i)
		}
		le.PutUint16(out[base:], uint16(mm.Class))
		le.PutUint16(out[base+2:], uint16(mm.Proto))
		le.PutUint32(out[base+4:], mm.Name)
	}
	// class_defs, in class_idx order
	for newIdx, old := range x.m.classOrder {
		cd := x.d.Classes[old]
		base := x.lo.classOff + 32*newIdx
		class, err := x.m.typ(cd.ClassIdx)
		if err != nil {
			return err
		}
		le.PutUint32(out[base:], class)
		le.PutUint32(out[base+4:], cd.AccessFlags)
		super, err := x.m.typ(cd.Superclass)
		if err != nil {
			return err
		}
		le.PutUint32(out[base+8:], super)
		le.PutUint32(out[base+12:], x.ifaceOff[old])
		src, err := x.m.str(cd.SourceFile)
		if err != nil {
			return err
		}
		le.PutUint32(out[base+16:], src)
		le.PutUint32(out[base+20:], x.classDirOff[old])
		le.PutUint32(out[base+24:], x.classDataOff[old])
		le.PutUint32(out[base+28:], x.staticOff[old])
	}
	return nil
}

// ------------------------------------------------------------ data item bodies

func (x *encoder) emitTypeLists() (protoParamsOff, ifaceOff []uint32, err error) {
	protoParamsOff = make([]uint32, len(x.d.Protos))
	for i, p := range x.d.Protos {
		if len(p.Params) == 0 {
			continue
		}
		x.e.align(4)
		off := x.e.tell()
		x.e.u32(uint32(len(p.Params)))
		for _, t := range p.Params {
			nt, err := x.m.typ(t)
			if err != nil {
				return nil, nil, err
			}
			x.e.u32(nt)
		}
		x.e.touch(mapTypeList, off)
		protoParamsOff[i] = uint32(off)
	}
	ifaceOff = make([]uint32, len(x.d.Classes))
	for i, c := range x.d.Classes {
		if len(c.Interfaces) == 0 {
			continue
		}
		x.e.align(4)
		off := x.e.tell()
		x.e.u32(uint32(len(c.Interfaces)))
		for _, t := range c.Interfaces {
			nt, err := x.m.typ(t)
			if err != nil {
				return nil, nil, err
			}
			x.e.u32(nt)
		}
		x.e.touch(mapTypeList, off)
		ifaceOff[i] = uint32(off)
	}
	return protoParamsOff, ifaceOff, nil
}

func (x *encoder) emitAnnotations() ([]uint32, error) {
	classDir := make([]uint32, len(x.d.Classes))
	var items []AnnotationItem
	var sets [][]int
	var refLists [][]int

	addSet := func(anns []AnnotationItem) int {
		if len(anns) == 0 {
			return -1
		}
		ix := len(sets)
		var refs []int
		for _, a := range anns {
			items = append(items, a)
			refs = append(refs, len(items)-1)
		}
		sets = append(sets, refs)
		return ix
	}

	type classPlan struct {
		classIdx int
		classSet int
		fields   []annFieldEntry
		methods  []annMethodEntry
		params   []annParamEntry
	}
	var plans []classPlan
	for ci, cd := range x.d.Classes {
		if cd.Annotations.empty() {
			continue
		}
		pl := classPlan{classIdx: ci, classSet: -1}
		pl.classSet = addSet(cd.Annotations.Class)
		for _, f := range cd.Annotations.Fields {
			if s := addSet(f.Anns); s >= 0 {
				pl.fields = append(pl.fields, annFieldEntry{field: f.Field, set: s})
			}
		}
		for _, m := range cd.Annotations.Methods {
			if s := addSet(m.Anns); s >= 0 {
				pl.methods = append(pl.methods, annMethodEntry{method: m.Method, set: s})
			}
		}
		for _, p := range cd.Annotations.Parameters {
			var ids []int
			any := false
			for _, anns := range p.Anns {
				s := addSet(anns)
				if s >= 0 {
					any = true
				}
				ids = append(ids, s)
			}
			if any {
				refLists = append(refLists, ids)
				pl.params = append(pl.params, annParamEntry{method: p.Method, ref: len(refLists) - 1})
			}
		}
		if pl.classSet < 0 && len(pl.fields) == 0 && len(pl.methods) == 0 && len(pl.params) == 0 {
			continue
		}
		plans = append(plans, pl)
	}

	// annotation_item (1-byte aligned)
	itemOff := make([]uint32, len(items))
	for i, it := range items {
		off := x.e.tell()
		x.e.u8(it.Visibility)
		if err := x.writeEncodedAnnotation(it.Ann); err != nil {
			return nil, fmt.Errorf("annotation_item[%d]: %w", i, err)
		}
		x.e.touch(mapAnnotation, off)
		itemOff[i] = uint32(off)
	}
	// annotation_set_item (4-byte aligned)
	setOff := make([]uint32, len(sets))
	for i, refs := range sets {
		x.e.align(4)
		off := x.e.tell()
		x.e.u32(uint32(len(refs)))
		for _, r := range refs {
			x.e.u32(itemOff[r])
		}
		x.e.touch(mapAnnotationSetItem, off)
		setOff[i] = uint32(off)
	}
	// annotation_set_ref_list (4-byte aligned)
	refOff := make([]uint32, len(refLists))
	for i, ids := range refLists {
		x.e.align(4)
		off := x.e.tell()
		x.e.u32(uint32(len(ids)))
		for _, s := range ids {
			if s < 0 {
				x.e.u32(0)
			} else {
				x.e.u32(setOff[s])
			}
		}
		x.e.touch(mapAnnotationSetRefList, off)
		refOff[i] = uint32(off)
	}
	// annotations_directory_item (4-byte aligned)
	type pair struct {
		idx uint32
		off uint32
	}
	for _, pl := range plans {
		x.e.align(4)
		off := x.e.tell()
		classSet := uint32(0)
		if pl.classSet >= 0 {
			classSet = setOff[pl.classSet]
		}
		fields := make([]pair, 0, len(pl.fields))
		for _, f := range pl.fields {
			nf, err := x.m.field(f.field)
			if err != nil {
				return nil, err
			}
			fields = append(fields, pair{nf, setOff[f.set]})
		}
		methods := make([]pair, 0, len(pl.methods))
		for _, mm := range pl.methods {
			nm, err := x.m.method(mm.method)
			if err != nil {
				return nil, err
			}
			methods = append(methods, pair{nm, setOff[mm.set]})
		}
		params := make([]pair, 0, len(pl.params))
		for _, pp := range pl.params {
			nm, err := x.m.method(pp.method)
			if err != nil {
				return nil, err
			}
			params = append(params, pair{nm, refOff[pp.ref]})
		}
		byIdx := func(l []pair) {
			sort.SliceStable(l, func(a, b int) bool { return l[a].idx < l[b].idx })
		}
		byIdx(fields)
		byIdx(methods)
		byIdx(params)
		x.e.u32(classSet)
		x.e.u32(uint32(len(fields)))
		x.e.u32(uint32(len(methods)))
		x.e.u32(uint32(len(params)))
		for _, p := range append(append(fields, methods...), params...) {
			x.e.u32(p.idx)
			x.e.u32(p.off)
		}
		x.e.touch(mapAnnotationsDirectory, off)
		classDir[pl.classIdx] = uint32(off)
	}
	return classDir, nil
}

func (x *encoder) emitStaticValues() ([]uint32, error) {
	off := make([]uint32, len(x.d.Classes))
	for i, c := range x.d.Classes {
		if len(c.StaticValues) == 0 {
			continue
		}
		start := x.e.tell()
		x.e.uleb(uint32(len(c.StaticValues)))
		for _, v := range c.StaticValues {
			if err := x.writeEncodedValue(v); err != nil {
				return nil, err
			}
		}
		x.e.touch(mapEncodedArray, start)
		off[i] = uint32(start)
	}
	return off, nil
}

func (x *encoder) emitDebugInfo() (map[*DebugInfo]uint32, error) {
	off := map[*DebugInfo]uint32{}
	for _, c := range x.d.Classes {
		if c.ClassData == nil {
			continue
		}
		for _, m := range append(append([]EncMethod{}, c.ClassData.DirectMethods...), c.ClassData.VirtualMethods...) {
			if m.Code == nil || m.Code.Debug == nil {
				continue
			}
			if _, done := off[m.Code.Debug]; done {
				continue
			}
			start := x.e.tell()
			if err := x.writeDebugInfo(m.Code.Debug); err != nil {
				return nil, err
			}
			x.e.touch(mapDebugInfo, start)
			off[m.Code.Debug] = uint32(start)
		}
	}
	return off, nil
}

func (x *encoder) emitCode() (map[*CodeItem]uint32, error) {
	off := map[*CodeItem]uint32{}
	for _, c := range x.d.Classes {
		if c.ClassData == nil {
			continue
		}
		for _, m := range append(append([]EncMethod{}, c.ClassData.DirectMethods...), c.ClassData.VirtualMethods...) {
			if m.Code == nil {
				continue
			}
			x.e.align(4)
			start := x.e.tell()
			if err := x.writeCodeItem(m.Code); err != nil {
				return nil, err
			}
			x.e.touch(mapCode, start)
			off[m.Code] = uint32(start)
		}
	}
	return off, nil
}

func (x *encoder) emitClassData() ([]uint32, error) {
	off := make([]uint32, len(x.d.Classes))
	for i, c := range x.d.Classes {
		if c.ClassData == nil {
			continue
		}
		start := x.e.tell()
		if err := x.writeClassData(c.ClassData); err != nil {
			return nil, err
		}
		x.e.touch(mapClassData, start)
		off[i] = uint32(start)
	}
	return off, nil
}

func (x *encoder) emitStringData() ([]uint32, error) {
	off := make([]uint32, len(x.m.strings))
	for i, s := range x.m.strings {
		start := x.e.tell()
		x.e.uleb(utf16Size(s))
		x.e.raw(mutf8Encode(s))
		x.e.u8(0)
		x.e.touch(mapStringData, start)
		off[i] = uint32(start)
	}
	return off, nil
}

// --------------------------------------------------------- item serialisation

func (x *encoder) writeCodeItem(ci *CodeItem) error {
	insns, err := x.remapInsns(ci.Insns)
	if err != nil {
		return err
	}
	x.e.u16(ci.Registers)
	x.e.u16(ci.Ins)
	x.e.u16(ci.Outs)
	x.e.u16(uint16(len(ci.Tries)))
	debugOff := uint32(0)
	if ci.Debug != nil {
		debugOff = x.debugOff[ci.Debug]
	}
	x.e.u32(debugOff)
	x.e.u32(uint32(len(insns)))
	for _, u := range insns {
		x.e.u16(u)
	}
	if len(ci.Tries) > 0 {
		x.e.align(4)
		// build the handler list first so try items can point at it
		var hb []byte
		appendULEB := func(v uint32) {
			for {
				b := byte(v & 0x7f)
				v >>= 7
				if v != 0 {
					b |= 0x80
				}
				hb = append(hb, b)
				if v == 0 {
					return
				}
			}
		}
		appendSLEB := func(v int32) {
			for {
				b := byte(v & 0x7f)
				v >>= 7
				if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
					hb = append(hb, b)
					return
				}
				hb = append(hb, b|0x80)
			}
		}
		appendULEB(uint32(len(ci.Handlers)))
		hOff := make([]uint16, len(ci.Handlers))
		for i, h := range ci.Handlers {
			hOff[i] = uint16(len(hb))
			typed := 0
			catchAll := false
			for _, c := range h {
				if c.Type == NoIndex {
					catchAll = true
				} else {
					typed++
				}
			}
			switch {
			case catchAll:
				appendSLEB(int32(typed + 1))
			default:
				appendSLEB(int32(-typed))
			}
			for _, c := range h {
				if c.Type == NoIndex {
					continue
				}
				nt, err := x.m.typ(c.Type)
				if err != nil {
					return err
				}
				appendULEB(nt)
				appendULEB(c.Addr)
			}
			if catchAll {
				for _, c := range h {
					if c.Type == NoIndex {
						appendULEB(c.Addr)
					}
				}
			}
		}
		for _, t := range ci.Tries {
			if int(t.HandlerIdx) >= len(hOff) {
				return fmt.Errorf("dex: try_item handler index %d out of range", t.HandlerIdx)
			}
			x.e.u32(t.StartAddr)
			x.e.u16(t.InsnCount)
			x.e.u16(hOff[t.HandlerIdx])
		}
		x.e.raw(hb)
	}
	return nil
}

// remapInsns rewrites the index operands embedded in the instruction stream
// (const-string, new-instance, invoke-*, iget/iput, ...) so they follow the new
// index spaces.
func (x *encoder) remapInsns(insns []uint16) ([]uint16, error) {
	out := make([]uint16, len(insns))
	copy(out, insns)
	for i := 0; i < len(insns); {
		f := insnTable[insns[i]>>8]
		if f.width < 1 || i+f.width > len(insns) {
			return nil, fmt.Errorf("dex: instruction at code unit %d overruns the stream", i)
		}
		if f.kind != ikNone {
			if err := x.remapOperand(out, i, f.off, f.size, f.kind); err != nil {
				return nil, err
			}
		}
		if f.kind2 != ikNone {
			if err := x.remapOperand(out, i, f.off2, f.size2, f.kind2); err != nil {
				return nil, err
			}
		}
		i += f.width
	}
	return out, nil
}

func (x *encoder) remapOperand(out []uint16, insnStart, byteOff, size int, kind indexKind) error {
	unit := insnStart + byteOff/2
	var old uint32
	if size == 2 {
		old = uint32(out[unit])
	} else {
		old = uint32(out[unit]) | uint32(out[unit+1])<<16
	}
	var (
		nv  uint32
		err error
	)
	switch kind {
	case ikString:
		nv, err = x.m.str(old)
	case ikType:
		nv, err = x.m.typ(old)
	case ikField:
		nv, err = x.m.field(old)
	case ikMethod:
		nv, err = x.m.method(old)
	case ikProto:
		nv, err = x.m.proto(old)
	default:
		return fmt.Errorf("dex: cannot remap instruction operand kind %d", kind)
	}
	if err != nil {
		return err
	}
	if size == 2 {
		if nv > 0xffff {
			return fmt.Errorf("dex: remapped index %d does not fit in the 16-bit operand", nv)
		}
		out[unit] = uint16(nv)
		return nil
	}
	out[unit] = uint16(nv & 0xffff)
	out[unit+1] = uint16(nv >> 16)
	return nil
}

func (x *encoder) writeDebugInfo(dbg *DebugInfo) error {
	x.e.uleb(dbg.LineStart)
	x.e.uleb(uint32(len(dbg.Params)))
	for _, p := range dbg.Params {
		if p == NoIndex {
			x.e.uleb(NoIndex)
			continue
		}
		np, err := x.m.str(p)
		if err != nil {
			return err
		}
		x.e.uleb(np)
	}
	for _, op := range dbg.Ops {
		x.e.uleb(op.Op)
		for i, a := range op.Args {
			kind := dbgPlain
			if i < len(op.Kind) {
				kind = op.Kind[i]
			}
			switch kind {
			case dbgSigned:
				x.e.sleb(int32(a))
			case dbgString:
				if a == NoIndex {
					x.e.uleb(NoIndex)
					break
				}
				nv, err := x.m.str(a)
				if err != nil {
					return err
				}
				x.e.uleb(nv)
			case dbgType:
				nv, err := x.m.typ(a)
				if err != nil {
					return err
				}
				x.e.uleb(nv)
			default:
				x.e.uleb(a)
			}
		}
	}
	return nil
}

func (x *encoder) writeClassData(cd *ClassData) error {
	x.e.uleb(uint32(len(cd.StaticFields)))
	x.e.uleb(uint32(len(cd.InstanceFields)))
	x.e.uleb(uint32(len(cd.DirectMethods)))
	x.e.uleb(uint32(len(cd.VirtualMethods)))

	writeFields := func(list []EncField) error {
		mapped := make([]uint32, len(list))
		for i, f := range list {
			nv, err := x.m.field(f.Field)
			if err != nil {
				return err
			}
			mapped[i] = nv
		}
		// The on-disk form stores ascending diffs, and remapping can reorder
		// the members, so re-sort by the new index before encoding.
		order := make([]int, len(list))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return mapped[order[a]] < mapped[order[b]] })
		var prev uint32
		for n, oi := range order {
			if n > 0 && mapped[oi] <= prev {
				return fmt.Errorf("dex: class_data field indices are not unique")
			}
			diff := mapped[oi]
			if n > 0 {
				diff -= prev
			}
			x.e.uleb(diff)
			x.e.uleb(list[oi].Access)
			prev = mapped[oi]
		}
		return nil
	}
	writeMethods := func(list []EncMethod) error {
		mapped := make([]uint32, len(list))
		for i, m := range list {
			nv, err := x.m.method(m.Method)
			if err != nil {
				return err
			}
			mapped[i] = nv
		}
		order := make([]int, len(list))
		for i := range order {
			order[i] = i
		}
		sort.SliceStable(order, func(a, b int) bool { return mapped[order[a]] < mapped[order[b]] })
		var prev uint32
		for n, oi := range order {
			if n > 0 && mapped[oi] <= prev {
				return fmt.Errorf("dex: class_data method indices are not unique")
			}
			diff := mapped[oi]
			if n > 0 {
				diff -= prev
			}
			x.e.uleb(diff)
			x.e.uleb(list[oi].Access)
			codeOff := uint32(0)
			if list[oi].Code != nil {
				off, ok := x.codeOff[list[oi].Code]
				if !ok {
					return fmt.Errorf("dex: method code item was not emitted")
				}
				codeOff = off
			}
			x.e.uleb(codeOff)
			prev = mapped[oi]
		}
		return nil
	}
	if err := writeFields(cd.StaticFields); err != nil {
		return err
	}
	if err := writeFields(cd.InstanceFields); err != nil {
		return err
	}
	if err := writeMethods(cd.DirectMethods); err != nil {
		return err
	}
	return writeMethods(cd.VirtualMethods)
}

func (x *encoder) writeEncodedAnnotation(ann EncodedAnnotation) error {
	nt, err := x.m.typ(ann.Type)
	if err != nil {
		return err
	}
	x.e.uleb(nt)
	x.e.uleb(uint32(len(ann.Elements)))
	for _, el := range ann.Elements {
		nn, err := x.m.str(el.Name)
		if err != nil {
			return err
		}
		x.e.uleb(nn)
		if err := x.writeEncodedValue(el.Value); err != nil {
			return err
		}
	}
	return nil
}

func (x *encoder) writeEncodedValue(v EncodedValue) error {
	const (
		valueByte       = 0x00
		valueShort      = 0x02
		valueChar       = 0x03
		valueInt        = 0x04
		valueLong       = 0x06
		valueFloat      = 0x10
		valueDouble     = 0x11
		valueMethodType = 0x15
		valueMethodHndl = 0x16
		valueString     = 0x17
		valueType       = 0x18
		valueField      = 0x19
		valueMethod     = 0x1a
		valueEnum       = 0x1b
		valueArray      = 0x1c
		valueAnnotation = 0x1d
		valueNull       = 0x1e
		valueBoolean    = 0x1f
	)
	writeRaw := func(n int, raw uint64) {
		for i := 0; i < n; i++ {
			x.e.u8(byte(raw >> (8 * i)))
		}
	}
	switch v.Type {
	case valueByte:
		x.e.u8(byte(valueByte))
		x.e.u8(byte(v.Int))
	case valueShort, valueInt, valueLong:
		arg := minSignedBytes(int64(v.Int))
		if v.Type == valueShort && arg > 1 {
			return fmt.Errorf("dex: short value out of range")
		}
		x.e.u8(byte(v.Type) | byte(uint(arg)<<5))
		writeRaw(arg+1, v.Int)
	case valueChar:
		arg := minUnsignedBytes(v.Int)
		if arg > 1 {
			return fmt.Errorf("dex: char value out of range")
		}
		x.e.u8(byte(valueChar) | byte(uint(arg)<<5))
		writeRaw(arg+1, v.Int)
	case valueFloat:
		x.e.u8(byte(valueFloat) | byte(3<<5))
		writeRaw(4, v.Int)
	case valueDouble:
		x.e.u8(byte(valueDouble) | byte(7<<5))
		writeRaw(8, v.Int)
	case valueString, valueType, valueField, valueMethod, valueEnum:
		var (
			nv  uint32
			err error
		)
		raw := v.Int
		switch v.Type {
		case valueString:
			nv, err = x.m.str(uint32(raw))
		case valueType:
			nv, err = x.m.typ(uint32(raw))
		case valueField, valueEnum:
			nv, err = x.m.field(uint32(raw))
		case valueMethod:
			nv, err = x.m.method(uint32(raw))
		}
		if err != nil {
			return err
		}
		value := uint64(nv)
		arg := minUnsignedBytes(value)
		x.e.u8(byte(v.Type) | byte(uint(arg)<<5))
		writeRaw(arg+1, value)
	case valueMethodType:
		nv, err := x.m.proto(uint32(v.Int))
		if err != nil {
			return err
		}
		value := uint64(nv)
		arg := minUnsignedBytes(value)
		x.e.u8(byte(valueMethodType) | byte(uint(arg)<<5))
		writeRaw(arg+1, value)
	case valueMethodHndl:
		return unsupported("method_handle encoded value")
	case valueArray:
		x.e.u8(byte(valueArray))
		x.e.uleb(uint32(len(v.Arr)))
		for _, e := range v.Arr {
			if err := x.writeEncodedValue(e); err != nil {
				return err
			}
		}
	case valueAnnotation:
		if v.Ann == nil {
			return fmt.Errorf("dex: annotation value without payload")
		}
		x.e.u8(byte(valueAnnotation))
		return x.writeEncodedAnnotation(*v.Ann)
	case valueNull:
		x.e.u8(byte(valueNull))
	case valueBoolean:
		x.e.u8(byte(valueBoolean) | byte(uint(v.Int&1)<<5))
	default:
		return fmt.Errorf("dex: cannot encode value type 0x%02x", v.Type)
	}
	return nil
}

// minSignedBytes returns the number of payload bytes minus one needed for the
// smallest signed encoding of v.
func minSignedBytes(v int64) int {
	for n := 1; n < 8; n++ {
		min := int64(-1) << (8*n - 1)
		max := int64(1)<<(8*n-1) - 1
		if v >= min && v <= max {
			return n - 1
		}
	}
	return 7
}

// minUnsignedBytes returns the number of payload bytes minus one needed for the
// smallest unsigned encoding of v.
func minUnsignedBytes(v uint64) int {
	for n := 1; n < 8; n++ {
		if v < uint64(1)<<(8*n) {
			return n - 1
		}
	}
	return 7
}
