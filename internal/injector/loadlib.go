package injector

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// LoadLibCall is one library lookup the host performs itself: a call to
// System.loadLibrary("x") (or Runtime.loadLibrary0) whose argument is a string
// constant, so the name is known without running anything. Instant marks a call
// site inside <clinit>/<init>, which runs while the class is being initialised.
type LoadLibCall struct {
	Name    string
	Caller  string
	Method  string
	Instant bool
}

// insnWidth returns the size in code units of the instruction at pc, or an
// error when the stream cannot be walked (an opcode this tool does not know, a
// truncated payload, a malformed switch payload).
func insnWidth(insns []uint16, pc int) (int, error) {
	if pc < 0 || pc >= len(insns) {
		return 0, fmt.Errorf("instruction offset %d outside the stream (%d units)", pc, len(insns))
	}
	op := byte(insns[pc] & 0xff)

	if op == 0x00 {
		// 0x00 with a non-zero second byte is a payload, not nop: packed-switch,
		// sparse-switch and fill-array-data live in the instruction stream.
		switch byte(insns[pc] >> 8) {
		case 0x00:
			return 1, nil
		case 0x01: // packed-switch-payload: size in units 4 + count*2
			if pc+1 >= len(insns) {
				return 0, fmt.Errorf("truncated packed-switch payload at %d", pc)
			}
			return 4 + 2*int(insns[pc+1]), nil
		case 0x02: // sparse-switch-payload: 2 + count*4
			if pc+1 >= len(insns) {
				return 0, fmt.Errorf("truncated sparse-switch payload at %d", pc)
			}
			return 2 + 4*int(insns[pc+1]), nil
		case 0x03: // fill-array-data-payload
			if pc+3 >= len(insns) {
				return 0, fmt.Errorf("truncated fill-array-data payload at %d", pc)
			}
			width := int(insns[pc+1])
			count := int(insns[pc+2]) | int(insns[pc+3])<<16
			return 4 + (width*count+1)/2, nil
		default:
			return 0, fmt.Errorf("unknown pseudo-instruction 0x%04x at %d", insns[pc], pc)
		}
	}

	switch {
	case op >= 0x01 && op <= 0x09:
		// move / move-wide / move-object, each in 12x(1), 22x(2), 32x(3):
		// 0x01 0x04 0x07 are 12x, 0x02 0x05 0x08 are 22x, 0x03 0x06 0x09 are 32x.
		return 1 + int((op-1)%3), nil
	case op >= 0x0a && op <= 0x11:
		return 1, nil // move-result*, move-exception, return*
	case op == 0x12:
		return 1, nil // const/4 11n
	case op == 0x13 || op == 0x15 || op == 0x16 || op == 0x19 || op == 0x1a || op == 0x1c:
		return 2, nil // const/16, const/high16, const-wide/16, const-wide/high16,
		// const-string and const-class are all 21x: one register, one index
	case op == 0x14 || op == 0x17 || op == 0x1b:
		return 3, nil // const, const-wide/32 and const-string/jumbo are 31x
	case op == 0x18:
		return 5, nil // const-wide 51l
	case op == 0x1d || op == 0x1e || op == 0x21 || op == 0x27:
		return 1, nil // 11x
	case op == 0x1f || op == 0x22:
		return 2, nil // 21c type reference
	case op == 0x20 || op == 0x23:
		return 2, nil // 22c
	case op == 0x24:
		return 3, nil // filled-new-array 35c
	case op == 0x25:
		return 3, nil // filled-new-array/range 3rc
	case op == 0x26 || op == 0x2b || op == 0x2c:
		return 3, nil // fill-array-data / *-switch, 31t
	case op == 0x28:
		return 1, nil // goto 10t
	case op == 0x29:
		return 2, nil // goto/16 20t
	case op == 0x2a:
		return 3, nil // goto/32 30t
	case op >= 0x2d && op <= 0x31:
		return 2, nil // cmp* 23x
	case op >= 0x32 && op <= 0x37:
		return 2, nil // if-test 22t
	case op >= 0x38 && op <= 0x3d:
		return 2, nil // if-testz 21t
	case op >= 0x44 && op <= 0x51:
		return 2, nil // aget/aput 23x
	case op >= 0x52 && op <= 0x5f:
		return 2, nil // iget/iput 22c
	case op >= 0x60 && op <= 0x6d:
		return 2, nil // sget/sput 21c
	case op >= 0x6e && op <= 0x72:
		return 3, nil // invoke-* 35c
	case op >= 0x74 && op <= 0x78:
		return 3, nil // invoke-*/range 3rc
	case op >= 0x7b && op <= 0x8f:
		return 1, nil // unop 12x
	case op >= 0x90 && op <= 0xaf:
		return 2, nil // binop 23x
	case op >= 0xb0 && op <= 0xcf:
		return 1, nil // binop/2addr 12x
	case op >= 0xd0 && op <= 0xd7:
		return 2, nil // binop/lit16 22s
	case op >= 0xd8 && op <= 0xe2:
		return 2, nil // binop/lit8 22b
	case op == 0xfa || op == 0xfb:
		return 4, nil // invoke-polymorphic 45cc/4rcc
	case op == 0xfc || op == 0xfd:
		return 3, nil // invoke-custom 35c/3rc
	case op == 0xfe || op == 0xff:
		return 2, nil // const-method-handle / const-method-type 21c
	default:
		// 0x3e-0x43, 0x73, 0x79-0x7a and 0xe3-0xf9 are unused in every dex
		// version this tool targets: a dex that uses them is not one we can walk.
		return 0, fmt.Errorf("unknown opcode 0x%02x at %d", op, pc)
	}
}

// WalkInsns checks that the instruction stream of a code item can be walked from
// the first instruction to exactly its end. A wrong size table shows up here
// first, before it can silently mis-read a method body.
func WalkInsns(insns []uint16) error {
	for pc := 0; pc < len(insns); {
		w, err := insnWidth(insns, pc)
		if err != nil {
			return err
		}
		pc += w
		if pc > len(insns) {
			return fmt.Errorf("instruction at %d ends at %d, past the code item (%d units)",
				pc-w, pc, len(insns))
		}
	}
	return nil
}

// --- минимальный читатель dex ------------------------------------------------

// minDex is a deliberately small read-only view of a dex file: only the tables a
// library-scan needs. The full parser+writer in pkg/dex exists for the tool's
// own stub dex, where a round trip has to be byte-exact; reading a *host* dex
// must not depend on that, so this reader bounds every access and skips what it
// cannot make sense of instead of failing the whole file.
type minDex struct {
	strs    []string
	types   []uint32
	methods []minMethod
	classes []minClass
}

type minMethod struct {
	classIdx uint32
	nameIdx  uint32
}

type minClass struct {
	classIdx uint32
	dataOff  uint32
}

func rdU16(b []byte, off int) (uint32, bool) {
	if off < 0 || off+2 > len(b) {
		return 0, false
	}
	return uint32(binary.LittleEndian.Uint16(b[off:])), true
}

func rdU32(b []byte, off int) (uint32, bool) {
	if off < 0 || off+4 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[off:]), true
}

// rdUleb reads an unsigned LEB128 with a hard bound on the number of bytes, so a
// misaligned offset cannot be mistaken for a long but valid number.
func rdUleb(b []byte, off int) (uint32, int, bool) {
	var v uint32
	var shift uint
	for i := 0; i < 5; i++ {
		if off+i >= len(b) {
			return 0, 0, false
		}
		c := b[off+i]
		v |= uint32(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

// rdMutf8 reads a NUL-terminated modified-UTF-8 string (the encoding dex uses in
// string_data_item).
func rdMutf8(b []byte, off int) (string, bool) {
	if off < 0 || off >= len(b) {
		return "", false
	}
	end := off
	for end < len(b) && b[end] != 0 {
		end++
	}
	if end >= len(b) {
		return "", false
	}
	raw := b[off:end]
	var sb strings.Builder
	for i := 0; i < len(raw); {
		c := raw[i]
		switch {
		case c == 0xc0 && i+1 < len(raw) && raw[i+1] == 0x80:
			sb.WriteByte(0)
			i += 2
		case c < 0x80:
			sb.WriteByte(c)
			i++
		case c&0xe0 == 0xc0 && i+1 < len(raw):
			sb.WriteByte((c&0x1f)<<6 | raw[i+1]&0x3f)
			i += 2
		case c&0xf0 == 0xe0 && i+2 < len(raw):
			sb.WriteRune(rune((c&0x0f)<<12 | (raw[i+1]&0x3f)<<6 | raw[i+2]&0x3f))
			i += 3
		default:
			sb.WriteByte(c)
			i++
		}
	}
	return sb.String(), true
}

func readMinDex(data []byte) (*minDex, error) {
	if len(data) < 0x70 || string(data[0:4]) != "dex\n" {
		return nil, fmt.Errorf("not a dex file")
	}
	get := func(off int) uint32 {
		v, _ := rdU32(data, off)
		return v
	}
	strSize, strOff := get(0x38), get(0x3c)
	typeSize, typeOff := get(0x40), get(0x44)
	methSize, methOff := get(0x58), get(0x5c)
	classSize, classOff := get(0x60), get(0x64)
	const maxTable = 1 << 22
	if strSize > maxTable || typeSize > maxTable || methSize > maxTable || classSize > maxTable {
		return nil, fmt.Errorf("implausible dex table size")
	}

	d := &minDex{}
	for i := uint32(0); i < strSize; i++ {
		off, ok := rdU32(data, int(strOff)+4*int(i))
		if !ok {
			break
		}
		// string_data_item = utf16_size (uleb128) + MUTF-8 bytes.
		_, n, ok := rdUleb(data, int(off))
		if !ok {
			break
		}
		s, ok := rdMutf8(data, int(off)+n)
		if !ok {
			break
		}
		d.strs = append(d.strs, s)
	}
	for i := uint32(0); i < typeSize; i++ {
		v, ok := rdU32(data, int(typeOff)+4*int(i))
		if !ok {
			break
		}
		d.types = append(d.types, v)
	}
	for i := uint32(0); i < methSize; i++ {
		base := int(methOff) + 8*int(i)
		ci, ok1 := rdU16(data, base)
		ni, ok2 := rdU32(data, base+4)
		if !ok1 || !ok2 {
			break
		}
		d.methods = append(d.methods, minMethod{classIdx: ci, nameIdx: ni})
	}
	for i := uint32(0); i < classSize; i++ {
		base := int(classOff) + 32*int(i)
		ci, ok1 := rdU32(data, base)
		do, ok2 := rdU32(data, base+24)
		if !ok1 || !ok2 {
			break
		}
		d.classes = append(d.classes, minClass{classIdx: ci, dataOff: do})
	}
	if len(d.strs) == 0 || len(d.classes) == 0 {
		return nil, fmt.Errorf("dex has no readable string or class table")
	}
	return d, nil
}

func (d *minDex) str(i uint32) string {
	if int(i) < len(d.strs) {
		return d.strs[i]
	}
	return ""
}

func (d *minDex) desc(i uint32) string {
	if int(i) < len(d.types) {
		return d.str(d.types[i])
	}
	return ""
}

// eachMethod walks the class_data_item at dataOff and calls fn for every method
// that carries code. Anything inconsistent ends the walk for that class only.
func (d *minDex) eachMethod(data []byte, dataOff uint32, fn func(desc, name string, insns []uint16)) {
	off := int(dataOff)
	rd := func() (uint32, bool) {
		v, n, ok := rdUleb(data, off)
		if !ok {
			return 0, false
		}
		off += n
		return v, true
	}
	staticFields, ok := rd()
	if !ok {
		return
	}
	instFields, ok := rd()
	if !ok {
		return
	}
	direct, ok := rd()
	if !ok {
		return
	}
	virtual, ok := rd()
	if !ok {
		return
	}
	for i := uint32(0); i < staticFields+instFields; i++ {
		if _, ok := rd(); !ok {
			return
		}
		if _, ok := rd(); !ok {
			return
		}
	}
	for i := uint32(0); i < direct+virtual; i++ {
		midx, ok := rd()
		if !ok {
			return
		}
		if _, ok := rd(); !ok {
			return
		}
		codeOff, ok := rd()
		if !ok {
			return
		}
		if codeOff == 0 || int(midx) >= len(d.methods) {
			continue
		}
		co := int(codeOff)
		sz, ok := rdU32(data, co+12)
		if !ok || sz == 0 || sz > 1<<20 {
			continue
		}
		start := co + 16
		if start+2*int(sz) > len(data) {
			continue
		}
		insns := make([]uint16, sz)
		for k := range insns {
			insns[k] = binary.LittleEndian.Uint16(data[start+2*k:])
		}
		fn(d.desc(d.methods[midx].classIdx), d.str(d.methods[midx].nameIdx), insns)
	}
}

// LoadLibraryCalls returns every statically resolvable library lookup in a dex
// file. Names that the compiler built at runtime (StringBuilder, a field, a
// computed path) are invisible here on purpose: without a literal there is
// nothing to hide behind.
func LoadLibraryCalls(data []byte) ([]LoadLibCall, error) {
	d, err := readMinDex(data)
	if err != nil {
		return nil, err
	}
	var out []LoadLibCall
	seen := map[string]bool{}
	for _, cd := range d.classes {
		if cd.dataOff == 0 {
			continue
		}
		caller := d.desc(cd.classIdx)
		d.eachMethod(data, cd.dataOff, func(_ string, mname string, insns []uint16) {
			name := loadLibIn(d, insns)
			if name == nil {
				return
			}
			key := *name + "\x00" + caller + "\x00" + mname
			if seen[key] {
				return
			}
			seen[key] = true
			out = append(out, LoadLibCall{
				Name:    *name,
				Caller:  caller,
				Method:  mname,
				Instant: mname == "<clinit>" || mname == "<init>",
			})
		})
	}
	return out, nil
}

// loadLibIn walks one method body and returns the literal passed to
// loadLibrary/loadLibrary0, or nil when the method makes no such call with a
// constant argument. Register values are tracked for constants only and dropped
// on every instruction that could move them, which is enough for the compiler
// shapes seen in practice (const-string immediately before the call).
func loadLibIn(d *minDex, insns []uint16) *string {
	regs := map[int]string{}
	reset := func() {
		for k := range regs {
			delete(regs, k)
		}
	}
	for pc := 0; pc < len(insns); {
		w, err := insnWidth(insns, pc)
		if err != nil {
			return nil
		}
		op := byte(insns[pc] & 0xff)
		switch {
		case op == 0x1a && pc+1 < len(insns): // const-string vAA, string@BBBB
			regs[int(insns[pc]>>8)] = d.str(uint32(insns[pc+1]))
		case op == 0x1b && pc+2 < len(insns): // const-string/jumbo vAA, string@BBBBBBBB
			idx := uint32(insns[pc+1]) | uint32(insns[pc+2])<<16
			regs[int(insns[pc]>>8)] = d.str(idx)
		case op >= 0x6e && op <= 0x72 && pc+2 < len(insns): // invoke-* 35c
			midx := int(insns[pc+1])
			if midx < len(d.methods) {
				mName := d.str(d.methods[midx].nameIdx)
				if mName == "loadLibrary" || mName == "loadLibrary0" {
					count := int(insns[pc] >> 12)
					unit2 := insns[pc+2]
					args := []int{int(unit2 & 0xf), int((unit2 >> 4) & 0xf), int((unit2 >> 8) & 0xf), int((unit2 >> 12) & 0xf), int((insns[pc] >> 8) & 0xf)}
					// With a single argument there is nothing to order: the
					// register is the low nibble. Runtime.loadLibrary0 takes
					// (Class, String), so the string is picked by shape.
					for i := 0; i < count && i < len(args); i++ {
						if s, ok := regs[args[i]]; ok {
							if count == 1 || len(s) == 0 || s[0] != 'L' {
								cp := s
								return &cp
							}
						}
					}
				}
			}
			reset()
		case op >= 0x74 && op <= 0x78: // invoke-*/range: register ranges
			reset()
		default:
			// Every other instruction may overwrite a register or leave the
			// straight-line path; only a constant set right before the call
			// survives, which is exactly the compiler's shape for this call.
			if op != 0x00 && (op < 0x0a || op > 0x11) {
				reset()
			}
		}
		pc += w
	}
	return nil
}

// learnSideloadName picks the library name for the sideload vector: a name the
// host itself asks for through loadLibrary() and that no lib/<abi>/ directory of
// the APK ships. Those two properties are what make the vector work -- the app
// performs the lookup itself, so nothing has to be started, patched or declared,
// and the lookup already had no answer, so the payload does not displace
// anything the host counted on.
//
// A call site in <clinit>/<init> is preferred: it runs while the class is being
// initialised, which is the closest thing to "runs on startup" that can be read
// off the dex. libNames is the APK's own lib/ listing.
func learnSideloadName(inputAPK string, libNames []string) (string, error) {
	shipped := map[string]bool{}
	for _, n := range libNames {
		shipped[filepath.Base(n)] = true
	}

	names, err := ListNames(inputAPK)
	if err != nil {
		return "", err
	}

	type candidate struct {
		lib, caller, method string
	}
	var cands []candidate
	for _, n := range names {
		if !isDexName(n) {
			continue
		}
		data, err := ReadEntry(inputAPK, n)
		if err != nil {
			return "", err
		}
		calls, err := LoadLibraryCalls(data)
		if err != nil {
			return "", fmt.Errorf("%s: %w", n, err)
		}
		for _, c := range calls {
			lib := "lib" + c.Name + ".so"
			if shipped[lib] {
				// The host ships this one: the lookup already has an answer and
				// the payload would never be reached.
				continue
			}
			cands = append(cands, candidate{lib, c.Caller, c.Method})
		}
	}
	if len(cands) == 0 {
		return "", fmt.Errorf("the host asks for no library it does not ship")
	}

	rank := func(m string) int {
		switch m {
		case "<clinit>":
			return 0
		case "<init>":
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(cands, func(i, j int) bool { return rank(cands[i].method) < rank(cands[j].method) })

	best := cands[0]
	bare := strings.TrimSuffix(strings.TrimPrefix(best.lib, "lib"), ".so")
	fmt.Printf("\t--sideload: %s calls System.loadLibrary(%q) in %s.%s and ships no %s\n",
		filepath.Base(inputAPK), bare, best.caller, best.method, best.lib)
	if len(cands) > 1 {
		fmt.Printf("\t--sideload: %d other unsatisfied names also exist\n", len(cands)-1)
	}
	fmt.Printf("SIDELOAD_TARGET=%s\n", best.lib)
	fmt.Printf("SIDELOAD_CALLER=%s->%s\n", best.caller, best.method)
	return best.lib, nil
}
