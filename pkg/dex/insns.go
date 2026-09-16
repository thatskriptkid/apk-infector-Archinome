package dex

import "fmt"

// Dalvik instruction table.
//
// The writer has to walk the bytecode of every code_item to rewrite the string
// / type / field / method indices that are embedded in instruction operands as
// literals. To iterate the instruction stream it needs the width (in 16-bit
// code units) of every opcode, and to rewrite it needs to know which operand of
// which format holds an index. This is the standard table from
// https://source.android.com/docs/core/runtime/dalvik-bytecode
//
// An index that lives in a 4-byte operand (const-string/jumbo, 31c) is
// remapped in place; 45cc/4rcc additionally carry a proto index.

type indexKind uint8

const (
	ikNone indexKind = iota // no index-bearing operand
	ikString
	ikType
	ikField
	ikMethod
	ikProto
	ikCallSite     // invoke-custom: call_site_id (dex 038+), unsupported
	ikMethodHandle // const-method-handle: method_handle_id, unsupported
)

type insnFormat struct {
	width int       // instruction size in code units
	kind  indexKind // primary index operand
	off   int       // byte offset of the primary index inside the instruction
	size  int       // primary index width in bytes (2 or 4)
	kind2 indexKind // secondary index operand (45cc/4rcc proto)
	off2  int
	size2 int
}

var insnTable = func() [256]insnFormat {
	var t [256]insnFormat
	for i := range t {
		t[i].width = 1 // every undefined opcode reuses 10x
	}
	set := func(from, to int, f insnFormat) {
		for op := from; op <= to; op++ {
			t[op] = f
		}
	}

	// 22x / 22s / 22b / 23x / 22t
	set(0x02, 0x02, insnFormat{width: 2})
	set(0x05, 0x05, insnFormat{width: 2})
	set(0x08, 0x08, insnFormat{width: 2})
	set(0x13, 0x13, insnFormat{width: 2}) // const/16
	set(0x15, 0x15, insnFormat{width: 2}) // const/high16
	set(0x16, 0x16, insnFormat{width: 2}) // const-wide/16
	set(0x19, 0x19, insnFormat{width: 2}) // const-wide/high16
	set(0x29, 0x29, insnFormat{width: 2}) // goto/16
	set(0x2d, 0x31, insnFormat{width: 2}) // cmp*
	set(0x32, 0x37, insnFormat{width: 2}) // if-*
	set(0x38, 0x3d, insnFormat{width: 2}) // if-*/z
	set(0x44, 0x51, insnFormat{width: 2}) // aget/aput
	set(0x90, 0xaf, insnFormat{width: 2}) // binop
	set(0xd0, 0xe2, insnFormat{width: 2}) // binop/lit16 (22s), binop/lit8 (22b)

	// 32x / 31i / 31t / 30t
	set(0x03, 0x03, insnFormat{width: 3})
	set(0x06, 0x06, insnFormat{width: 3})
	set(0x09, 0x09, insnFormat{width: 3})
	set(0x14, 0x14, insnFormat{width: 3}) // const
	set(0x17, 0x17, insnFormat{width: 3}) // const-wide/32
	set(0x26, 0x26, insnFormat{width: 3}) // fill-array-data
	set(0x2a, 0x2a, insnFormat{width: 3}) // goto/32
	set(0x2b, 0x2c, insnFormat{width: 3}) // packed/sparse-switch

	// 21c: const-string, const-class, check-cast, new-instance, sget/sput, ...
	set(0x1a, 0x1a, insnFormat{width: 2, kind: ikString, off: 2, size: 2})
	set(0x1c, 0x1c, insnFormat{width: 2, kind: ikType, off: 2, size: 2})
	set(0x1f, 0x1f, insnFormat{width: 2, kind: ikType, off: 2, size: 2}) // check-cast
	set(0x22, 0x22, insnFormat{width: 2, kind: ikType, off: 2, size: 2}) // new-instance
	set(0x60, 0x6d, insnFormat{width: 2, kind: ikField, off: 2, size: 2})

	// 22c: instance-of, new-array, iget/iput
	set(0x20, 0x20, insnFormat{width: 2, kind: ikType, off: 2, size: 2})
	set(0x23, 0x23, insnFormat{width: 2, kind: ikType, off: 2, size: 2})
	set(0x52, 0x5f, insnFormat{width: 2, kind: ikField, off: 2, size: 2})

	// 35c: filled-new-array, invoke-*
	//
	// The layout is [op|A|G] [BBBB index] [F|E|D|C registers]: the operand is the
	// *second* code unit, the register word the third. Verified against dexdump on
	// a real dex -- for the bytes `6e10 4200 0400` it prints
	// `invoke-virtual {v4}, L...;.isLocked:()Z // method@0042`, i.e. index 0x0042
	// in unit 1 and the register word 0x0004 in unit 2. Reading the operand from
	// the third unit remaps the register list and leaves the real id stale.
	set(0x24, 0x24, insnFormat{width: 3, kind: ikType, off: 2, size: 2})
	set(0x6e, 0x72, insnFormat{width: 3, kind: ikMethod, off: 2, size: 2})

	// 3rc: filled-new-array/range, invoke-*/range
	set(0x25, 0x25, insnFormat{width: 3, kind: ikType, off: 2, size: 2})
	set(0x74, 0x78, insnFormat{width: 3, kind: ikMethod, off: 2, size: 2})

	// 51l: const-wide
	set(0x18, 0x18, insnFormat{width: 5})

	// 31c: const-string/jumbo
	set(0x1b, 0x1b, insnFormat{width: 3, kind: ikString, off: 2, size: 4})

	// dex 038+: invoke-polymorphic / invoke-custom / const-method-*
	set(0xfa, 0xfa, insnFormat{width: 4, kind: ikMethod, off: 2, size: 2, kind2: ikProto, off2: 6, size2: 2})
	set(0xfb, 0xfb, insnFormat{width: 4, kind: ikMethod, off: 2, size: 2, kind2: ikProto, off2: 6, size2: 2})
	set(0xfc, 0xfc, insnFormat{width: 3, kind: ikCallSite, off: 2, size: 2})
	set(0xfd, 0xfd, insnFormat{width: 3, kind: ikCallSite, off: 2, size: 2})
	set(0xfe, 0xfe, insnFormat{width: 2, kind: ikMethodHandle, off: 2, size: 2})
	set(0xff, 0xff, insnFormat{width: 2, kind: ikProto, off: 2, size: 2})

	return t
}()

// Payload pseudo-instruction signatures: the first code unit of an inline data
// blob referenced by fill-array-data / packed-switch / sparse-switch.
//
// The low byte of every signature is 0x00, so a linear walk that only looks at
// the opcode byte reads a payload as nop (width 1) and then decodes the data as
// instructions: it desynchronises within a few code units and either overruns
// the stream (rejecting a valid file) or, worse, rewrites index operands that
// are really payload bytes. Payloads are not instructions; they are skipped by
// length, which is what ART's verifier does too.
const (
	packedSwitchPayload = 0x0100
	sparseSwitchPayload = 0x0200
	arrayDataPayload    = 0x0300
)

// insnExtent returns the number of code units occupied by the item at index i
// of an n-unit stream read through get: the opcode width from insnTable for a
// real instruction, or the full length of an inline payload.
//
//   - packed-switch-payload:  ident u16, size u16, first_key int32,
//     size*4 bytes of targets
//   - sparse-switch-payload:  ident u16, size u16, size*8 bytes of key/target
//   - fill-array-data-payload: ident u16, element_width u16, size u32,
//     size*element_width bytes of elements
//
// The packed payload carries first_key (4 bytes) between the header and the
// target table: forgetting it makes the walk end two code units early and
// reject every method whose packed switch is the last item in the code.
func insnExtent(get func(int) uint16, n, i int) (int, error) {
	switch get(i) {
	case packedSwitchPayload:
		if i+4 > n {
			return 0, fmt.Errorf("dex: packed-switch-payload header runs past the end of the code")
		}
		return 4 + 2*int(get(i+1)), nil
	case sparseSwitchPayload:
		if i+2 > n {
			return 0, fmt.Errorf("dex: sparse-switch-payload header runs past the end of the code")
		}
		return 2 + 4*int(get(i+1)), nil
	case arrayDataPayload:
		if i+4 > n {
			return 0, fmt.Errorf("dex: fill-array-data-payload header runs past the end of the code")
		}
		elementWidth := int(get(i + 1))
		size := int(get(i+2)) | int(get(i+3))<<16
		return 4 + (elementWidth*size+1)/2, nil
	}
	return insnTable[insnOpcode(get(i))].width, nil
}

// insnWidth returns the size of the instruction at insns[pc] in code units.
func insnWidth(unit uint16) int {
	return insnTable[insnOpcode(unit)].width
}

// insnOpcode extracts the opcode of a code unit.
//
// A Dalvik instruction starts at the low byte of its first code unit: the
// opcode is code[0], and the high byte (when the format uses it) carries
// registers -- for 35c it is A(15:12)|G(11:8)|opcode(7:0). The insns array in
// the model holds the on-disk code units, so the opcode is unit&0xff. Reading
// unit>>8 instead picks up the register field and desynchronises every walk of
// the instruction stream (ART: `opcode = inst & 0xff`).
func insnOpcode(unit uint16) uint8 {
	return uint8(unit & 0xff)
}
