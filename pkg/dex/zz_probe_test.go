// Диагностика (временная) внутри pkg/dex: где именно Parse расходится с
// реальным хостовым dex. DEX_PATH=<файл classesN.dex>.
package dex

import (
	"encoding/binary"
	"fmt"
	"os"
	"testing"
)

func TestProbeParse(t *testing.T) {
	path := os.Getenv("DEX_PATH")
	if path == "" {
		t.Skip("DEX_PATH не задан")
	}
	d, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(d[off:]) }
	strSize, strOff := u32(0x38), u32(0x3c)
	typeSize, typeOff := u32(0x40), u32(0x44)
	cdSize, cdOff := u32(0x60), u32(0x64)
	fmt.Printf("файл=%s размер=%d строк=%d(%#x) типов=%d(%#x) class_defs=%d(%#x)\n",
		path, len(d), strSize, strOff, typeSize, typeOff, cdSize, cdOff)

	for i := 0; i < 8 && uint32(i) < cdSize; i++ {
		base := int(cdOff) + 32*i
		fmt.Printf("  class_def[%d] class=%d super=%d ifaces=%#x src=%d ann=%#x data=%#x static=%#x\n",
			i, u32(base), u32(base+8), u32(base+12), u32(base+16), u32(base+20), u32(base+24), u32(base+28))
		// что лежит по class_data_off с точки зрения сырых uleb128
		if off := u32(base + 24); off != 0 && int(off) < len(d) {
			b := d[off : off+12]
			fmt.Printf("      байты по data_off: % x\n", b)
		}
	}

	f, err := Parse(d)
	if err != nil {
		fmt.Printf("Parse -> %v\n", err)
		if f != nil {
			fmt.Printf("  частично: строк=%d типов=%d классов=%d\n", len(f.Strings), len(f.Types), len(f.Classes))
		}
		return
	}
	fmt.Printf("Parse OK: строк=%d типов=%d методов=%d классов=%d\n",
		len(f.Strings), len(f.Types), len(f.Methods), len(f.Classes))
	methods := 0
	for _, c := range f.Classes {
		if c.ClassData == nil {
			continue
		}
		methods += len(c.ClassData.DirectMethods) + len(c.ClassData.VirtualMethods)
	}
	fmt.Printf("  методов с class_data: %d\n", methods)
	out, err := f.Encode()
	if err != nil {
		fmt.Printf("  Encode -> %v\n", err)
		return
	}
	fmt.Printf("  Encode OK: %d байт (было %d)\n", len(out), len(d))
}
