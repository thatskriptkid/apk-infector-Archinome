import struct

data = open('AndroidManifest.xml', 'rb').read()

def u16(o): return struct.unpack_from('<H', data, o)[0]
def u32(o): return struct.unpack_from('<I', data, o)[0]

CHUNK_NAMES = {
    0x0001: 'STRING_POOL', 0x0003: 'AXML_FILE',
    0x0180: 'RESOURCE_MAP',
    0x0100: 'XML_NS_START', 0x0101: 'XML_NS_END',
    0x0102: 'XML_TAG_START', 0x0103: 'XML_TAG_END', 0x0104: 'XML_TEXT',
}

axml_size = u32(4)
off = 8
strings = {}  # index -> decoded string
resmap = []

# First pass: extract string pool and resource map (they come before XML body)
while off < axml_size:
    t = u16(off); hdr = u16(off+2); size = u32(off+4)
    name = CHUNK_NAMES.get(t, f'UNKNOWN_{t:#x}')
    if t == 0x0001:
        sc = u32(off+8); stylc = u32(off+12); flags = u32(off+16)
        ss = u32(off+20); stys = u32(off+24)
        utf8 = bool(flags & 0x100)
        offs = [u32(off+28+i*4) for i in range(sc)]
        print(f"[{name}] @0x{off:04x} size={size} stringCount={sc} styleCount={stylc} flags={flags:#x} utf8={utf8} stringsStart={ss} stylesStart={stys}")
        for i, so in enumerate(offs):
            sstart = off + ss + so
            if utf8:
                # ResStringPool_string: u16 len, u8 len, data..., null
                l1 = u16(sstart)
                l2 = u16(sstart+2)
                raw = data[sstart+2 : sstart+2+l1]
                s = raw.decode('utf-8', 'replace')
            else:
                l1 = u16(sstart)
                raw = data[sstart+2 : sstart+2+l1*2]
                s = raw.decode('utf-16-le', 'replace')
            strings[i] = s
            print(f"    [{i}] off={so:#x} -> {s!r}")
    elif t == 0x0180:
        count = (size - hdr)//4
        resmap = [u32(off+8+i*4) for i in range(count)]
        print(f"[{name}] @0x{off:04x} resourceIds ({count}):")
        print('    ' + ' '.join(f'{i}:{v:#010x}' for i,v in enumerate(resmap)))
    off += size

print("\n=== XML BODY ===")
off = 8
while off < axml_size:
    t = u16(off); hdr = u16(off+2); size = u32(off+4)
    name = CHUNK_NAMES.get(t, f'UNKNOWN_{t:#x}')
    print(f"\n@0x{off:04x} {name} hdr={hdr} size={size}")
    if t == 0x0100:  # ns start
        print(f"  prefix={u32(off+8)} ({strings.get(u32(off+8),'?')!r}) uri={u32(off+12)} ({strings.get(u32(off+12),'?')!r})")
    elif t == 0x0102:  # tag start
        ns = u32(off+16); nm = u32(off+20)
        attrStart = u16(off+24); attrSize = u16(off+26); attrCount = u16(off+28)
        idIdx = u16(off+30); classIdx = u16(off+32); styleIdx = u16(off+34)
        print(f"  ns={ns} name={nm} ({strings.get(nm,'?')!r}) attrStart={attrStart} attrSize={attrSize} attrCount={attrCount} idIdx={idIdx}")
        for i in range(attrCount):
            a = off + 16 + attrStart + i*attrSize
            ans = u32(a); aname = u32(a+4); araw = u32(a+8)
            tsize = u16(a+12); atype = data[a+15]; adata = u32(a+16)
            aname_str = strings.get(aname, f'<res {aname}>')
            aval = strings.get(adata) if atype == 0x03 else (f'@res{adata:#x}' if atype==0x01 else f'{adata}')
            print(f"    attr[{i}] ns={ans} name={aname}({aname_str!r}) raw={araw} type={atype:#x} data={adata} -> {aval!r}")
    elif t == 0x0103:  # tag end
        print(f"  ns={u32(off+8)} name={u32(off+12)} ({strings.get(u32(off+12),'?')!r})")
    off += size
