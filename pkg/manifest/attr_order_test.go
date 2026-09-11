package manifest

import (
	"encoding/binary"
	"testing"
)

// buildElement собирает минимальный START_ELEMENT-чанк: 8 байт заголовка чанка,
// lineNumber/comment, ns/name, метаданные атрибутов и сами атрибуты (rawValue = -1)
// с заданными полями name.
func buildElement(nameFields []uint32) ([]byte, int) {
	const header = 36 // 8 + 8 + 8 + 12
	buf := make([]byte, header+20*len(nameFields))
	binary.LittleEndian.PutUint16(buf[0:], 0x0102)
	binary.LittleEndian.PutUint16(buf[2:], 16)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[24:], 20) // attributeStart
	binary.LittleEndian.PutUint16(buf[26:], 20) // attributeSize
	binary.LittleEndian.PutUint16(buf[28:], uint16(len(nameFields)))
	for i, nf := range nameFields {
		binary.LittleEndian.PutUint32(buf[header+i*20+4:], nf)
	}
	return buf, header
}

// buildManifest собирает мини-манифест: 8-байтный заголовок файла, карта
// ресурсов (chunk 0x0180: индекс имени атрибута -> resource ID, как пишет aapt2)
// и один START_ELEMENT.
func buildManifest(resIDs []uint32, nameFields []uint32) (data []byte, elemStart, attrBase int) {
	resMap := make([]byte, 8+4*len(resIDs))
	binary.LittleEndian.PutUint16(resMap[0:], chunkResourceIds)
	binary.LittleEndian.PutUint16(resMap[2:], 8)
	binary.LittleEndian.PutUint32(resMap[4:], uint32(len(resMap)))
	for i, id := range resIDs {
		binary.LittleEndian.PutUint32(resMap[8+i*4:], id)
	}
	elem, hdr := buildElement(nameFields)
	total := 8 + len(resMap) + len(elem)
	out := make([]byte, 8, total)
	binary.LittleEndian.PutUint16(out[0:], 0x0003) // RES_XML_TYPE
	binary.LittleEndian.PutUint16(out[2:], 8)
	binary.LittleEndian.PutUint32(out[4:], uint32(total))
	out = append(out, resMap...)
	elemStart = len(out)
	out = append(out, elem...)
	return out, elemStart, elemStart + hdr
}

// Реальные resource ID из android-неймспейса.
const (
	idTheme     = 0x01010000
	idLabel     = 0x01010001
	idIcon      = 0x01010002
	idName      = 0x01010003
	idAllowBack = 0x01010280
	idExtract   = 0x010104ea
	idAppCF     = 0x0101057a
	idReqLegacy = 0x01010603
	idDataExtr  = 0x0101063e
)

// Атрибут обязан встать так, чтобы список остался отсортирован по resource ID:
// libandroidfw ищет атрибут бинарным поиском по ID, разрешённым через карту
// ресурсов. Сортировка по сырому name-полю (индексу пула) совпадает с ней лишь
// случайно — на этом ломался V6/V8 у хостов с requestLegacyExternalStorage.
func TestAttrInsertOffsetKeepsResIDOrder(t *testing.T) {
	// <application> из org.billthefarmer.editor: последним идёт атрибут с ID
	// больше, чем у appComponentFactory.
	editor := []uint32{idTheme, idLabel, idIcon, idAllowBack, idExtract, idReqLegacy}
	// Хост, где appComponentFactory — самый старший ID.
	gurgle := []uint32{idTheme, idLabel, idIcon, idAllowBack, idExtract}

	cases := []struct {
		name    string
		resIDs  []uint32
		fields  []uint32
		wantID  uint32
		wantPos int
	}{
		{"appComponentFactory встаёт перед requestLegacyExternalStorage", editor, []uint32{0, 1, 2, 3, 4, 5}, idAppCF, 5},
		{"appComponentFactory дописывается в конец, если он старший", gurgle, []uint32{0, 1, 2, 3, 4}, idAppCF, 5},
		{"android:name встаёт после icon, перед allowBackup", editor, []uint32{0, 1, 2, 3, 4, 5}, idName, 3},
		{"ID больше всех остальных — в конец", editor, []uint32{0, 1, 2, 3, 4, 5}, idDataExtr, 6},
		{"пустой элемент", []uint32{idTheme}, nil, idAppCF, 0},
	}

	for _, c := range cases {
		data, elemStart, base := buildManifest(c.resIDs, c.fields)
		got := attrInsertOffset(data, elemStart, len(c.fields), c.wantID)
		want := base + c.wantPos*20
		if got != want {
			t.Errorf("%s: offset = %d, ожидалось %d (позиция %d)", c.name, got, want, c.wantPos)
		}
	}
}

// После вставки порядок разрешённых через карту ресурсов ID должен остаться
// возрастающим, иначе PMS молча игнорирует атрибут.
func TestAttrInsertOffsetProducesSortedResIDList(t *testing.T) {
	resIDs := []uint32{idTheme, idLabel, idIcon, idAllowBack, idExtract, idReqLegacy, idAppCF}
	fields := []uint32{0, 1, 2, 3, 4, 5}
	data, elemStart, base := buildManifest(resIDs, fields)
	off := attrInsertOffset(data, elemStart, len(fields), idAppCF)

	out := make([]byte, 0, len(data)+20)
	out = append(out, data[:off]...)
	slot := make([]byte, 20)
	binary.LittleEndian.PutUint32(slot[4:], 6) // новый атрибут: индекс пула 6
	out = append(out, slot...)
	out = append(out, data[off:]...)

	ids, _, _ := readResMap(out)
	prev := uint32(0)
	for i := 0; i < len(fields)+1; i++ {
		raw := binary.LittleEndian.Uint32(out[base+i*20+4:])
		cur := attrNameResID(ids, raw)
		if i > 0 && cur < prev {
			t.Fatalf("порядок ID сломан на позиции %d: 0x%08x < 0x%08x", i, cur, prev)
		}
		prev = cur
	}
}

// attrNameResID: значение внутри карты ресурсов — индекс пула, вне её — уже
// готовый resource ID (так пишут некоторые упаковщики).
func TestAttrNameResID(t *testing.T) {
	ids := []uint32{idTheme, idLabel, 0, idReqLegacy}
	if got := attrNameResID(ids, 0); got != idTheme {
		t.Errorf("индекс пула 0 -> 0x%08x, ожидалось 0x%08x", got, idTheme)
	}
	if got := attrNameResID(ids, 2); got != 2 {
		t.Errorf("пустая запись карты должна вернуть сырое значение, получено 0x%08x", got)
	}
	if got := attrNameResID(ids, idAppCF); got != idAppCF {
		t.Errorf("literal resource ID не должен подменяться, получено 0x%08x", got)
	}
	if got := attrNameResID(nil, 7); got != 7 {
		t.Errorf("без карты ресурсов ожидалось сырое значение, получено 0x%08x", got)
	}
}
