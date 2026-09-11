package manifest

import (
	"encoding/binary"
	"testing"
)

// buildElement собирает минимальный START_ELEMENT-чанк: 8 байт заголовка чанка,
// lineNumber/comment, ns/name, метаданные атрибутов и сами атрибуты (name = 0,
// rawValue = -1) с заданными индексами имён в пуле.
func buildElement(nameIdxs []int) ([]byte, int) {
	const header = 36 // 8 + 8 + 8 + 12
	buf := make([]byte, header+20*len(nameIdxs))
	binary.LittleEndian.PutUint16(buf[0:], 0x0102)
	binary.LittleEndian.PutUint16(buf[2:], 16)
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(buf)))
	binary.LittleEndian.PutUint16(buf[24:], 20) // attributeStart
	binary.LittleEndian.PutUint16(buf[26:], 20) // attributeSize
	binary.LittleEndian.PutUint16(buf[28:], uint16(len(nameIdxs)))
	for i, idx := range nameIdxs {
		binary.LittleEndian.PutUint32(buf[header+i*20+4:], uint32(idx))
	}
	return buf, header
}

// Атрибут обязан встать на место, сохраняющее сортировку по индексу имени:
// ровно этого требует разбор через resource map, иначе система молча
// игнорирует атрибут (проверено на android:name: PMS отдавал className=null).
func TestAttrInsertOffsetKeepsNameIndexOrder(t *testing.T) {
	base := []int{0, 1, 2, 14, 23}

	cases := []struct {
		name    string
		idxs    []int
		insert  int
		wantPos int // позиция в списке атрибутов, не байтовое смещение
	}{
		{"android:name (3) встаёт после icon (2)", base, 3, 3},
		{"наибольший индекс дописывается в конец", base, 24, 5},
		{"индекс меньше всех встаёт первым", []int{1, 2, 14, 23}, 0, 0},
		{"равный индекс встаёт после равного", base, 14, 4},
		{"пустой элемент", nil, 3, 0},
	}

	for _, c := range cases {
		data, header := buildElement(c.idxs)
		got := attrInsertOffset(data, 0, len(c.idxs), c.insert)
		want := header + c.wantPos*20
		if got != want {
			t.Errorf("%s: offset = %d, ожидалось %d", c.name, got, want)
		}
	}
}

// Ресурс-мап-совместимая проверка: после вставки порядок индексов имён атрибутов
// должен остаться возрастающим.
func TestAttrInsertOffsetProducesSortedList(t *testing.T) {
	idxs := []int{0, 1, 2, 14, 23}
	data, header := buildElement(idxs)
	off := attrInsertOffset(data, 0, len(idxs), 3)

	out := make([]byte, 0, len(data)+20)
	out = append(out, data[:off]...)
	slot := make([]byte, 20)
	binary.LittleEndian.PutUint32(slot[4:], 3) // вставляемый атрибут: name index 3
	out = append(out, slot...)
	out = append(out, data[off:]...)

	for i := 0; i < len(idxs)+1; i++ {
		cur := int(binary.LittleEndian.Uint32(out[header+i*20+4:]))
		if i > 0 {
			prev := int(binary.LittleEndian.Uint32(out[header+(i-1)*20+4:]))
			if cur < prev {
				t.Fatalf("порядок сломан на позиции %d: %d < %d", i, cur, prev)
			}
		}
	}
}
