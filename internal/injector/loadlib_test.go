package injector

import "testing"

// rdMutf8 — декодер строк dex. Тест держит ровно тот баг, который нашёл `go vet`
// и который на ASCII-именах методов был незаметен: сдвиг байта в uint8 терял
// старшие биты, поэтому 2- и 3-байтовые последовательности декодировались молча
// неверно.
func TestRdMutf8(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
		ok   bool
	}{
		{"ascii", []byte("loadLibrary\x00"), "loadLibrary", true},
		{"two-byte", []byte{0xc3, 0xa9, 0x00}, "é", true},
		{"three-byte", []byte{0xe4, 0xb8, 0xad, 0x00}, "中", true},
		{"four-byte-jumbo", []byte{0xf0, 0x9f, 0x98, 0x80, 0x00}, "\U0001f600", true},
		{"nul-in-two-bytes", []byte{0xc0, 0x80, 0x61, 0x00}, "\x00a", true},
		// Неверный UTF-8 не должен ронять декодер: такие байты отдаются как есть.
		{"bad-continuation", []byte{0xc3, 0x28, 0x00}, "\xc3(", true},
		{"no-terminator", []byte("no-nul"), "", false},
	}
	for _, c := range cases {
		got, ok := rdMutf8(c.in, 0)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: rdMutf8(% x) = %q,%v; want %q,%v", c.name, c.in, got, ok, c.want, c.ok)
		}
	}
	if _, ok := rdMutf8([]byte("abc"), 9); ok {
		t.Error("offset past the end must fail")
	}
}
