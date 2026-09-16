// Диагностика (временная): ищет хосты, которые обращаются к классам, отсутствующим
// в самом APK (кандидаты вектора «provide missing class» — payload исполняется из
// <clinit>/метода класса, который поставляет наш dex, без правки хостового dex и
// манифеста).
package injector

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// isPlatformPrefix отсекает пространства имён, которые поставляет платформа (или
// которые почти всегда упакованы в само приложение): их подменять нельзя.
var platformPrefixes = []string{
	"Landroid/", "Ljava/", "Ljavax/", "Ldalvik/", "Ljunit/", "Llibcore/", "Lsun/",
	"Lorg/apache/", "Lorg/json/", "Lorg/w3c/", "Lorg/xml/", "Lorg/xmlpull/",
	"Lorg/kxml2/", "Lorg/ietf/", "Lorg/bouncycastle/", "Lorg/conscrypt/",
	"Lcom/android/", "Lkotlin/", "Lorg/jetbrains/", "Lorg/intellij/",
}

func isPlatform(desc string) bool {
	for _, p := range platformPrefixes {
		if strings.HasPrefix(desc, p) {
			return true
		}
	}
	return false
}

func TestScanProvidedClass(t *testing.T) {
	dir := os.Getenv("CORPUS_DIR")
	if dir == "" {
		t.Skip("CORPUS_DIR не задан")
	}
	apks, _ := filepath.Glob(filepath.Join(dir, "apk", "*.apk"))
	if len(apks) == 0 {
		t.Skipf("нет apk в %s/apk", dir)
	}
	hosts, total := 0, 0
	for _, apk := range apks {
		pkg := strings.TrimSuffix(filepath.Base(apk), ".apk")
		blobs, err := readAllDexes(apk)
		if err != nil {
			t.Logf("%s: %v", pkg, err)
			continue
		}
		defined := map[string]bool{}
		var tables []*minDex
		for _, b := range blobs {
			md, err := readMinDex(b)
			if err != nil {
				continue
			}
			tables = append(tables, md)
			for _, c := range md.classes {
				defined[md.desc(c.classIdx)] = true
			}
		}
		refs := map[string]string{}
		for bi, md := range tables {
			for _, cl := range md.classes {
				if cl.dataOff == 0 {
					continue
				}
				caller := md.desc(cl.classIdx)
				md.eachMethod(blobs[bi], cl.dataOff, func(_ string, mname string, insns []uint16) {
					for pc := 0; pc < len(insns); {
						w, err := insnWidth(insns, pc)
						if err != nil {
							return
						}
						switch insns[pc] & 0xff {
						case 0x71: // invoke-static: инициализирует класс-владелец
							idx := int(insns[pc+1])
							if idx < len(md.methods) {
								cls := md.desc(md.methods[idx].classIdx)
								if !isPlatform(cls) {
									if _, ok := refs[cls]; !ok {
										refs[cls] = "invoke-static " + caller + "." + mname
									}
								}
							}
						case 0x22: // new-instance: инициализирует при <init>
							cls := md.desc(uint32(insns[pc+1]))
							if !isPlatform(cls) {
								if _, ok := refs[cls]; !ok {
									refs[cls] = "new-instance " + caller + "." + mname
								}
							}
						}
						pc += w
					}
				})
			}
		}
		var missing []string
		for cls, how := range refs {
			if !defined[cls] {
				missing = append(missing, cls+" <- "+how)
			}
		}
		if len(missing) > 0 {
			hosts++
			total += len(missing)
			sort.Strings(missing)
			shown := missing
			if len(shown) > 4 {
				shown = shown[:4]
			}
			t.Logf("%-45s кандидатов=%d; %s", pkg, len(missing), strings.Join(shown, "; "))
		}
	}
	t.Logf("ИТОГО: хостов с кандидатами %d из %d, кандидатов %d", hosts, len(apks), total)
}

// readAllDexes возвращает содержимое всех classes*.dex внутри APK.
func readAllDexes(apk string) ([][]byte, error) {
	rc, err := zip.OpenReader(apk)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var out [][]byte
	for _, f := range rc.File {
		if !isDexName(f.Name) {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, data)
	}
	return out, nil
}
