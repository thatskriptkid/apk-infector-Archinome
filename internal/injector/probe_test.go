// Диагностика (временная): проверяет минимальный читатель dex и таблицу длин
// инструкций на реальных хостовых файлах. PROBE_APK=<apk> — подробно по одному
// хосту, CORPUS_DIR=<dir> — сводка по всему корпусу.
package injector

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func dexesOf(t *testing.T, apk string) []struct {
	Name string
	Data []byte
} {
	t.Helper()
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var out []struct {
		Name string
		Data []byte
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".dex") || strings.Contains(f.Name, "/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out = append(out, struct {
			Name string
			Data []byte
		}{f.Name, b})
	}
	return out
}

func libsOf(t *testing.T, apk string) map[string]bool {
	t.Helper()
	zr, err := zip.OpenReader(apk)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	m := map[string]bool{}
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "lib/") {
			m[filepath.Base(f.Name)] = true
		}
	}
	return m
}

// scanAPK возвращает (методов, ошибок обхода, все вызовы, необеспеченные имена).
func scanAPK(t *testing.T, apk string, detail int) (int, []string, []LoadLibCall, []string) {
	t.Helper()
	methods := 0
	var walkErrs []string
	var calls []LoadLibCall
	shipped := libsOf(t, apk)
	var unmet []string
	for _, d := range dexesOf(t, apk) {
		md, err := readMinDex(d.Data)
		if err != nil {
			walkErrs = append(walkErrs, d.Name+": read: "+err.Error())
			continue
		}
		for _, cd := range md.classes {
			if cd.dataOff == 0 {
				continue
			}
			md.eachMethod(d.Data, cd.dataOff, func(desc, name string, insns []uint16) {
				methods++
				if err := WalkInsns(insns); err != nil {
					if len(walkErrs) < detail {
						walkErrs = append(walkErrs, fmt.Sprintf("%s %s.%s (%d units): %v", d.Name, desc, name, len(insns), err))
						if os.Getenv("TRACE") != "" {
							fmt.Printf("  trace %s.%s:\n", desc, name)
							traceInsns(insns, 40)
						}
					}
				}
			})
		}
		// Диагностика: есть ли вообще ссылки на loadLibrary в таблице методов
		// и видит ли их обход.
		for _, mm := range md.methods {
			if strings.Contains(md.str(mm.nameIdx), "oadLibrary") {
				fmt.Printf("  ref: %s->%s\n", md.desc(mm.classIdx), md.str(mm.nameIdx))
				break
			}
		}
		cs, err := LoadLibraryCalls(d.Data)
		if err != nil {
			walkErrs = append(walkErrs, d.Name+": scan: "+err.Error())
			continue
		}
		calls = append(calls, cs...)
	}
	for _, c := range calls {
		lib := "lib" + c.Name + ".so"
		if !shipped[lib] {
			unmet = append(unmet, lib+"<-"+c.Caller+"."+c.Method)
		}
	}
	return methods, walkErrs, calls, unmet
}

// traceInsns печатает первые инструкции метода с их длиной — по этому следу
// видно, какая инструкция сдвигает обход.
func traceInsns(insns []uint16, limit int) {
	for pc := 0; pc < len(insns) && pc < limit; {
		w, err := insnWidth(insns, pc)
		op := byte(insns[pc] & 0xff)
		if err != nil {
			fmt.Printf("    pc=%d op=0x%02x unit0=0x%04x -> %v\n", pc, op, insns[pc], err)
			return
		}
		fmt.Printf("    pc=%d op=0x%02x w=%d unit0=0x%04x\n", pc, op, w, insns[pc])
		pc += w
	}
}

func TestProbeLoadLibrary(t *testing.T) {
	apk := os.Getenv("PROBE_APK")
	if apk == "" {
		t.Skip("PROBE_APK не задан")
	}
	methods, errs, calls, unmet := scanAPK(t, apk, 5)
	fmt.Printf("файл=%s методов=%d ошибокОбхода=%d вызовов=%d необеспеченных=%d\n",
		filepath.Base(apk), methods, len(errs), len(calls), len(unmet))
	for _, e := range errs {
		fmt.Printf("  err: %s\n", e)
	}
	for i, c := range calls {
		if i >= 8 {
			break
		}
		fmt.Printf("  call: System.loadLibrary(%q) в %s.%s instant=%v\n", c.Name, c.Caller, c.Method, c.Instant)
	}
	for i, u := range unmet {
		if i >= 8 {
			break
		}
		fmt.Printf("  unmet: %s\n", u)
	}
}

func TestScanCorpus(t *testing.T) {
	dir := os.Getenv("CORPUS_DIR")
	if dir == "" {
		t.Skip("CORPUS_DIR не задан")
	}
	apks, _ := filepath.Glob(filepath.Join(dir, "apk", "*.apk"))
	sort.Strings(apks)
	totalMethods, totalErrs, totalCalls, hostsWithUnmet := 0, 0, 0, 0
	for _, apk := range apks {
		methods, errs, calls, unmet := scanAPK(t, apk, 3)
		totalMethods += methods
		totalErrs += len(errs)
		totalCalls += len(calls)
		if len(unmet) > 0 {
			hostsWithUnmet++
			if len(unmet) > 3 {
				unmet = unmet[:3]
			}
			fmt.Printf("%-45s unmet=%s\n", filepath.Base(apk), strings.Join(unmet, " "))
		}
		for _, e := range errs {
			fmt.Printf("  err %s: %s\n", filepath.Base(apk), e)
		}
	}
	fmt.Printf("итого: хостов=%d методов=%d ошибокОбхода=%d вызовов=%d хостовСНеобеспеченными=%d\n",
		len(apks), totalMethods, totalErrs, totalCalls, hostsWithUnmet)
}
