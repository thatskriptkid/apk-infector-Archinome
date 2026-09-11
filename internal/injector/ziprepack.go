package injector

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is a brand new archive member.
type Entry struct {
	Name   string
	Data   []byte
	Method uint16 // zip.Store (0) or zip.Deflate (8), honoured verbatim
}

// RepackPlan describes how the source APK is rewritten into the output APK.
//
// Every member that is not mentioned in the plan is streamed through verbatim:
// its name, its compression method and its compressed bytes are copied as they
// are. That is what makes the repack safe for real-world APKs — aab/aapt2
// resource obfuscation produces names that differ only by case (res/HQ.xml and
// res/hq.xml), and any repack that round-trips the archive through a
// case-insensitive filesystem (macOS, Windows) silently drops one of them, which
// makes the patched application crash with Resources$NotFoundException.
type RepackPlan struct {
	Replace   map[string][]byte                       // name -> new content
	Transform map[string]func([]byte) ([]byte, error) // name -> rewritten content
	Rename    map[string]string                       // old name -> new name
	Delete    map[string]bool
	Add       []Entry
}

func NewRepackPlan() RepackPlan {
	return RepackPlan{
		Replace:   map[string][]byte{},
		Transform: map[string]func([]byte) ([]byte, error){},
		Rename:    map[string]string{},
		Delete:    map[string]bool{},
	}
}

// ListNames returns every member name of the archive, in archive order.
func ListNames(srcAPK string) ([]string, error) {
	r, err := zip.OpenReader(srcAPK)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	names := make([]string, 0, len(r.File))
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	return names, nil
}

// ReadEntry returns the uncompressed content of one member.
func ReadEntry(srcAPK, name string) ([]byte, error) {
	r, err := zip.OpenReader(srcAPK)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name == name {
			return readZipFile(f)
		}
	}
	return nil, fmt.Errorf("%s: %s not found", srcAPK, name)
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Repack streams srcAPK into dstAPK applying plan.
func Repack(srcAPK, dstAPK string, plan RepackPlan) error {
	r, err := zip.OpenReader(srcAPK)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", srcAPK, err)
	}
	defer r.Close()

	out, err := os.Create(dstAPK)
	if err != nil {
		return err
	}
	defer out.Close()

	zw := zip.NewWriter(out)
	written := make(map[string]bool, len(r.File))

	for _, f := range r.File {
		if plan.Delete[f.Name] {
			continue
		}
		if fn, ok := plan.Transform[f.Name]; ok {
			data, err := readZipFile(f)
			if err != nil {
				return fmt.Errorf("read %s: %w", f.Name, err)
			}
			data, err = fn(data)
			if err != nil {
				return fmt.Errorf("transform %s: %w", f.Name, err)
			}
			if err := writeEntry(zw, f, f.Name, data); err != nil {
				return err
			}
			written[f.Name] = true
			continue
		}
		if data, ok := plan.Replace[f.Name]; ok {
			if err := writeEntry(zw, f, f.Name, data); err != nil {
				return err
			}
			written[f.Name] = true
			continue
		}
		name := f.Name
		if newName, ok := plan.Rename[f.Name]; ok {
			name = newName
		}
		if err := copyEntryRaw(zw, f, name); err != nil {
			return err
		}
		written[f.Name] = true
	}

	for _, e := range plan.Add {
		if written[e.Name] {
			continue // never shadow an existing member
		}
		// Method is honoured verbatim: zip.Store (0) is the zero value, so
		// coercing it to Deflate would silently compress .so members that must
		// stay stored (extractNativeLibs=false APKs fail to install otherwise:
		// INSTALL_FAILED_INTERNAL_ERROR "Failed to extract native libraries").
		hdr := &zip.FileHeader{Name: e.Name, Method: e.Method}
		hdr.SetMode(0644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return fmt.Errorf("add %s: %w", e.Name, err)
		}
		if _, err := w.Write(e.Data); err != nil {
			return fmt.Errorf("add %s: %w", e.Name, err)
		}
		written[e.Name] = true
	}
	return zw.Close()
}

// writeEntry writes fresh content while keeping the original member's
// compression method (a stored entry must stay stored) and timestamp.
func writeEntry(zw *zip.Writer, src *zip.File, name string, data []byte) error {
	hdr := &zip.FileHeader{Name: name, Method: src.Method, Modified: src.Modified}
	hdr.NonUTF8 = src.NonUTF8
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// copyEntryRaw copies the compressed bytes of an existing member without
// recompressing it, preserving names, methods and CRCs exactly.
func copyEntryRaw(zw *zip.Writer, src *zip.File, name string) error {
	hdr := src.FileHeader
	hdr.Name = name
	w, err := zw.CreateRaw(&hdr)
	if err != nil {
		return copyEntryDecode(zw, src, name)
	}
	rc, err := src.OpenRaw()
	if err != nil {
		return copyEntryDecode(zw, src, name)
	}
	if _, err := io.Copy(w, rc); err != nil {
		return fmt.Errorf("copy %s: %w", name, err)
	}
	return nil
}

// copyEntryDecode is the fallback for members archive/zip cannot hand over
// raw (empty files, unusual headers): decompress and recompress.
func copyEntryDecode(zw *zip.Writer, src *zip.File, name string) error {
	data, err := readZipFile(src)
	if err != nil {
		return fmt.Errorf("copy %s: %w", name, err)
	}
	method := src.Method
	if method != zip.Store && method != zip.Deflate {
		method = zip.Deflate
	}
	hdr := &zip.FileHeader{Name: name, Method: method, Modified: src.Modified}
	hdr.NonUTF8 = src.NonUTF8
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// ExtractSubtree unpacks every member below prefix into dstDir. It refuses to
// run when two members under that prefix collide case-insensitively, because the
// filesystem would silently merge them.
func ExtractSubtree(srcAPK, prefix, dstDir string) ([]string, error) {
	r, err := zip.OpenReader(srcAPK)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	seen := map[string]string{}
	var names []string
	for _, f := range r.File {
		if !strings.HasPrefix(f.Name, prefix) || strings.HasSuffix(f.Name, "/") {
			continue
		}
		key := strings.ToLower(f.Name)
		if prev, ok := seen[key]; ok && prev != f.Name {
			return nil, fmt.Errorf("members %q and %q differ only by case below %s: refusing to unpack", prev, f.Name, prefix)
		}
		seen[key] = f.Name
		names = append(names, f.Name)
	}
	for _, name := range names {
		for _, f := range r.File {
			if f.Name != name {
				continue
			}
			dst := filepath.Join(dstDir, filepath.FromSlash(f.Name))
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return nil, err
			}
			data, err := readZipFile(f)
			if err != nil {
				return nil, err
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return nil, err
			}
		}
	}
	return names, nil
}

// PlanFromDir builds the mutations needed to turn the members listed in
// original (with their content in origData) into the tree rooted at dir.
func PlanFromDir(dir string, original map[string][]byte, plan *RepackPlan, storeExts ...string) error {
	store := func(name string) uint16 {
		for _, ext := range storeExts {
			if strings.HasSuffix(name, ext) {
				return zip.Store
			}
		}
		return zip.Deflate
	}

	onDisk := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		onDisk[filepath.ToSlash(rel)] = path
		return nil
	})
	if err != nil {
		return err
	}

	var added []string
	for rel, path := range onDisk {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		old, existed := original[rel]
		switch {
		case !existed:
			added = append(added, rel)
			plan.Add = append(plan.Add, Entry{Name: rel, Data: data, Method: store(rel)})
		case !bytes.Equal(old, data):
			plan.Replace[rel] = data
		}
	}
	sort.Strings(added)
	for _, rel := range added {
		_ = rel
	}

	for rel := range original {
		if _, ok := onDisk[rel]; !ok {
			plan.Delete[rel] = true
		}
	}
	return nil
}

// DeflateData compresses data with the default flate settings; used by callers
// that need to embed a blob with an explicit method.
func DeflateData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
