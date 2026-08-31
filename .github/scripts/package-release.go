package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	libraryPath := flag.String("library", "", "path to the compiled plugin library")
	archivePath := flag.String("archive", "", "path to the output zip archive")
	checksumPath := flag.String("checksum", "", "path to the output checksum file")
	flag.Parse()

	if *libraryPath == "" || *archivePath == "" || *checksumPath == "" {
		fatalf("library, archive, and checksum are required")
	}
	archiveData, errPackage := packageLibrary(*libraryPath, *archivePath)
	if errPackage != nil {
		fatalf("%v", errPackage)
	}
	checksum := sha256.Sum256(archiveData)
	line := fmt.Sprintf("%s  %s\n", hex.EncodeToString(checksum[:]), filepath.Base(*archivePath))
	if errWrite := os.WriteFile(*checksumPath, []byte(line), 0o644); errWrite != nil {
		fatalf("write checksum: %v", errWrite)
	}
}

func packageLibrary(libraryPath, archivePath string) ([]byte, error) {
	library, errOpen := os.Open(libraryPath)
	if errOpen != nil {
		return nil, fmt.Errorf("open library: %w", errOpen)
	}
	defer library.Close()

	info, errStat := library.Stat()
	if errStat != nil {
		return nil, fmt.Errorf("stat library: %w", errStat)
	}
	archive, errCreate := os.Create(archivePath)
	if errCreate != nil {
		return nil, fmt.Errorf("create archive: %w", errCreate)
	}
	defer archive.Close()

	writer := zip.NewWriter(archive)
	header, errHeader := zip.FileInfoHeader(info)
	if errHeader != nil {
		return nil, fmt.Errorf("create zip header: %w", errHeader)
	}
	header.Name = filepath.Base(libraryPath)
	header.Method = zip.Deflate
	header.SetMode(0o755)
	entry, errEntry := writer.CreateHeader(header)
	if errEntry != nil {
		return nil, fmt.Errorf("create zip entry: %w", errEntry)
	}
	if _, errCopy := io.Copy(entry, library); errCopy != nil {
		return nil, fmt.Errorf("copy library: %w", errCopy)
	}
	if errClose := writer.Close(); errClose != nil {
		return nil, fmt.Errorf("close zip writer: %w", errClose)
	}
	if _, errSeek := archive.Seek(0, 0); errSeek != nil {
		return nil, fmt.Errorf("rewind archive: %w", errSeek)
	}
	return io.ReadAll(archive)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
