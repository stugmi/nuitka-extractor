package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/text/encoding/unicode"
)

var verbose = false

func debugf(format string, args ...interface{}) {
	if verbose {
		fmt.Printf("[debug] "+format+"\n", args...)
	}
}

type FileType int

const (
	ELF FileType = iota
	PE
)

type CompressionFlag int

const (
	NON_COMPRESSED CompressionFlag = iota
	COMPRESSED
)

type NuitkaExecutable struct {
	path          string
	fileType      FileType
	fPtr          *os.File
	streamReader  *bufio.Reader
	compressFlag  CompressionFlag
	hasChecksum   bool
	checksumKnown bool
}

func (ne *NuitkaExecutable) New(path string) {
	ne.path = path
}

func (ne *NuitkaExecutable) Check() bool {
	var err error
	ne.fPtr, err = os.Open(ne.path)
	if err != nil {
		fmt.Printf("[!] Couldn't open %s\n", ne.path)
		return false
	}
	fmt.Println("[+] Processing", ne.path)

	// Rudimentary file check logic
	var magic = make([]byte, 4)
	ne.fPtr.Read(magic)
	if magic[0] == 0x4d && magic[1] == 0x5a {
		ne.fileType = PE
		fmt.Println("[+] File type: PE")
	} else if magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46 {
		fmt.Println("[+] File type: ELF")
		ne.fileType = ELF
	} else {
		fmt.Println("[!] Unsupported file type")
		return false
	}

	// Newer Nuitka (onefile_compressor.OnefileCompressor.attachOnefilePayload)
	// appends the payload directly to the end of the bootstrap binary (opened
	// with "ab"), terminated by an 8-byte little endian size. This is still
	// how ELF onefile binaries work. Try that first.
	streamPosition, _ := ne.fPtr.Seek(-8, io.SeekEnd)
	debugf("EOF size field at offset %d", streamPosition)

	var payLoadSize int64
	var payloadSizeBuf = make([]byte, 8)
	ne.fPtr.Read(payloadSizeBuf)
	binary.Read(bytes.NewReader(payloadSizeBuf), binary.LittleEndian, &payLoadSize)
	fmt.Println("[+] Payload size:", payLoadSize, "bytes")

	if payLoadSize > 0 && payLoadSize <= streamPosition {
		payLoadStartPos := streamPosition - payLoadSize
		debugf("Payload start offset (EOF-trailer): %d", payLoadStartPos)
		ne.fPtr.Seek(payLoadStartPos, io.SeekStart)

		var nuitkaMagic = make([]byte, 3)
		ne.fPtr.Read(nuitkaMagic)
		debugf("magic bytes at payload start: %q", nuitkaMagic)

		if nuitkaMagic[0] == 'K' && nuitkaMagic[1] == 'A' && (nuitkaMagic[2] == 'X' || nuitkaMagic[2] == 'Y') {
			ne.compressFlag = NON_COMPRESSED
			if nuitkaMagic[2] == 'Y' {
				ne.compressFlag = COMPRESSED
			}
			fmt.Println("[+] Payload compression:", ne.compressFlag == COMPRESSED)
			return true
		}
	}

	// PE builds with _NUITKA_CONSTANTS_FROM_COFF_OBJ (the modern Windows
	// default) embed the payload as a plain linked-in byte array baked into
	// a PE section (.rdata/.data) rather than appending it after the binary.
	// There's no header pointing at it, so scan for the "KAX"/"KAY" magic.
	if ne.fileType == PE {
		debugf("EOF-trailer lookup failed, scanning file for KA[XY] magic...")

		payloadOffset, compressed := scanForNuitkaMagic(ne.fPtr)
		if payloadOffset >= 0 {
			debugf("Found payload magic at offset %d", payloadOffset)
			ne.fPtr.Seek(payloadOffset, io.SeekStart)

			if compressed {
				ne.compressFlag = COMPRESSED
			} else {
				ne.compressFlag = NON_COMPRESSED
			}
			fmt.Println("[+] Payload compression:", ne.compressFlag == COMPRESSED)
			return true
		}
	}

	fmt.Println("[!] Nuitka magic header mismatch")
	return false
}

// scanForNuitkaMagic searches the file for the "KAX" (uncompressed) or "KAY"
// (zstd compressed) onefile payload header and returns the offset right
// after the 3-byte magic, ready to read/decompress from. Returns -1 if not found.
//
// The first "KAY" hit's zstd frame magic (0x28 0xB5 0x2F 0xFD) right after it
// is used to disambiguate the real payload header from incidental "KAX"/"KAY"
// byte sequences that occur inside already-compressed data.
func scanForNuitkaMagic(f *os.File) (int64, bool) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return -1, false
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return -1, false
	}

	zstdFrameMagic := []byte{0x28, 0xB5, 0x2F, 0xFD}

	searchFrom := 0
	for {
		i := bytes.Index(data[searchFrom:], []byte("KAY"))
		if i == -1 {
			break
		}
		absolute := searchFrom + i
		if absolute+7 <= len(data) && bytes.Equal(data[absolute+3:absolute+7], zstdFrameMagic) {
			return int64(absolute + 3), true
		}
		searchFrom = absolute + 1
	}

	if i := bytes.Index(data, []byte("KAX")); i != -1 {
		return int64(i + 3), false
	}

	return -1, false
}

// looksLikeFileStart reports whether the given bytes look like the start of
// a recognizable file format, used to detect whether the optional 4-byte
// CRC32 checksum field is present before file content in the payload stream.
func looksLikeFileStart(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch {
	case b[0] == 'M' && b[1] == 'Z': // PE/DLL/EXE
		return true
	case b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F': // ELF
		return true
	case b[0] == 'P' && b[1] == 'K': // ZIP-based (whl, jar, etc.)
		return true
	case b[0] == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G': // PNG
		return true
	case b[0] == 0x1F && b[1] == 0x8B: // gzip
		return true
	}
	return false
}

func (ne *NuitkaExecutable) readFileName() string {
	var fileNameBytes []byte
	if ne.fileType == PE {
		buffer := make([]byte, 2)
		for {
			ne.readChunk(buffer)
			if buffer[0] == 0 && buffer[1] == 0 {
				break
			}
			fileNameBytes = append(fileNameBytes, buffer...)
		}
		utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
		fileName, _ := utf16.String(string(fileNameBytes))
		return fileName
	} else {
		buffer := make([]byte, 1)
		for {
			ne.readChunk(buffer)
			if buffer[0] == 0 {
				break
			}
			fileNameBytes = append(fileNameBytes, buffer[0])
		}
		return string(fileNameBytes)
	}
}

func (ne *NuitkaExecutable) dumpFile(fileSize uint64, outpath string) {
	dir := filepath.Dir(outpath)
	os.MkdirAll(dir, 0755)

	f, err := os.Create(outpath)
	if err != nil {
		fmt.Println("[!] Couldn't write", outpath)
		return
	}
	defer f.Close()

	io.CopyN(f, ne.streamReader, int64(fileSize))
}

func (ne *NuitkaExecutable) readChunk(buf []byte) {
	io.ReadFull(ne.streamReader, buf)
}

func (ne *NuitkaExecutable) Extract() {
	if ne.compressFlag == COMPRESSED {
		zr, err := zstd.NewReader(ne.fPtr)
		if err != nil {
			fmt.Println("[!] Couldn't initialize zstd for decompression")
			return
		}
		ne.streamReader = bufio.NewReader(zr)
	} else {
		ne.streamReader = bufio.NewReader(ne.fPtr)
	}

	fmt.Println("[+] Beginning extraction...")
	var extractionDir = ne.path + "_extracted"
	os.MkdirAll(extractionDir, 0755)

	total_files := 0

	for {
		fn := ne.readFileName()
		if fn == "" {
			break
		}

		//https://github.com/Nuitka/Nuitka/blob/develop/nuitka/build/static_src/OnefileBootstrap.c
		//https://github.com/Nuitka/Nuitka/blob/develop/nuitka/tools/onefile_compressor/OnefileCompressor.py
		//https://github.com/Nuitka/Nuitka/blob/develop/nuitka/options/Options.py

		fnNormalized := strings.ReplaceAll(fn, "\\", "/")
		fnNormalized = strings.ReplaceAll(fnNormalized, "..", "__")
		var outpath = filepath.Join(extractionDir, fnNormalized)

		debugf("(%d) entry filename=%q", total_files+1, fn)

		// File flags byte only present on non-Windows builds (readPayloadFileFlagsValue
		// is compiled out under #if !defined(_WIN32) && !defined(__MSYS__)).
		if ne.fileType == ELF {
			var fileFlags = make([]byte, 1)
			ne.readChunk(fileFlags)
			debugf("file_flags=0x%02x", fileFlags[0])

			// Bit 1 (0x02): entry is a symlink, payload holds link target filename
			// instead of file size/checksum/data.
			if fileFlags[0]&0x02 != 0 {
				linkTarget := ne.readFileName()
				debugf("symlink -> %s", linkTarget)
				os.MkdirAll(filepath.Dir(outpath), 0755)
				os.Remove(outpath)
				if err := os.Symlink(linkTarget, outpath); err != nil {
					fmt.Println("[!] Couldn't create symlink", outpath, "->", linkTarget, ":", err)
				}
				total_files += 1
				continue
			}
		}

		var fileSize uint64
		var fileSizeBuffer = make([]byte, 8)
		ne.readChunk(fileSizeBuffer)
		fileSize = binary.LittleEndian.Uint64(fileSizeBuffer)

		// 4 bytes CRC32 checksum, present when extraction is to a permanent
		// (cached) directory rather than a temp one (_NUITKA_ONEFILE_TEMP_BOOL == 0).
		// There's no flag in the payload itself for this, so detect it once
		// from the first non-empty entry by peeking for a known file magic
		// (e.g. "MZ" for PE DLLs) right where content would start.
		if !ne.checksumKnown && fileSize >= 4 {
			peeked, _ := ne.streamReader.Peek(8)
			ne.hasChecksum = !looksLikeFileStart(peeked)
			ne.checksumKnown = true
			debugf("checksum field present: %v", ne.hasChecksum)
		}

		var checksum []byte
		if ne.hasChecksum {
			checksum = make([]byte, 4)
			ne.readChunk(checksum)
		}

		debugf("file_size=%d checksum=%x -> %s", fileSize, checksum, outpath)

		ne.dumpFile(fileSize, outpath)
		total_files += 1
	}
	fmt.Println("[+] Total files:", total_files)
	fmt.Println("[+] Successfully extracted to", extractionDir)
}

func main() {
	args := os.Args[1:]

	var path string
	for _, arg := range args {
		if arg == "-v" || arg == "--verbose" {
			verbose = true
		} else {
			path = arg
		}
	}

	if path == "" {
		fmt.Println("Usage: nuitka-extractor [-v] <filename>")
		return
	}

	ne := NuitkaExecutable{}
	ne.New(path)
	if ne.Check() {
		ne.Extract()
	}
}
