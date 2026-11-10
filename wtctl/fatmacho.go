package main

import (
	"encoding/binary"
	"fmt"
)

// Universal ("fat") Mach-O files: a big-endian header followed by one thin Mach-O per architecture.
// wtctl splits them so each architecture is uploaded as its own file with its own debug id.
const (
	fatMagic   = 0xcafebabe
	fatMagic64 = 0xcafebabf
	// Apple's own heuristic to tell a fat binary from a Java class file (same magic).
	maxFatArchs = 30
)

// machoSlice is one architecture of a fat file.
type machoSlice struct {
	arch string
	data []byte
}

func fatHeader(head []byte) (magic uint32, n uint32, ok bool) {
	if len(head) < 8 {
		return 0, 0, false
	}
	magic, n = binary.BigEndian.Uint32(head), binary.BigEndian.Uint32(head[4:])
	return magic, n, (magic == fatMagic || magic == fatMagic64) && n > 0 && n < maxFatArchs
}

func isThinMachO(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	switch [4]byte(b[:4]) {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xfe, 0xed, 0xfa, 0xcf},
		[4]byte{0xce, 0xfa, 0xed, 0xfe}, [4]byte{0xcf, 0xfa, 0xed, 0xfe}:
		return true
	}
	return false
}

func cpuName(cpu, sub uint32) string {
	switch cpu {
	case 0x01000007:
		return "x86_64"
	case 7:
		return "i386"
	case 0x0100000c:
		if sub&0xffffff == 2 {
			return "arm64e"
		}
		return "arm64"
	case 0x0200000c:
		return "arm64_32"
	case 12:
		return "arm"
	}
	return fmt.Sprintf("cpu%x", cpu)
}

// splitFatMachO cuts a universal binary into its per-architecture slices; ok is false when data is
// not a well-formed fat Mach-O (including a Java class file) so the caller can skip it.
func splitFatMachO(data []byte) (out []machoSlice, ok bool) {
	magic, n, ok := fatHeader(data)
	if !ok {
		return nil, false
	}
	entry := 20 // cputype, cpusubtype, offset, size, align (32-bit fields)
	if magic == fatMagic64 {
		entry = 32 // 64-bit offset and size, plus a reserved word
	}
	seen := map[string]bool{}
	for i := 0; i < int(n); i++ {
		at := 8 + i*entry
		if at+entry > len(data) {
			return nil, false
		}
		e := data[at : at+entry]
		cpu, sub := binary.BigEndian.Uint32(e), binary.BigEndian.Uint32(e[4:])
		var off, size uint64
		if magic == fatMagic64 {
			off, size = binary.BigEndian.Uint64(e[8:]), binary.BigEndian.Uint64(e[16:])
		} else {
			off, size = uint64(binary.BigEndian.Uint32(e[8:])), uint64(binary.BigEndian.Uint32(e[12:]))
		}
		if size == 0 || off > uint64(len(data)) || size > uint64(len(data))-off {
			return nil, false
		}
		sl := data[off : off+size]
		arch := cpuName(cpu, sub)
		if !isThinMachO(sl) || seen[arch] {
			return nil, false
		}
		seen[arch] = true
		out = append(out, machoSlice{arch: arch, data: sl})
	}
	return out, true
}
