// Package wardenbintest builds minimal ELF files for tests.
package wardenbintest

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
)

// ELF returns a minimal ELF64 little-endian file of type typ for machine,
// with one PT_LOAD and, if interp is set, a PT_INTERP (dynamically linked).
func ELF(machine elf.Machine, typ elf.Type, interp bool) []byte {
	nprog := 1
	if interp {
		nprog = 2
	}
	var b bytes.Buffer
	h := elf.Header64{
		Type: uint16(typ), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT),
		Phoff: 64, Ehsize: 64, Phentsize: 56, Phnum: uint16(nprog),
	}
	copy(h.Ident[:], elf.ELFMAG)
	h.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	h.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	h.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	binary.Write(&b, binary.LittleEndian, h)
	binary.Write(&b, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_LOAD), Flags: uint32(elf.PF_R | elf.PF_X)})
	if interp {
		binary.Write(&b, binary.LittleEndian, elf.Prog64{Type: uint32(elf.PT_INTERP), Flags: uint32(elf.PF_R)})
	}
	b.WriteString("payload")
	return b.Bytes()
}

// Static is a static amd64 executable.
func Static() []byte { return ELF(elf.EM_X86_64, elf.ET_EXEC, false) }
