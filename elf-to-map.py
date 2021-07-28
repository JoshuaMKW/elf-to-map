import sys
from io import BytesIO
from typing import Dict, Tuple, Type

from elftools.elf.constants import SHN_INDICES
from elftools.elf.elffile import (ELFFile, Section, StringTableSection,
                                  SymbolTableIndexSection, SymbolTableSection)
from elftools.elf.relocation import RelocationSection

from sortedcontainers import SortedDict

symbolFuncPackets: Dict[int, Tuple[str, int]] = SortedDict()
symbolVarPackets: Dict[int, Tuple[str, int]] = SortedDict()


def extract_symbols_from_table(symbolTable: SymbolTableSection, stringTable: StringTableSection):
    if symbolTable.header["sh_entsize"] != 16:
        raise ValueError("Invalid symbol table format (sh_entsize != 16)")
    if not isinstance(stringTable, StringTableSection):
        raise TypeError("String table does not have type SHT_STRTAB")

    for symbol in symbolTable.iter_symbols():
        name = symbol.name
        st_value = symbol["st_value"]
        st_size = symbol["st_size"]
        st_info = symbol["st_info"]
        st_shndx = symbol["st_shndx"]

        if len(name) == 0 or st_shndx == "SHN_UNDEF":
            continue

        if st_info["type"] == "STT_FUNC":
            symbolFuncPackets[st_value] = [name, st_size]
        elif st_info["type"] == "STT_OBJECT":
            symbolVarPackets[st_value] = [name, st_size]


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        elf = ELFFile(BytesIO(f.read()))

    for sect in elf.iter_sections():
        if not isinstance(sect, SymbolTableSection):
            continue

        strTabIdx = sect.header["sh_link"]
        if strTabIdx <= 0 or strTabIdx >= elf.num_sections():
            raise ValueError(f"Invalid strTabIdx {strTabIdx}")

        strTab = elf.get_section(strTabIdx)

        extract_symbols_from_table(sect, strTab)

    with open("dump_map.txt", "w") as f:
        f.write(".text section layout\n  Starting        Virtual\n  address  Size   address\n  -----------------------\n")
        startAddr = 0
        for k, v in symbolFuncPackets.items():
            f.write(f"  {startAddr:08x} {v[1]:06x} {k:08x}  4 {v[0]}\n")
            startAddr += v[1]

        f.write("\n\n")

        f.write(".data section layout\n  Starting        Virtual\n  address  Size   address\n  -----------------------\n")
        startAddr = 0
        for k, v in symbolVarPackets.items():
            f.write(f"  {startAddr:08x} {v[1]:06x} {k:08x}  4 {v[0]}\n")
            startAddr += v[1]
