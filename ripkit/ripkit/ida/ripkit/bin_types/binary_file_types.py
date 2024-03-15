"""
Enums and dataclasses for cargo_automation files
"""
from enum import Enum
from pathlib import Path

class RegBit(Enum):
    X86 = "x86"
    X64 = "x64"

class FileFormat(Enum):
    PE = "pe"
    ELF = "elf"


# TODO: MACH - 0

#class FileType(Enum):
#    ''' File type enums '''
#    # @TODO: Add MACH-0 support
#    # @TODO: NOTICE: lief has its own file types but doesn't differenciate
#    #         64bit and 32bit
#    PE_X86 = "pe_x86"
#    PE_X86_64 = "pe_x86_64"
#    ELF_X86 = "elf_x86"
#    ELF_X86_64 = "elf_x86_64"

