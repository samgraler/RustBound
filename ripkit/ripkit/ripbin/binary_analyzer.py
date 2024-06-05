"""
This file is responsible for the analyzing of a file and the 
storage of the file and it's analysis
"""

import numpy as np
import polars as pl
from typing import List
from pathlib import Path
import magic
import pefile
from elftools.elf.elffile import ELFFile
from capstone import (
    Cs,
    CS_ARCH_X86,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_32,
    CS_MODE_64,
    CsInsn,
)
from dataclasses import dataclass, asdict, fields
import warnings
from typing import Tuple, Union, Generator
import lief
from .analyzer_types import (
    FunctionInfo,
    binaryFileExecSectionOnly,
    FileType,
    ProgLang,
    ByteInfo,
    RustcOptimization,
    KnownByteInfo_verbose_sql,
    KnownByteInfo_verbose,
    RustcTarget,
    Compiler,
)
from alive_progress import alive_bar
from .ripbin_exceptions import (
    RipbinRegistryError,
    RipbinAnalysisError,
    RipbinDbError,
    AnalysisExistsError,
)


@dataclass
class FoundFunctions:
    addresses: np.ndarray
    names: List[str]
    lengths: np.ndarray


@dataclass
class GroundTruth:
    func_addrs: np.ndarray
    func_lens: np.ndarray
    func_names: List[str]
    num_bytes: int
    text_first_addr: int
    text_last_addr: int


@dataclass
class ConfusionMatrix:
    tp: int
    fp: int
    tn: int
    fn: int


@dataclass
class Metrics:
    prec: float
    recall: float
    f1: float


def calc_metrics(inp: ConfusionMatrix) -> Metrics:
    """
    Return F1, prec, and recall
    """
    if inp.tp == 0:
        return Metrics(0, 0, 0)

    prec = inp.tp / (inp.tp + inp.fp)
    recall = inp.tp / (inp.tp + inp.fn)
    f1 = 2 * ((prec * recall) / (prec + recall))
    return Metrics(prec, recall, f1)


def lief_gnd_truth(bin_path: Path):
    """
    Retrun labels all the functions in the .text section of the
    binary
    """
    bin = lief.parse(str(bin_path.resolve()))

    text_section = bin.get_section(".text")
    text_bytes = text_section.content

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = bin.imagebase

    functions = get_functions(bin_path)

    func_start_addrs = {x.addr: (x.name, x.size) for x in functions}
    func_addrs = []
    func_names = []
    func_lengths = []
    first_addr = base_address + text_section.virtual_address

    # This enumerate the .text byte and sees which ones are functions
    for i, _ in enumerate(text_bytes):
        # The current address is the base image address, plus the text section
        # virtual address plus the current byte in text bytes
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            func_addrs.append(address)
            func_names.append(func_start_addrs[address][0])
            func_lengths.append(func_start_addrs[address][1])

    last_addr = first_addr + len(text_bytes)

    # Return the addrs and names
    func_addrs = np.array(func_addrs)
    func_lens = np.array(func_lengths)
    return GroundTruth(
        func_addrs, func_lens, func_names, len(text_bytes), first_addr, last_addr
    )


def save_func_start_and_length(data: np.ndarray, save_path: Path):
    """
    The ndarray that has:
        | addr: int | length: int |

    This should be used for Ghidra and IDA
    """

    # Make sure the save file has 2 columns, the address and the length
    if data.shape[1] != 2:
        raise Exception

    np.savez_compressed(save_path, data)
    return


def save_every_byte_prob(data: np.ndarray, save_path: Path):
    """
    The ndarray has:
        | byte_val: int | probability of class |

    Where class may be function start or function end

    This should be used for BiRNN
    """
    if data.shape[1] != 2:
        raise Exception
    np.savez_compressed(save_path, data)
    return


def save_three_class_byte_prob(data: np.ndarray, save_path: Path):
    """
    The ndarray has:
        | byte_val: int | prob class1 | prob class2 | prob class 3|
    """
    if data.shape[2] != 3:
        raise Exception

    np.savez_compressed(save_path, data)
    return


def save_raw_experiment_three_prob(
    bin: Path, runtime: float, result_matrix: np.ndarray, base_path: Path
):
    """
    Save numpy data and other info

    base_path: Path
        Directory to save the experiment. Each experiment will make a new
        directory in base_path that will have info.txt and {bin.name}_result.npz
    """

    # Check that the dir exists, and is not a file
    if base_path.exists() and base_path.is_file():
        raise Exception
    elif not base_path.exists():
        base_path.mkdir()

    # Make the sub directory
    sub_dir = base_path.joinpath(bin.name)
    if not sub_dir.exists():
        sub_dir.mkdir()
    elif sub_dir.is_file():
        raise Exception

    # Save the compressed matrix
    matrix_saved = sub_dir.joinpath(f"{bin.name}_result")
    if matrix_saved.exists():
        raise Exception
    save_three_class_byte_prob(result_matrix, matrix_saved)

    # Save the runtime
    runtime_file = sub_dir.joinpath("runtime.txt")
    with open(runtime_file, "w") as f:
        f.write(f"{runtime}")
    return


def save_raw_experiment(
    bin: Path, runtime: float, funcs_and_length: np.ndarray, base_path: Path
):
    """
    Save numpy data and other info

    base_path: Path
        Directory to save the experiment. Each experiment will make a new
        directory in base_path that will have info.txt and {bin.name}_result.npz
    """

    # Check that the dir exists, and is not a file
    if base_path.exists() and base_path.is_file():
        raise Exception
    elif not base_path.exists():
        base_path.mkdir()

    # Make the sub directory
    sub_dir = base_path.joinpath(bin.name)
    if not sub_dir.exists():
        sub_dir.mkdir()
    elif sub_dir.is_file():
        raise Exception

    # Save the compressed matrix
    matrix_saved = sub_dir.joinpath(f"{bin.name}_result")
    if matrix_saved.exists():
        raise Exception

    save_func_start_and_length(funcs_and_length, matrix_saved)

    # Save the runtime
    runtime_file = sub_dir.joinpath("runtime.txt")
    with open(runtime_file, "w") as f:
        f.write(f"{runtime}")
    return


def generate_features(
    path: Path, minimum_func_length, one_hot=True, label_functions=True
) -> Generator[np.ndarray, None, None]:
    """
    Generate npz for given binary
    """

    functions = get_functions(path)

    func_start_addrs = {
        x.addr: (x.name, x.size) for x in functions if x.size > minimum_func_length
    }

    func_end_addrs = {}
    for start, (_, size) in func_start_addrs.items():
        func_end_addrs[start] = start + size - 1

    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    for i, byte in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        func_start = True if address in func_start_addrs.keys() else False
        func_end = True if address in func_end_addrs.keys() else False
        func_middle = True if not func_start and not func_end else False
        if one_hot:
            byte = one_hot_encoding(byte)
            if label_functions:
                yield np.array(
                    [func_start, func_middle, func_end, *byte], dtype=np.bool_
                )
            else:
                yield np.array([*byte])

        else:

            if label_functions:
                yield np.array(
                    [func_start, func_middle, func_end, byte], dtype=np.uint16
                )
            else:
                yield np.array([byte])


def disasm_with(path: Path, start_addr: int, num_bytes: int, res) -> List[str]:
    """
    Disasemble start at the given address
    """

    # but finds the longest one so I can format the output string nicely
    max_len = max(len(" ".join([f"{b:02x}" for b in x.bytes])) for x in res)

    disasm = []

    # Format each byte in the res nicely
    for thing in [
        x
        for x in res
        if x.address >= start_addr and x.address <= start_addr + num_bytes
    ]:

        # if int(thing.address) < start_addr:
        #    continue
        # if int(thing.address) > start_addr + num_bytes:
        #    return disasm

        byte_ar = thing.bytes
        bytes_string = " ".join([f"{b:02x}" for b in byte_ar])
        res_str = f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}"
        disasm.append(res_str)

    return disasm


def disasm_at(path: Path, start_addr: int, num_bytes: int) -> List[str]:
    """
    Disasemble start at the given address
    """

    # Get the generator for the disasm section
    res = lief_disassemble_text_section(path)
    print(f"Got res")

    # NOTICE:
    # -res is a list of CsInsn objects... which are a bit confusing
    #  - Important values in CsInsn are
    #      [id, addr, mnemonic, op_str, size, bytes]
    #  - The bytes value are also odd... it is a byteArray
    #  which looks like byteArray(b'\xo...\'), so a weird wrapper
    #  around a byte object

    # See the below for how the bytes_string is created, this does that
    # but finds the longest one so I can format the output string nicely
    max_len = max(len(" ".join([f"{b:02x}" for b in x.bytes])) for x in res)

    disasm = []

    # Format each byte in the res nicely
    for thing in [
        x
        for x in res
        if x.address >= start_addr and x.address <= start_addr + num_bytes
    ]:

        # if int(thing.address) < start_addr:
        #    continue
        # if int(thing.address) > start_addr + num_bytes:
        #    return disasm

        byte_ar = thing.bytes
        bytes_string = " ".join([f"{b:02x}" for b in byte_ar])
        res_str = f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}"
        disasm.append(res_str)

    return disasm


def lief_get_file_type(path: Path):
    bin = lief.parse(str(path.resolve()))
    return bin.header.machine_type


def get_file_type(file_path: Path) -> FileType:
    """Detect the FileType of the file"""

    # Use the absoltue path
    file_path = file_path.resolve()

    # Load the info for the file
    file_info = magic.from_file(file_path)

    # Check for PE vs ELF
    if "PE" in file_info:
        # Load the
        pe = pefile.PE(file_path)

        # Check the header for the machine type
        # - NOTICE: The below lines will give a type error about machine but its ok
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            return FileType.PE_X86
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            return FileType.PE_X86_64
        else:
            raise Exception(f"No filetype for {file_info}")

    elif "ELF" in file_info:
        # Open the file and read the file header using ELFFile obj
        with open(file_path, "rb") as f:
            elf_file = ELFFile(f)
            header = elf_file.header

            # 'e_machine' will indicate 32bit vs 64bit
            if header["e_machine"].lower() == "em_386":
                return FileType.ELF_X86
            elif header["e_machine"].lower() == "em_x86_64":
                return FileType.ELF_X86_64
            else:
                raise Exception(f"No filetype for {header['e_machine']}")
    elif "MACH":
        # TODO: Handle MACH files
        raise Exception("TODO: Implement MACHO files")
    else:
        raise Exception("File type unknown")


def one_hot_encoding(byte: int) -> list[int]:
    """
    One hot encode bytes 0x00 - 0xFF

    0x00 : < 0, 0, 0, ...>
    0x01: < 1, 0, 0, ...>
    0xFF: < 0,0 ... 1>
    """

    encoding = [0 for x in range(255)]

    # Max index is 254, 0xFF is 255 -1 = 254
    encoding[byte - 1] = 1

    return encoding


def get_capstone_arch_mode(file_type: FileType) -> Tuple[int, int]:
    """Get the corresponding capstone arch and mode for the passed file"""

    match file_type:
        case FileType.PE_X86:
            # mode, arch
            return CS_MODE_32, CS_ARCH_X86
        case FileType.PE_X86_64:
            return CS_MODE_64, CS_ARCH_X86
        case FileType.ELF_X86:
            return CS_MODE_32, CS_ARCH_X86
        case FileType.ELF_X86_64:
            return CS_MODE_64, CS_ARCH_X86
        # TODO: ARM and MACH case?
        case _:
            raise Exception(f"No capstone arch and mode for file of type {file_type}")


def disasm_bytes(path: Path, byts: str):

    # Use lief for parsing!
    parsed_bin = lief.parse(str(path.resolve()))

    if parsed_bin.format is lief.EXE_FORMATS.UNKNOWN:
        estr = f"Cannot parse file format {parsed_bin.format}"
        raise Exception(estr)

    # Get information about the file type
    file_type = get_file_type(path)

    # Get the corresponding modes for the disasembler
    cs_mode, cs_arch = get_capstone_arch_mode(file_type)
    # print(f"File type: {file_type} mode {cs_mode} arch {cs_arch}")

    md = Cs(cs_arch, cs_mode)

    file_type = get_file_type(path)
    cs_mode, cs_arch = get_capstone_arch_mode(file_type)

    return list(md.disasm(byts, parsed_bin.entrypoint))


def lief_disassemble_text_section(path: Path) -> list[CsInsn]:
    """Disasm the file path"""

    # Use lief for parsing!
    parsed_bin = lief.parse(str(path.resolve()))

    if parsed_bin.format is lief.EXE_FORMATS.UNKNOWN:
        estr = f"Cannot parse file format {parsed_bin.format}"
        raise Exception(estr)

    # Get information about the file type
    file_type = get_file_type(path)

    # Get the corresponding modes for the disasembler
    cs_mode, cs_arch = get_capstone_arch_mode(file_type)
    # print(f"File type: {file_type} mode {cs_mode} arch {cs_arch}")

    md = Cs(cs_arch, cs_mode)

    text_section = parsed_bin.get_section(".text")
    file_type = get_file_type(path)
    cs_mode, cs_arch = get_capstone_arch_mode(file_type)

    return list(md.disasm(text_section.content, parsed_bin.entrypoint))


def disassemble_text_section(file_path: Path) -> list[CsInsn]:
    """Disasm the file path"""

    # Get information about the file type
    file_type = get_file_type(file_path)

    # Get the corresponding modes for the disasembler
    cs_mode, cs_arch = get_capstone_arch_mode(file_type)

    # Check file type
    if file_type in [FileType.ELF_X86, FileType.ELF_X86_64]:
        with open(file_path, "rb") as f:
            # Load the text section of the file
            if text_section := ELFFile(f).get_section_by_name(".text"):

                # Define the disasmbler
                disasm = Cs(cs_arch, cs_mode)

                # Get the bytes in the .text section
                code = text_section.data()

                # Disasmble the code and return a a list
                disasm_res = disasm.disasm(code, text_section["sh_addr"])
                return list(disasm_res)
            else:
                raise Exception("Error could not find .text section")

    elif file_type in [FileType.PE_X86, FileType.PE_X86_64]:

        # Load the pe fle
        pe = pefile.PE(file_path)

        # Find the text section
        text_section = None
        for section in pe.sections:
            if section.Name.decode().strip("\x00") == ".text":
                text_section = section
            break
        if text_section is None:
            raise Exception("Could not find text section")

        # The entry point and the VirtualAddress of a given
        # section will be the same
        entry_point = text_section.VirtualAddress

        # Create the disassembler
        disasm = Cs(cs_arch, cs_mode)

        # NOTICE: Comparing the size of
        # text_section.SizeOfRawData and MiscVirtualSize
        # show that padding was added to the end because they
        # were different sizes!!!
        #
        # Took me forever to figure out why I had junk at the end
        # ... so I leave this note for later me
        code = text_section.get_data(ignore_padding=True)

        # Disasm the code
        disasm_res = disasm.disasm(code, entry_point)
        return list(disasm_res)
    else:
        raise Exception(f"Unknown file type: {file_type}")


def get_functions(path: Path) -> List[FunctionInfo]:
    """
    Get the functions in the passed bin file
    """

    parsed_bin = lief.parse(str(path.resolve()))

    if parsed_bin.format == lief.EXE_FORMATS.ELF:
        res = get_elf_functions(path)
    elif parsed_bin.format == lief.EXE_FORMATS.PE:
        res = get_pe_functions(path)
    else:
        raise Exception("File is neither PE or ELF")
    return res


def pretty_print_functions(path):

    parsed_bin = lief.parse(path.resolve().name)
    if parsed_bin.format == lief.EXE_FORMATS.ELF:
        pretty_elf_analyze_functions(path)
    elif parsed_bin.format == lief.EXE_FORMATS.PE:
        res = get_pe_functions(path)
        print(res)
    else:
        raise Exception("File is neither PE or ELF")


def get_pe_functions(path: Path) -> list:
    # Iterate over the PE file's exported functions

    warnings.warn(
        "PE files generated by go sometimes are automatically stripped! Beware!"
    )

    pe = pefile.PE(path)

    function_names = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                function_names.append(exp.name.decode())
    else:
        raise Exception("Error getting symbol information! File may be stripped!")
    return function_names


def get_elf_functions(path: Path, warn_if_stripped: bool = False) -> list[FunctionInfo]:
    """
    Get the functions in an ELF file.
    NOTICE: elffile seems to ignore functions injected by gcc such as
    "register_tm...", "deregister_tm...",
    Therefore those names will be included in the list, but will have
    a size of 0
    """

    with open(path, "rb") as f:
        elf = ELFFile(f)

        # Get the symbol table
        symbol_table = elf.get_section_by_name(".symtab")

        # Get the .text section
        text_section = elf.get_section_by_name(".text")

        if symbol_table is None or text_section is None:
            raise Exception(f"Cannot get functions in file {path}")

        # Create a list of functionInfo objects... symbol_table will give a
        # list of symbols, grab the function symbols and get their name,
        # their 'st_value' which is start addr and size
        functionInfo = [
            FunctionInfo(x.name, x["st_value"], f"0x{x['st_value']:x}", x["st_size"])
            for x in symbol_table.iter_symbols()
            if x["st_info"]["type"] == "STT_FUNC"
        ]

        if functionInfo == [] and warn_if_stripped:
            # TODO: This warning wont make sense when someone is analyzing an
            #   file without knowing if its stripped or not, maybe take out?
            warnings.warn("There is no function info, and expect stripped is off")

    return functionInfo


def objdump_cp(path: Path):
    """
    Copy of object dump using lief
    """

    # Get the generator for the disasm section
    res = lief_disassemble_text_section(path)

    # NOTICE:
    # -res is a list of CsInsn objects... which are a bit confusing
    #  - Important values in CsInsn are
    #      [id, addr, mnemonic, op_str, size, bytes]
    #  - The bytes value are also odd... it is a byteArray
    #  which looks like byteArray(b'\xo...\'), so a weird wrapper
    #  around a byte object

    # See the below for how the bytes_string is created, this does that
    # but finds the longest one so I can format the output string nicely
    max_len = max(len(" ".join([f"{b:02x}" for b in x.bytes])) for x in res)

    # Format each byte in the res nicely
    for thing in res:
        byte_ar = thing.bytes
        bytes_string = " ".join([f"{b:02x}" for b in byte_ar])
        print(
            f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}"
        )

    print(get_file_type(path))
    return


def extract_debug_symbols(file_path: Path):
    """
    Helper function to extract the debug symbols
    """
    try:
        pe = pefile.PE(file_path)

        debug_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]
        ].structs

        for entry in debug_directory:
            if entry.type == pefile.DEBUG_TYPE["IMAGE_DEBUG_TYPE_CODEVIEW"]:
                codeview_entry = pe.parse_debug_directory(entry)
                codeview_symbols = codeview_entry[0].entry
                print(f"CodeView Debug Symbols:\n{codeview_symbols}\n")

            elif entry.type == pefile.DEBUG_TYPE["IMAGE_DEBUG_TYPE_POGO"]:
                pogo_entry = pe.parse_debug_directory(entry)
                print(f"POGO Debug Symbols:\n{pogo_entry}\n")

            # Add more conditions for other debug types if needed

    except pefile.PEFormatError:
        print(f"Invalid or unsupported PE file: {file_path}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def dataclass_pretty_print(some_dataclass) -> None:
    for funcInfo in some_dataclass:
        for field in fields(FunctionInfo):
            print(f"{field.name} = {getattr(funcInfo, field.name)}")


def pretty_elf_analyze_functions(path: Path) -> None:

    res = get_elf_functions(Path(path))

    max_addr_str = max([f"{x.addr:x}" for x in res])

    for funcInfo in res:
        addr_str = f"0x{funcInfo.addr:08x}:"
        print(f"{addr_str}  {funcInfo.name} ")


def generate_minimal_labeled_features(
    path: Path, use_one_hot=True
) -> Generator[np.ndarray, None, None]:
    """
    Generate npy matrix with vectors:
        <isStart, isMiddle, isEnd, byte>
    """
    functions = get_functions(path)

    func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

    func_end_addrs = {}
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start + info[1]] = info[0]

    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    for i, byte in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        func_start = True if address in func_start_addrs.keys() else False
        func_end = True if address in func_end_addrs.keys() else False
        func_middle = True if not func_start and not func_end else False
        if use_one_hot:
            byte = one_hot_encoding(byte)
            yield np.array([func_start, func_middle, func_end, *byte], dtype=np.bool_)
        else:

            yield np.array([func_start, func_middle, func_end, byte], dtype=np.uint16)


def generate_minimal_unlabeled_features(
    path: Path, use_one_hot=True, disp_bar=False
) -> Generator[np.ndarray, None, None]:
    """
    Generate npy matrix with vectors:
        <addr, byte, >
    """

    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    for i, byte in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if use_one_hot:
            byte = one_hot_encoding(byte)
            yield np.array([address, *byte], dtype=np.int32)
        else:

            yield np.array([address, byte], dtype=np.int32)


def POLARS_generate_minimal_unlabeled_features(path: Path, use_one_hot=True):
    """
    Generate npy matrix with vectors:
        <addr, byte, >
    """

    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    # if use_one_hot:
    #    schema={
    #        'address': pl.UInt32,
    #        'byte': pl.List,
    #    }
    # else:
    #    schema={
    #        'address': pl.UInt32,
    #        'byte': pl.Boolean,
    #    }

    # ret_df = pl.DataFrame({
    #    'address':[],
    #    'byte':[],
    # }, schema=schema)

    for i, byte in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if use_one_hot:
            byte = one_hot_encoding(byte)
            yield pl.Series([address, *byte])  # , schema=schema)

            # yield ret_df
            # yield np.array([address, *byte],
            #           dtype=np.int32)
        else:

            yield pl.Series([address, byte])
