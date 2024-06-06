from typing_extensions import Annotated
from typing import List, Any
import lief
from lief import Binary, Symbol
from alive_progress import alive_bar, alive_it
from pathlib import Path
import multiprocessing
from rich.console import Console
from dataclasses import dataclass
import typer
import random
import math


from ripkit.ripbin import (
    get_functions,
    save_analysis,
    calculate_md5,
    RustFileBundle,
    generate_minimal_labeled_features,
    AnalysisType,
    disasm_at,
    iterable_path_shallow_callback,
)
from ripkit.ripbin.analyzer_types import FunctionInfo

@dataclass
class ModifyPaddingInfo:
    start: int
    end: int
    size: int
    symbol: Symbol


num_cores = multiprocessing.cpu_count()
CPU_COUNT_75 = math.floor(num_cores * (3 / 4))


console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)


def modify_bin_padding(
    binary_path: Path,
    byte_str: List[int],
    output_path: Path,
    follow: List[int],
    verbose: bool = False,
    random_injection: bool = False,
):
    # Load the binary
    binary: Binary = lief.parse(str(binary_path.resolve()))

    # Get functions from the binary using binary_analyzer (does not exclude functions of length 0)
    bin_analysis_functions: list[FunctionInfo] = get_functions(binary_path)

    # Get functions from the binary using symbol table, excluding those that have a size of 0
    modify_functions: list[ModifyPaddingInfo] = []
    for symbol in binary.symbols:
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.size != 0:
            func = ModifyPaddingInfo(symbol.value, symbol.value + symbol.size - 1, symbol.size, symbol)
            modify_functions.append(func)

    # Ensure function counts match (display warning if they don't)
    bin_analysis_functions = [x for x in bin_analysis_functions if x.size != 0]
    if len(bin_analysis_functions) != len(modify_functions):
        console.print(f"[bold yellow][WARNING][/bold yellow] Function identification produced two different counts: "
              f"{len(bin_analysis_functions)} vs {len(modify_functions)}")

    # Sort function addresses
    modify_functions = sorted(modify_functions, key=lambda x: x.start)
    bin_start_addresses = sorted([x.addr for x in bin_analysis_functions])

    # Modify padding following functions with the correct final byte
    for i in range(len(modify_functions) - 1):
        #for i in range(10, len(modify_functions) - 10):
        # Skip functions that were not identified by both methods
        if modify_functions[i].start not in bin_start_addresses:
            console.print(f"[bold yellow][WARNING][/bold yellow] Function at address {modify_functions[i][0]} not identified by both methods (skipped)")
            continue

        # Get end address of current function and start address of next function (to derive padding (patchable bytes))
        end_addr = modify_functions[i].end
        padding_start = end_addr + 1 # end_addr + 1 to get to first padding byte
        next_start = modify_functions[i + 1].start
        patchable_addrs = [x for x in range(padding_start, next_start)]
        patchable_values = binary.get_content_from_virtual_address(padding_start, len(patchable_addrs))

        # Ensure that the last byte of the function is in the follow list (if provided)
        last_byte = binary.get_content_from_virtual_address(end_addr, 1).tolist()[0]
        if (follow != [] and last_byte not in follow):
            if verbose:
                print(f"Skipping padding following function {i} from {modify_functions[i].start} to {modify_functions[i].end}; "
                      f"last byte ({last_byte}) not in: {follow}")
            continue

        # If the random injection option was not selected, use the given byte sequence
        if not random_injection:
            # If the padding is smaller than the chosen byte string, skip
            if len(patchable_addrs) < len(byte_str):
                continue
            # If the padding is equal or greater than the chosen byte string, use as many full repetitions of byte string as possible without overwriting
            else:
                full_byte_strs = len(patchable_addrs) // len(byte_str)
                padding_overwrite = byte_str * full_byte_strs

                if verbose:
                    print(f"Padding (original): {[hex(x) for x in patchable_values]}\n"
                        f"Padding (patched):  {[hex(x) for x in padding_overwrite]}")
                    
                binary.patch_address(padding_start, padding_overwrite)
        
        # Otherwise, use random bytes for the entire length of the padding
        else:
            # Generate padding_overwrite bytes
            padding_overwrite = []
            for i in range(padding_start, next_start):
                padding_overwrite.append(random.randint(0, 255))

            if verbose:
                print(f"Padding (original): {[hex(x) for x in patchable_values]}\n"
                      f"Padding (patched):  {[hex(x) for x in padding_overwrite]}")
                
            binary.patch_address(padding_start, padding_overwrite)
                
    # Save the modified binary
    binary.write(str(output_path.resolve()))
    return

@app.command()
def edit_padding(
    dataset: Annotated[
        str,
        typer.Argument(help="Input dataset", callback=iterable_path_shallow_callback),
    ],
    output_dir: Annotated[str, typer.Argument(help="output dir")],
    bytestring: Annotated[
        str,
        typer.Argument(help="Byte pattern to inject, write in hex separated by comma (90,90: nop,nop for x86-64)"),
    ],
    must_follow: Annotated[
        str, typer.Option(help="What the last byte of a function must be to allow padding modification. Write in hex separated by comma (c3: ret for x86-64)")
    ] = "",
    verbose: Annotated[bool, typer.Option()] = False,
    random_injection: Annotated[bool, typer.Option(help="Overwrite padding with random byte sequences (this option negates bytestring argument)")] = False,
):
    """
    Copy and modify the input dataset. Specifically, modify the padding
    byte preceding functions
    """

    out_path = Path(output_dir)
    if not out_path.exists():
        out_path.mkdir()

    byte_str = [int(x, 16) for x in bytestring.split(",")]
    print(byte_str)

    if must_follow == "":
        follow = []
    else:
        follow = [int(x, 16) for x in must_follow.split(",")]

    for bin in alive_it(dataset):
        modify_bin_padding(bin, byte_str, out_path.joinpath(bin.name), follow, verbose, random_injection)
    return


# def big_brain_modify_padding(bin: Path, out: Path):  # , new_byte:int):
#     """
#     Modify padding byte doing some more sophisticated changes
#     than liefs .patchaddress.

#     Steps:
#     1. Copy the text section contents
#     2. Iterate over bytes and add nops to end of functions
#     3. Re-write binary with new contents

#     """
#     # Load the binary
#     binary = lief.parse(str(bin.resolve()))

#     # Find the .text section
#     text_section = binary.get_section(".text")
#     if text_section is None:
#         print("No .text section found!")
#         return

#     # Retrieve the original .text section content
#     original_text_content = bytearray(text_section.content)

#     # Calculate the base address of the .text section for offset calculations
#     text_base = text_section.virtual_address

#     # Create a new bytearray for the modified content
#     modified_text_content = bytearray()

#     # Initialize last function end offset
#     last_end_offset = 0

#     # Process each symbol (function) in the section
#     for symbol in sorted(binary.symbols, key=lambda x: x.value):
#         if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
#             func_address = symbol.value
#             func_size = symbol.size

#             # Start offset of this function in the .text section
#             start_offset = func_address - text_base
#             end_offset = start_offset + func_size

#             # Append the content up to this function
#             modified_text_content += original_text_content[last_end_offset:start_offset]

#             # Append the function itself
#             modified_text_content += original_text_content[start_offset:end_offset]

#             # Append 4 NOPs
#             modified_text_content += b"\x90\x90\x90\x90"

#             # Update last_end_offset
#             last_end_offset = end_offset

#     # Append any remaining content after the last function
#     modified_text_content += original_text_content[last_end_offset:]

#     # Update the .text section with modified content
#     text_section.content = modified_text_content
#     text_section.size = len(modified_text_content)

#     # Update virtual size if necessary (e.g., for PE files)
#     if hasattr(text_section, "virtual_size"):
#         text_section.virtual_size = len(modified_text_content)

#     # Rebuild the binary
#     builder = lief.ELF.Builder(binary)
#     # builder.build_sections()
#     builder.build()
#     builder.write(str(out.resolve()))

#     return