from typing_extensions import Annotated
from typing import List, Any
import lief
from lief import Binary
from alive_progress import alive_bar, alive_it
from pathlib import Path
import multiprocessing
from rich.console import Console
import typer
from ripkit.ripkit.ripbin.analyzer_types import FunctionInfo


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

    # TODO: Investigate this function identification process (why do we do it twice?)

    # Get functions from the binary
    my_functions: list[FunctionInfo] = get_functions(binary_path)

    # Get function starts, assuming that all functions are listed in the symbol table
    functions: list[tuple[int, int, int, Any]] = [
        (symbol.value, symbol.value + symbol.size - 1, symbol)
        for symbol in binary.symbols
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.value + symbol.size != 0
    ]

    # Sort function addresses
    functions = sorted(functions, key=lambda x: x[0])

    # Change padding before functions
    for i in range(10, len(functions) - 10):
        # TODO: This relates to the TODO listed above
        if functions[i][0] not in [x.addr for x in my_functions]:
            print("dis agree")

        # Get end address of current function and start address of next function (to derive padding (patchable bytes))
        end_addr = functions[i][1]
        next_start = functions[i + 1][0]
        patchable = [x for x in range(end_addr + 1, next_start)]

        # Ensure that the last byte of the function is the one we want
        last_byte = binary.get_content_from_virtual_address(end_addr, 1).tolist()[0]
        if (last_byte not in follow and follow != []):
            if verbose:
                print(f"Skipping val {last_byte} :: {follow}")
            continue

        # If the random injection option was not selected, use the given byte sequence
        if not random_injection:
            # TODO: fix this check so that any available padding (padding that follows the follow string) can be over written
            if len(patchable) < len(byte_str) or len(patchable) % len(byte_str) != 0:
                continue

            if verbose:
                print(f"Patch on {[hex(x) for x in patchable]}")

            # end_addr + 1 to get to first padding
            for addr in range(end_addr + 1, next_start, len(byte_str)):
                binary.patch_address(addr, byte_str)

        # Otherwise, use random bytes for the entire length of the padding
        else:
            if verbose:
                print(f"Random patch on {[hex(x) for x in patchable]}")

            for addr in range(end_addr + 1, next_start):
                binary.patch_address(addr, [lief.PE.get_random_byte()])
                
    # Save the modified binary
    binary.write(str(output_path.resolve()))
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


@app.command()
def edit_padding(
    dataset: Annotated[
        str,
        typer.Argument(help="Input dataset", callback=iterable_path_shallow_callback),
    ],
    output_dir: Annotated[str, typer.Argument(help="output dir")],
    bytestring: Annotated[
        str,
        typer.Argument(help="Injected Byte, write in hex separated by comma 90,90 "),
    ],
    must_follow: Annotated[
        str, typer.Option(help="Last byte of function must be, hex separated by comma")
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
