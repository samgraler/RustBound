from typing_extensions import Annotated
from typing import List, Any
import lief
from lief import Binary, Symbol, Section
from alive_progress import alive_bar, alive_it
from pathlib import Path
from multiprocessing import cpu_count, Pool, Lock
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
    name: str

num_cores = cpu_count()
CPU_COUNT_75 = math.floor(num_cores * (3 / 4))

console = Console()
console.width = console.width - 10 # fixes some output issues caused by alive_it progress output "on 0: ", "on 1: ", etc.
app = typer.Typer(pretty_exceptions_show_locals=False)

# Function to convert a single digit hex number to a two digit hex number (for cleaner output)
def custom_hex(num : int):
    hex_string = hex(num)
    if len(hex_string) == 3:  # Single digit hex number
        return hex_string[:2] + '0' + hex_string[2]  # Insert '0' before the single digit
    else:
        return hex_string


# Function to update the progress bar when a worker completes its task
def update_progress(result, bar):
    bar()

# init function to allow for global lock variable to be passed to the workers
def init(l):
    global lock
    lock = l

def lock_print(msg):
    lock.acquire()
    console.print(msg)
    lock.release()

@app.command()
def edit_padding(
    dataset_dir: Annotated[
        str,
        typer.Argument(help="Input dataset directory", callback=iterable_path_shallow_callback),
    ],
    output_dir: Annotated[str, typer.Argument(help="Output directory")],
    bytestring: Annotated[
        str,
        typer.Argument(help="Byte pattern to inject, write in hex separated by comma (e.g. 90,90: nop,nop for x86-64)"),
    ],
    must_follow: Annotated[
        str, typer.Option(help="What the last byte of a function must be to allow padding modification. Write in hex separated by commas (e.g. c3,00,ff)")
    ] = "",
    verbose: Annotated[bool, typer.Option()] = False,
    random_injection: Annotated[bool, typer.Option(help="Overwrite padding with random byte sequences (this option negates bytestring argument)")] = False,
    num_workers: Annotated[int, typer.Option(help="Number of workers to use for multiprocessing", show_default=True)] = CPU_COUNT_75,
):
    """
    Modify the padding bytes of the input dataset (preserving functionality), and write to the output directory. 
    
    Manual inspection of the modified binaries is recommended to ensure functionality is preserved.
    """

    # Example usage:
    # python ripkit/main.py modify edit-padding --random-injection ~/modify_test_input/ ~/modify_test_output/ 00
    # Test executable files with
    # ~/modify_test_output/<file> --help
    # View differences in files using objdump / diff
    # objdump -D ~/modify_test_input/<file> > /tmp/<file>_dump_orig
    # objdump -D ~/modify_test_output/<file> > /tmp/<file>_dump_mod
    # diff -y /tmp/<file>_dump_orig /tmp/<file>_dump_mod > /tmp/<file>_mod_diff

    out_path = Path(output_dir)
    if not out_path.exists():
        out_path.mkdir()

    byte_str = [int(x, 16) for x in bytestring.split(",")]

    if must_follow == "":
        follow = []
    else:
        follow = [int(x, 16) for x in must_follow.split(",")]

    # Create a list of arguments for the multiprocessing pool
    args = []
    for bin in dataset_dir:
        args.append((bin, byte_str, out_path.joinpath(bin.name), follow, verbose, random_injection))

    # Handle improper num_workers input
    if num_workers > CPU_COUNT_75:
        num_workers = CPU_COUNT_75
    elif num_workers < 1:
        num_workers = 1
    
    # Process the binaries in parallel
    l = Lock()
    pool = Pool(processes=num_workers, initializer=init, initargs=(l,))
    with alive_bar(len(args), title="Modifying padding") as bar:
        results = []
        # Use pool.apply_async to execute the worker_function with the tasks
        for arg in args:
            result = pool.apply_async(modify_bin_padding, args=(arg,), callback=lambda x: update_progress(x, bar))
            results.append(result)
        # Wait for all results to complete
        for result in results:
            result.wait()
    pool.close()
    pool.join()

    # Process the binaries sequentially (for debugging)
    # for arg in args:
    #     modify_bin_padding(arg)
    
    # Process modification results (across entire dataset)
    tot_func_modify, tot_total_func, tot_byte_write, tot_total_byte, tot_duplicate, tot_back_to_back, tot_zero_size, tot_skipped = 0, 0, 0, 0, 0, 0, 0, 0
    for result in results:
        func_modify, total_func, byte_write, total_byte, duplicate, back_to_back, zero_size, skipped = result.get()
        tot_func_modify += func_modify
        tot_total_func += total_func
        tot_byte_write += byte_write
        tot_total_byte += total_byte
        tot_duplicate += duplicate
        tot_back_to_back += back_to_back
        tot_zero_size += zero_size
        tot_skipped += skipped
    
    # Format output
    output = "-" * console.width + "\n"
    output += f"[bold magenta]Dataset Modification Statistics:[/bold magenta]\n" 
    output += "-" * console.width + "\n"
    output += f"[bold green]Function padding sections modified: [/bold green]{(tot_func_modify / tot_total_func * 100):.4f}% ({tot_func_modify} of {tot_total_func})\n"
    output += f"[bold green]     Back-to-back functions:        [/bold green]{tot_back_to_back}\n"
    output += f"[bold green]     Duplicate functions:           [/bold green]{tot_duplicate}\n"
    output += f"[bold green]     Zero-size functions:           [/bold green]{tot_zero_size}\n"
    output += f"[bold green]     Skipped functions:             [/bold green]{tot_skipped}\n"
    output += f"[bold green]Bytes (over)written:                [/bold green]{(tot_byte_write / tot_total_byte * 100):.4f}% ({tot_byte_write} of {tot_total_byte})\n"
    output += "-" * console.width
    console.print(output)
    return


def modify_bin_padding(
    args: tuple[Path, List[int], Path, List[int], bool, bool]
) -> tuple[int, int, int, int, int, int, int, int]:
    # Unpack arguments
    binary_path = args[0]
    byte_str = args[1]
    output_path = args[2]
    follow = args[3]
    verbose = args[4]
    random_injection = args[5]

    # Variable to hold output for the worker function (to be printed at the end of the function with the lock acquired)
    full_output = "\n"
    full_output += "-" * console.width + "\n"
    full_output += f"[bold cyan]Modifying Binary: {binary_path}[/bold cyan]\n"
    full_output += "-" * console.width + "\n"

    # Load the binary
    binary: Binary = lief.parse(str(binary_path.resolve()))

    # Get functions from the binary using binary_analyzer (does not exclude functions of length 0)
    bin_analysis_functions: list[FunctionInfo] = get_functions(binary_path)

    # Get functions from the binary using symbol table, excluding those that have a size of 0, and those that are not in the (a) text section
    # Find the .text section(s) start and end addresses
    text_sections: list[Section] = [section for section in binary.sections if section.name == ".text"]
    text_start = [section.virtual_address for section in text_sections]
    text_end = [section.virtual_address + section.size for section in text_sections]

    modify_functions: list[ModifyPaddingInfo] = []
    for symbol in binary.symbols:
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
            for i in range(len(text_start)):
                # Verify that the function symbol is within a text section
                if text_start[i] <= symbol.value < text_end[i]:
                    func = ModifyPaddingInfo(symbol.value, symbol.value + symbol.size - 1, symbol.size, symbol, symbol.name)
                    modify_functions.append(func)
                    break

    # Ensure function counts match (display warning if they don't)
    bin_analysis_functions = [x for x in bin_analysis_functions if x.size != 0]
    if len(bin_analysis_functions) != len(modify_functions):
        if verbose:
            full_output += f"[bold yellow][WARNING][/bold yellow] Function identification produced two different counts: {len(bin_analysis_functions)} vs {len(modify_functions)}\n"

    # Sort function addresses
    modify_functions = sorted(modify_functions, key=lambda x: x.start)
    bin_start_addresses = sorted([x.addr for x in bin_analysis_functions])
    
    func_modify_count, byte_write_count, duplicate_count, back_to_back_count, zero_size_count, skipped = 0, 0, 0, 0, 0, 0

    # Modify padding
    for i in range(len(modify_functions) - 1):
        # Check for functions that were not identified by both methods
        if modify_functions[i].start not in bin_start_addresses:
            if verbose:
                full_output += f"[bold yellow][WARNING][/bold yellow]: Function at address {modify_functions[i].start} ({modify_functions[i].name}) not identified by both methods\n"

        # Check to ensure function has a non-zero size
        if modify_functions[i].size == 0:
            zero_size_count += 1
            if verbose:
                full_output += f"[yellow]Skipping padding[/yellow]; Function at address {modify_functions[i].start} ({modify_functions[i].name}) has a size of 0\n"
            continue

        # Get end address of current function and start address of next function (to derive padding (patchable bytes))
        end_addr = modify_functions[i].end
        padding_start = end_addr + 1 # end_addr + 1 to get to first padding byte
        next_start = modify_functions[i + 1].start
        patchable_addrs = [x for x in range(padding_start, next_start)]

        # Check for duplicate function entries and functions with no padding between them and the next function
        if padding_start == next_start:
            back_to_back_count += 1
            if verbose:
                full_output += f"[blue]Function {i}: {modify_functions[i].start} - {modify_functions[i].end}[/blue] [red](no padding following this function)[/red]\n"
            continue
        elif padding_start > next_start:
            duplicate_count += 1
            if verbose:
                full_output += f"[blue]Function {i}: {modify_functions[i].start} - {modify_functions[i].end}[/blue] [red](duplicate entry)[/red]\n"
            continue
        else:
            if verbose:
                full_output += f"[cyan]Function {i}: {modify_functions[i].start} - {modify_functions[i].end}[/cyan] [magenta](padding: {padding_start} - {next_start})[/magenta]\n"

        # Ensure that the last byte of the function is in the follow list (if provided)
        last_byte = binary.get_content_from_virtual_address(end_addr, 1).tolist()[0]
        if (follow != [] and last_byte not in follow):
            if verbose:
                full_output += f"[yellow]Skipping padding[/yellow]; last byte ({last_byte}) not in: {follow}\n"
            continue

        # If the random injection option was not selected, use the given byte sequence
        if not random_injection:
            # If the padding is smaller than the chosen byte string, skip
            if len(patchable_addrs) < len(byte_str):
                skipped += 1
                if verbose:
                    full_output += f"[yellow]Skipping padding[/yellow]; padding size ({len(patchable_addrs)}) is smaller than byte string size ({len(byte_str)})\n"
                continue
            # If the padding is equal or greater than the chosen byte string, use as many full repetitions of byte string as possible without overwriting
            else:
                if verbose:
                    full_output += f"Padding (original): {[custom_hex(x) for x in binary.get_content_from_virtual_address(padding_start, len(patchable_addrs))]}\n"
                          
                full_byte_strs = len(patchable_addrs) // len(byte_str)
                padding_overwrite = byte_str * full_byte_strs
                binary.patch_address(padding_start, padding_overwrite)
                func_modify_count += 1
                byte_write_count += len(padding_overwrite)

                if verbose:
                    full_output += f"Padding (patched):  {[custom_hex(x) for x in binary.get_content_from_virtual_address(padding_start, len(patchable_addrs))]}\n"
        
        # Otherwise, use random bytes for the entire length of the padding
        else:
            if verbose:
                full_output += f"Padding (original): {[custom_hex(x) for x in binary.get_content_from_virtual_address(padding_start, len(patchable_addrs))]}\n"
                      
            # Overwrite padding with random bytes
            padding_overwrite = []
            for i in range(padding_start, next_start):
                padding_overwrite.append(random.randint(0, 255))
            binary.patch_address(padding_start, padding_overwrite)
            func_modify_count += 1
            byte_write_count += len(padding_overwrite)

            if verbose:
                full_output += f"Padding (patched):  {[custom_hex(x) for x in binary.get_content_from_virtual_address(padding_start, len(patchable_addrs))]}\n"
                
    # Save the modified binary
    binary.write(str(output_path.resolve()))
    total_func_count = len(modify_functions)
    total_byte_count = binary.virtual_size

    # Output metrics
    full_output += "-" * console.width + "\n"
    full_output += f"[bold green]Function padding sections modified: [/bold green]{(func_modify_count / total_func_count * 100):.4f}% ({func_modify_count} of {total_func_count})\n"
    full_output += f"[bold green]     Back-to-back functions:        [/bold green]{back_to_back_count}\n"
    full_output += f"[bold green]     Duplicate functions:           [/bold green]{duplicate_count}\n"
    full_output += f"[bold green]     Zero-size functions:           [/bold green]{zero_size_count}\n"
    full_output += f"[bold green]     Skipped functions:             [/bold green]{skipped}\n"
    full_output += f"[bold green]Bytes (over)written:                [/bold green]{(byte_write_count / total_byte_count * 100):.4f}% ({byte_write_count} of {total_byte_count})\n"
    full_output += "-" * console.width
    lock_print(full_output)
    return (func_modify_count, total_func_count, byte_write_count, total_byte_count, duplicate_count, back_to_back_count, zero_size_count, skipped)


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