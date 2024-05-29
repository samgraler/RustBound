import typer
import shlex
from rich import print
from multiprocessing import Pool
import multiprocessing
from collections import Counter
from art import text2art
import numpy as np

import ghidra.cli as ghidra_cli
import cargo_picky.db_cli as cargo_db_cli

from typing import List, Tuple
import ida.cli as ida_cli
import shutil
from dataclasses import dataclass, asdict
import subprocess
import lief
import json
from typing_extensions import Annotated
from alive_progress import alive_bar, alive_it
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.progress import track

import ripbin_cli
import analyze_cli
import evil_mod

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)
app.add_typer(ghidra_cli.app, name="ghidra", help="Ghidra related functions")
app.add_typer(ida_cli.app, name="ida", help="IDA related functions")
app.add_typer(cargo_db_cli.app, name="cargo", help="Pull cargo crates")
app.add_typer(ripbin_cli.app, name="ripbin", help="Build and stash binaries into ripbin db")
app.add_typer(analyze_cli.app, name="profile", help="Profile and analyze datasets")
app.add_typer(evil_mod.app, name="modify", help="Modify binaries")

from ripkit.cargo_picky import (
    build_crate,
    RustcStripFlags,
    RustcTarget,
    CrateBuildException,
)

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

from cli_utils import opt_lvl_callback, get_enum_type
import math

num_cores = multiprocessing.cpu_count()
CPU_COUNT_75 = math.floor(num_cores * (3/4))

@dataclass
class arch_stats():
    '''
    Architecture Specifics stats when profiling dataset
    '''
    files: int
    size: int
    funcs: int

@dataclass
class FoundFunctions():
    '''
    Helper Object to make explict found functions
    '''
    addresses: np.ndarray
    names: List[str]


@dataclass
class DatasetStat:
    '''
    Helper Object for gathering dataset stats
    '''
    files: int
    file_size: int
    stripped_size: int
    text_section_size: int
    functions: int
    text_section_functions: int
    alias_count: int

@dataclass
class SequenceCounter:
    '''
    Helper Object to count occurances of sequences in the dataset
    '''
    sequences: int
    found_in_nonstart: int 
    found_only_in_start: int 
    found_once_in_start: int

    nonstart_occurances:int
    start_occurances:int


@app.command()
def disasm(
    file: Annotated[str, typer.Argument(help="Input file")],
    addr: Annotated[str,
                    typer.Argument(help="Address to start at in hex")],
    num_bytes: Annotated[int,
                         typer.Argument(
                             help="Number of bytes to disassameble")],
):
    '''
    Copy of objdump... in python
    '''

    file_path = Path(file)

    if not file_path.exists():
        return

    res = disasm_at(file_path, int(addr, 16), num_bytes)
    for line in res:
        print(line)
    return

#@app.command()
#def build(
#    crate: Annotated[str, typer.Argument(help="crate name")],
#    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
#    target: Annotated[str, typer.Argument(help="crate target")],
#    strip: Annotated[bool, typer.Option()] = False,
#    verbose: Annotated[bool, typer.Option()] = False,
#):
#    '''
#    Build a crate for a specific target
#    '''
#
#    #TODO: For simpilicity I prompt for only
#    # 64 vs 32 bit and pe vs elf. Really I
#    # should prompt for the whole target arch
#    # b/c theres many different ways to get
#    # a 64bit pe  or 32bit elf
#
#    # Opt lvl call back
#    try:
#        opt = opt_lvl_callback(opt_lvl)
#    except Exception as e:
#        print(e)
#        return
#
#    # Match the target to its enum
#    target_enum = get_enum_type(RustcTarget, target)
#    if not strip:
#        strip_lvl = RustcStripFlags.NOSTRIP
#    else:
#        # SYM_TABLE is the all the symbols
#        strip_lvl = RustcStripFlags.SYM_TABLE
#
#    if target_enum == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
#        build_crate(crate,
#                    opt,
#                    target_enum,
#                    strip_lvl,
#                    use_cargo=True,
#                    debug=verbose)
#    else:
#        build_crate(crate,
#                    opt,
#                    target_enum,
#                    strip_lvl,
#                    use_cargo=False,
#                    debug=verbose)
#
#    print(f"Crate {crate} built")
#    return
#
#
#@app.command()
#def build_all(
#    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
#    target: Annotated[str, typer.Argument()],
#):
#    '''
#    Build all the installed crates
#    '''
#
#    #TODO: For simpilicity I prompt for only
#    # 64 vs 32 bit and pe vs elf. Really I
#    # should prompt for the whole target arch
#    # b/c theres many different ways to get
#    # a 64bit pe  or 32bit elf
#
#    # Opt lvl call back
#    try:
#        opt = opt_lvl_callback(opt_lvl)
#    except Exception as e:
#        print(e)
#        return
#
#    strip_lvl = RustcStripFlags.NOSTRIP
#
#    # List of crate current installed
#    installed_crates = [
#        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
#        if x.is_dir()
#    ]
#
#    target = get_enum_type(RustcTarget, target)
#
#    for crate in alive_it(installed_crates):
#        if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
#            build_crate(crate,
#                        opt,
#                        target,
#                        strip_lvl,
#                        use_cargo=True,
#                        debug=True)
#        else:
#            try:
#                build_crate(crate, opt, target, strip_lvl)
#            except Exception as e:
#                print(f"Error on {crate}")
#
#
#@app.command()
#def analyze(
#    bin_path: Annotated[str, typer.Argument()],
#    language: Annotated[str, typer.Argument()],
#    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
#    save: Annotated[bool, typer.Option()] = True,
#    verbose: Annotated[bool, typer.Option()] = False,
#    overwrite_existing: Annotated[bool, typer.Option()] = False,
#):
#    '''
#    Analyze binary file 
#    '''
#
#    binary = Path(bin_path).resolve()
#    if not binary.exists():
#        print(f"Binary {binary} doesn't exist")
#        return
#
#    # Generate analysis
#    if verbose:
#        print("Generating Tensors...")
#    data = generate_minimal_labeled_features(binary)
#
#    # Create the file info
#    if verbose: print("Calculating bin hash...")
#    binHash = calculate_md5(binary)
#
#    # TODO: Anlysis not being saved with target or ELF vs PE?
#
#    # Create the file info
#    info = RustFileBundle(binary.name, binHash, "", opt_lvl,
#                          binary.name, "", "")
#
#    if verbose: print("Saving Tensor and binary")
#    # Save analyiss
#    save_analysis(binary,
#                  data,
#                  AnalysisType.ONEHOT_PLUS_FUNC_LABELS,
#                  info,
#                  overwrite_existing=overwrite_existing)


def lief_num_funcs(path: Path):

    functions = get_functions(path)
    parsed_bin = lief.parse(str(path.resolve()))

    # Get the text session
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    func_start_addrs = {
        x.addr: (x.name, x.size)
        for x in functions
        if x.addr > base_address + text_section.virtual_address and
        x.addr < base_address + text_section.virtual_address + len(text_bytes)
    }

    return len(func_start_addrs.keys())

def stat_worker(bin_info):
    '''
    Worker to retrieve stats from ripbin
    '''
    bin_file = bin_info[0]
    info = bin_info[1]

    return info, bin_file.stat().st_size, lief_num_funcs(bin_file)

@app.command()
def stats(
    workers: Annotated[int, typer.Option(help="Number of workers")] = CPU_COUNT_75,
    ):
    '''
    Print statistics about the ripped binaries in the ripbin database
    '''
    ripbin_dir = Path("~/.ripbin/ripped_bins").expanduser().resolve()
    if not ripbin_dir.exists():
        print(f"Ripbin dir does not exist at {ripbin_dir}")
        return

    riplist = list(ripbin_dir.iterdir())

    bins_info = []

    for parent in riplist:
        info_file = parent / 'info.json'
        info = {}
        try:
            with open(info_file, 'r') as f:
                info = json.load(f)
        except FileNotFoundError:
            print(f"File not found: {info_file}")
            continue
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue


        bin_file = parent / info['binary_name']
        bins_info.append((bin_file, info))

    with Pool(processes=workers) as pool:
        results = pool.map(stat_worker, bins_info)

    stats = {}
    for res in results:
        cur_key = (res[0]['target'], res[0]['optimization'])
        if cur_key not in stats.keys():
            stats[cur_key] = arch_stats(0,0,0)
        stats[cur_key].files +=1
        stats[cur_key].size += res[1]
        stats[cur_key].funcs += res[2]


    for (arch, opt), data in stats.items():
        if arch != "":
            print(f"{arch} | {opt}")
        else:
            print(f"Unkown | {opt}")
        print(f"    {data.files} files")
        print(f"    {data.size} bytes")
    return


@app.command()
def export_large_dataset(
    target: Annotated[str, typer.Argument()],
    output_dir: Annotated[str,
                          typer.Option(
                              help="Save the binaries to a directory")] = "",
    output_file: Annotated[str,
                           typer.Option(
                               help="Save the binaries paths to a file")] = "",
    min_text_bytes: Annotated[
        int,
        typer.Option(
            help="Minimum number of bytes in a files .text section")] = 2000,
    drop_dups: Annotated[bool,
                         typer.Option(
                             help="Don't include duplicate files")] = True,
    verbose: Annotated[bool, typer.Option] = False,
):
    '''
    Export a dataset from the ripkit db
    '''

    out_to_dir = False
    out_to_file = False

    if output_dir != "":
        out_to_dir = True

        out_dir = Path(output_dir)

        if out_dir.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_dir.resolve()}")
            return

    if output_file != "":
        out_to_file = True
        out_file = Path(output_file)
        if out_file.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_file.resolve()}")
            return

    if not out_to_file and not out_to_dir:
        print("No output to file or directory given")
        return

    # Get a dictionary of all the binaries that are in the ripbin db
    org_bins = get_all_bins()

    # Need to find all the bins that exist in each opt lvl
    # and that are atleast the min number of bytes long

    # For each optimization levels and its corresponding bin list:
    # If any binary names appears more than once drop it
    no_dups_bins = {k: [] for k in org_bins.keys()}

    # A dictionary of all the binary names
    dict_of_names = {k: [x.name for x in v] for k, v in org_bins.items()}

    print("Finding binaries whose name occurs in opt lvls more than once...")

    # 1. For each opt level drop all binaries
    #       where they're name appears more than once
    for opt_lvl, bin_list in org_bins.items():
        print(f"[DUP] Before | {opt_lvl} | {len(bin_list)}")
        # For each binary in the list of binaries
        for bin in bin_list:
            # If this binary name appears exactly once, its
            # a good bin
            if dict_of_names[opt_lvl].count(bin.name) == 1:
                no_dups_bins[opt_lvl].append(bin)
        print(f"[DUP] After | {opt_lvl} | {len(no_dups_bins[opt_lvl])}")

    print("Finding binaries that don't match len requirement")

    # New dict to hold bins that meet length requirement
    good_len_bins = {}
    short_bin_names = []

    # Iterate over the dictionary of opt_lvl : [bins]
    # where each list of bins has no duplicates
    for opt_lvl, bins in no_dups_bins.items():
        print(f"[LEN] Before | {opt_lvl} | {len(bins)}")
        cur_good_bins = []
        #TEMP_COUNT = 0
        for bin in track(
                bins,
                description=f"Checking {opt_lvl} | {len(bins)} bin sizes..."):

            # If the name of the binary has already been
            # found to be short in other opt lvls, don't
            # even consider it
            if bin.name in short_bin_names:
                continue

            # Parse the binary with lief
            parsed_bin = lief.parse(str(bin.resolve()))

            # Get the text section and the bytes themselse
            text_section = parsed_bin.get_section(".text")
            num_text_bytes = len(text_section.content)

            # Append a good binary to the list of current good
            # binaries
            if num_text_bytes >= min_text_bytes:
                cur_good_bins.append(bin)
            else:
                short_bin_names.append(bin.name)
                print(f"[LEN] | SHORT | {opt_lvl} | {bin.name}")

        print(f"[LEN] After | {opt_lvl} | {len(cur_good_bins)}")
        good_len_bins[opt_lvl] = cur_good_bins

    # Update the dict of names
    dict_of_names = {k: [x.name for x in v] for k, v in good_len_bins.items()}

    print(f"[SET] Making sure binaries appear in all lvls")
    # 3. Make sure the names of all the binaries
    #       exist in each opt lvl
    bins_set = []
    for bin_list in dict_of_names.values():
        if len(bins_set) == 0:
            bins_set = bin_list
        else:
            bins_set = set(bins_set) & set(bin_list)

    # Need the intersection of the names of all
    # opt lvls
    set_of_names = list(bins_set)
    final_bins = {}
    print(f"[SET] Found {len(set_of_names)} in final set")

    # remove files that are not in set_of_names
    for opt_lvl, bin_list in no_dups_bins.items():
        print(f"[SET] Before | {opt_lvl} | {len(bin_list)}")
        good_bins = []
        for bin in bin_list:
            if bin.name in set_of_names:
                good_bins.append(bin)

        print(f"[SET] After | {opt_lvl} | {len(good_bins)}")
        final_bins[opt_lvl] = good_bins

    # Write to the output file
    if out_to_file:
        with open(output_file, 'w') as f:
            for key in final_bins.keys():
                f.write(str(key) + "\n")
                f.write("\n".join(
                    str(bin.resolve()) for bin in final_bins[key]))

    # Write to output dir
    if out_to_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir()
        for key, bins in final_bins.items():
            opt_out_dir = out_dir / f"{key}_lvl_bins"
            opt_out_dir.mkdir()
            for bin in track(
                    bins,
                    description=f"Copying {len(bins)} bins for opt {key}..."):
                dest_file = opt_out_dir / bin.name
                shutil.copy(bin.resolve(), dest_file.resolve())
    return


#TODO: drop bit and file type and replace with a target type.
#       may be have create a custom type that wraps targets for rust and
#       go
@app.command()
def export_large_target_dataset(
    target: Annotated[str, typer.Argument(
        help="Target triplet to compile")],
    output_dir: Annotated[str, typer.Argument(
        help="Save the binaries to a directory")],
    output_file: Annotated[str, typer.Option(
        help="Save the binaries paths to a file")] = "",
    min_text_bytes: Annotated[ int, typer.Option(
        help="Minimum number of bytes in a files .text section")] = 2000,
    drop_dups: Annotated[bool, typer.Option(
        help="Don't include duplicate files")] = True,
    verbose: Annotated[bool, typer.Option] = False,
):
    '''
    Export a dataset from the CRATES IO DB 
    '''

    out_to_dir = False
    out_to_file = False

    if output_dir != "":
        out_to_dir = True

        out_dir = Path(output_dir)

        if out_dir.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_dir.resolve()}")
            return

    if output_file != "":
        out_to_file = True
        out_file = Path(output_file)
        if out_file.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_file.resolve()}")
            return

    if not out_to_file and not out_to_dir:
        print("No output to file or directory given")
        return

    target_enum = get_enum_type(RustcTarget, target)

    # Get a dictionary of all the binaries that are in the ripbin db
    org_bins = get_all_target_bins(target_enum)

    # Need to find all the bins that exist in each opt lvl
    # and that are atleast the min number of bytes long

    # For each optimization levels and its corresponding bin list:
    # If any binary names appears more than once drop it
    no_dups_bins = {k: [] for k in org_bins.keys()}

    # A dictionary of all the binary names
    dict_of_names = {k: [x.name for x in v] for k, v in org_bins.items()}

    print("Finding binaries whose name occurs in opt lvls more than once...")

    # 1. For each opt level drop all binaries
    #       where they're name appears more than once
    for opt_lvl, bin_list in org_bins.items():
        print(f"[DUP] Before | {opt_lvl} | {len(bin_list)}")
        # For each binary in the list of binaries
        for bin in bin_list:
            # If this binary name appears exactly once, its
            # a good bin
            if dict_of_names[opt_lvl].count(bin.name) == 1:
                no_dups_bins[opt_lvl].append(bin)
        print(f"[DUP] After | {opt_lvl} | {len(no_dups_bins[opt_lvl])}")

    print("Finding binaries that don't match len requirement")
    # New dict to hold bins that meet length requirement
    good_len_bins = {}
    short_bin_names = []

    # Iterate over the dictionary of opt_lvl : [bins]
    # where each list of bins has no duplicates
    for opt_lvl, bins in no_dups_bins.items():
        print(f"[LEN] Before | {opt_lvl} | {len(bins)}")
        cur_good_bins = []
        #TEMP_COUNT = 0
        for bin in track(
                bins,
                description=f"Checking {opt_lvl} | {len(bins)} bin sizes..."):

            #TEMP_COUNT+=1
            #if TEMP_COUNT > 100:
            #    break
            # If the name of the binary has already been
            # found to be short in other opt lvls, don't
            # even consider it
            if bin.name in short_bin_names:
                continue

            # Parse the binary with lief
            parsed_bin = lief.parse(str(bin.resolve()))

            # Get the text section and the bytes themselse
            text_section = parsed_bin.get_section(".text")
            num_text_bytes = len(text_section.content)

            # Append a good binary to the list of current good
            # binaries
            if num_text_bytes >= min_text_bytes:
                cur_good_bins.append(bin)
            else:
                short_bin_names.append(bin.name)
                print(f"[LEN] | SHORT | {opt_lvl} | {bin.name}")

        print(f"[LEN] After | {opt_lvl} | {len(cur_good_bins)}")
        good_len_bins[opt_lvl] = cur_good_bins

    # Update the dict of names
    dict_of_names = {k: [x.name for x in v] for k, v in good_len_bins.items()}

    print(f"[SET] Making sure binaries appear in all lvls")
    # 3. Make sure the names of all the binaries
    #       exist in each opt lvl
    bins_set = []
    for bin_list in dict_of_names.values():
        if len(bins_set) == 0:
            bins_set = bin_list
        else:
            bins_set = set(bins_set) & set(bin_list)

    # Need the intersection of the names of all
    # opt lvls
    set_of_names = list(bins_set)
    final_bins = {}
    print(f"[SET] Found {len(set_of_names)} in final set")

    # remove files that are not in set_of_names
    for opt_lvl, bin_list in no_dups_bins.items():
        print(f"[SET] Before | {opt_lvl} | {len(bin_list)}")
        good_bins = []
        for bin in bin_list:
            if bin.name in set_of_names:
                good_bins.append(bin)

        print(f"[SET] After | {opt_lvl} | {len(good_bins)}")
        final_bins[opt_lvl] = good_bins

    # Write to the output file
    if out_to_file:
        with open(output_file, 'w') as f:
            for key in final_bins.keys():
                f.write(str(key) + "\n")
                f.write("\n".join(
                    str(bin.resolve()) for bin in final_bins[key]))

    # Write to output dir
    if out_to_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir()
        for key, bins in final_bins.items():
            opt_out_dir = out_dir / f"{key}_lvl_bins"
            opt_out_dir.mkdir()
            for bin in track(
                    bins,
                    description=f"Copying {len(bins)} bins for opt {key}..."):
                dest_file = opt_out_dir / bin.name
                shutil.copy(bin.resolve(), dest_file.resolve())
    return


def get_funcs_with(files, backend):

    num_funcs = {}
    f_size = {}
    lief_total = {}
    total_funcs = 0

    if Path(files).is_dir():
        files = list(Path(files).glob('*'))
    else:
        files = [Path(files)]

    for path in alive_it(files):

        f_size[path] = path.stat().st_size

        if backend == 'lief':
            functions = get_functions(path)
            parsed_bin = lief.parse(str(path.resolve()))

            # Get the text session
            text_section = parsed_bin.get_section(".text")

            # Get the bytes in the .text section
            text_bytes = text_section.content

            # Get the base address of the loaded binary
            base_address = parsed_bin.imagebase

            # Save total functions per path
            lief_total[path] = len(functions)

            funcs_all = {x.addr: (x.name, x.size) for x in functions}

            funcs_txt = {
                x.addr: (x.name, x.size)
                for x in functions if x.addr > base_address +
                text_section.virtual_address and x.addr < base_address +
                text_section.virtual_address + len(text_bytes)
            }

            return funcs_all, funcs_txt

        elif backend == 'ghidra':
            #TODO
            return []
        elif backend == 'ida':
            #TODO
            print('nop')
            return []
        elif backend == 'objdump1':
            cmd = f"objdump -t -f {path.resolve()} | grep 'F .text' | sort"
            res = subprocess.run(cmd,
                                 shell=True,
                                 universal_newlines=True,
                                 capture_output=True)
            return res.stdout

        elif backend == 'objdump2':
            #TODO
            cmd = f"objdump -d {path.resolve()} | grep -cE '^[[:xdigit:]]+ <[^>]+>:'"
            res = subprocess.check_output(cmd, shell=True)
            total_funcs += int(res)
        elif backend == 'readelf':
            #TODO
            cmd = f"readelf -Ws {path.resolve()} | grep FUNC | wc -l"
            res = subprocess.check_output(cmd, shell=True)
            print(res)

    return


def parse_obj_stdout(inp):
    addrs = []

    for line in inp.split('\n'):
        addr = line.split(' ')[0].strip()
        if addr != '':
            addrs.append(int(addr, 16))
    return addrs


@app.command()
def count_diff(
    inp: Annotated[str,
                   typer.Argument(
                       help="Directory containing files -or- single file")],
    backend: Annotated[
        str,
        typer.Argument(help="lief, ghidra, ida, objdump1, objdump2, readelf")],
    backend2: Annotated[str, typer.Argument()],
):
    '''
    For generation of ground truth there are various tools that can be used to 
    extract the addresses. Interesting, despite the function addresses and 
    function lengths are explicitly stated in the binary file. Therefore this 
    function will take different 'backends' (the tools to extract) the 
    ground truth and compre them! 
    '''


    if backend == "lief":
        tot_funcs, txt_funcs = get_funcs_with(inp, 'lief')
        print(txt_funcs)

    if backend2 == "objdump1":
        # Need to parse this output for functions
        stdout_res = get_funcs_with(inp, 'objdump1')
        func_addrs = np.array(parse_obj_stdout(stdout_res))
        print(func_addrs)

    same = np.intersect1d(list(txt_funcs.keys()), func_addrs)

    lief_only = np.setdiff1d(list(txt_funcs.keys()), func_addrs)

    obj_only = np.setdiff1d(func_addrs, list(txt_funcs.keys()))
    print(f"Same {len(same)}")
    print(f"Lief only {len(lief_only)}")
    print(f"Obj only {len(obj_only)}")
    print(f"Obj count {len(func_addrs)}")
    print(f"Obj set count {len(set(func_addrs))}")
    print(f"lief count {len(list(txt_funcs.keys()))}")

    # Get the functions that are repeated more than once
    multi_obj = np.setdiff1d(func_addrs, set(func_addrs))

    # TODO: obj repreaeted funcs?
    print(f"The repeated function in obj: {multi_obj}")
    print(f"The repeated function in obj: {len(multi_obj)}")

    with open("SAME", 'w') as f:
        for addr in same:
            f.write(f"{hex(addr)}\n")

    with open("LIEF_UNIQUE", 'w') as f:
        for addr in lief_only:
            f.write(f"{hex(addr)}\n")

    with open("OBJ_UNIQUE", 'w') as f:
        for addr in obj_only:
            f.write(f"{hex(addr)}\n")

    # Then comparse the parsed output with the functions given by lief

    return

#
# @app.command()
# def count_funcs(
#     inp: Annotated[str,
#                    typer.Argument(
#                        help="Directory containing files -or- single file")],
#     backend: Annotated[
#         str,
#         typer.Argument(
#             help="lief, ghidra, ida, objdump1, objdump2, readelf")] = 'lief',
#     list_functions: Annotated[
#         bool,
#         typer.Option(
#             help="List all the functions in the given files")] = False,
# ):
#     '''
#     Count the functions in the .text section. Files must be non-stripped
#     '''
#
#     num_funcs = {}
#     f_size = {}
#     lief_total = {}
#
#     # Check that the backend is good
#     if backend not in [
#             "lief", "ghidra", "ida", "objdump1", "objdump2", "readelf"
#     ]:
#         print(f"The backend is not in {backend}")
#         return
#
#     if Path(inp).is_dir():
#         files = list(Path(inp).glob('*'))
#     else:
#         files = [Path(inp)]
#
#     total_funcs = 0
#     if backend == 'lief':
#         print("Using Lief for function boundary")
#
#         res = """
#         NOTICE: elffile seems to ignore functions injected by gcc such as 
#         "register_tm...", "deregister_tm...", 
#         Therefore those names will be included in the list, but will have 
#         a size of 0 
#             elf = ELFFile(f)
#
#             # Get the symbol table
#             symbol_table = elf.get_section_by_name('.symtab')
#
#             # Create a list of functionInfo objects... symbol_table will give a 
#             # list of symbols, grab the function sybols and get there name, 
#             # their 'st_value' which is start addr and size 
#             functionInfo = [FunctionInfo(x.name, x['st_value'], f"0x{x['st_value']:x}",x['st_size']) 
#                 for x in symbol_table.iter_symbols() if x['st_info']['type'] == 'STT_FUNC']
#
#         """
#         print(res)
#     elif backend == 'ida':
#         print('nop')
#     elif backend == 'objdump1':
#         cmd = "objdump -t -f <FILE_PATH> | grep 'F .text' | sort | wc -l"
#         print(f"The command being used is {cmd}")
#     elif backend == 'objdump2':
#         cmd = "objdump -d <FILE_PATH> | grep -cE '^[[:xdigit:]]+ <[^>]+>:'"
#         print(f"The command being used is {cmd}")
#     elif backend == 'readelf':
#         cmd = "readelf -Ws <FILE_PATH> | grep FUNC | wc -l"
#         print(f"The command being used is {cmd}")
#
#     for path in alive_it(files):
#
#         f_size[path] = path.stat().st_size
#
#         if backend == 'lief':
#             functions = get_functions(path)
#             parsed_bin = lief.parse(str(path.resolve()))
#
#             # Get the text session
#             text_section = parsed_bin.get_section(".text")
#
#             # Get the bytes in the .text section
#             text_bytes = text_section.content
#
#             # Get the base address of the loaded binary
#             base_address = parsed_bin.imagebase
#
#             lief_total[path] = len(functions)
#             func_start_addrs = {
#                 x.addr: (x.name, x.size)
#                 for x in functions if x.addr > base_address +
#                 text_section.virtual_address and x.addr < base_address +
#                 text_section.virtual_address + len(text_bytes)
#             }
#
#             num_funcs[path] = len(func_start_addrs.keys())
#             if list_functions:
#                 for addr, (name, size) in func_start_addrs.items():
#                     print(f'{hex(addr)} : {name}')
#
#         elif backend == 'ghidra':
#             #TODO
#             print('nop')
#         elif backend == 'ida':
#             #TODO
#             print('nop')
#         elif backend == 'objdump1':
#             #TODO
#             cmd = f"objdump -t -f {path.resolve()} | grep 'F .text' | sort | wc -l"
#             res = subprocess.check_output(cmd, shell=True)
#             total_funcs += int(res)
#         elif backend == 'objdump2':
#             #TODO
#             cmd = f"objdump -d {path.resolve()} | grep -cE '^[[:xdigit:]]+ <[^>]+>:'"
#             res = subprocess.check_output(cmd, shell=True)
#             total_funcs += int(res)
#         elif backend == 'readelf':
#             #TODO
#             cmd = f"readelf -Ws {path.resolve()} | grep FUNC | wc -l"
#             res = subprocess.check_output(cmd, shell=True)
#             print(res)
#
#     if backend == 'lief':
#         print(f"lief Total funcs: {sum(lief_total.values())}")
#         print(f"Total funcs: {sum(num_funcs.values())}")
#         print(f"Total file size: {sum(f_size.values())}")
#     else:
#         print(f"Total functions: {total_funcs}")
#         print(f"Total files: {len(files)}")
#
#     return
#
#
# @app.command()
# def build_all_and_stash(
#     opt_lvl: Annotated[str, typer.Argument()],
#     target: Annotated[str, typer.Argument(help="crate target")],
#     stop_on_fail: Annotated[bool, typer.Option()] = False,
# ):
#     '''
#     Build the crates in crates io and stash into ripbin db
#     '''
#
#     # Opt lvl call back
#     try:
#         opt = opt_lvl_callback(opt_lvl)
#     except Exception as e:
#         print(e)
#         return
#
#     target_enum = get_enum_type(RustcTarget, target)
#
#     # List of crate current installed that can be built
#     crates_to_build = [
#         x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
#         if x.is_dir()
#     ]
#
#     # If we don't have to build all the crates, find the crates that
#     # are already built with the specified optimization and arch
#     # an dremovet that from the list of installed crates
#     for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
#         info_file = parent / 'info.json'
#         info = {}
#         try:
#             with open(info_file, 'r') as f:
#                 info = json.load(f)
#         except FileNotFoundError:
#             print(f"File not found: {info_file}")
#             continue
#         except json.JSONDecodeError as e:
#             print(f"JSON decoding error: {e}")
#             continue
#         except Exception as e:
#             print(f"An error occurred: {e}")
#             continue
#
#         if info['optimization'].upper() in opt_lvl and \
#             info['target'].upper() in target_enum.value.upper():
#             # Remove this file from the installed crates list
#             if (x := info['binary_name']) in crates_to_build:
#                 crates_to_build.remove(x)
#
#     success = 0
#     # Build and analyze each crate
#     for crate in alive_it(crates_to_build):
#         res = 0
#         try:
#             res = build_and_stash(crate,
#                             opt,
#                             target_enum,
#                             use_cargo=False)
#         except CrateBuildException as e:
#             print(f"[bold red]Failed to build crate {crate}:: {e}[/bold red]")
#             continue
#         if res != 99:
#             success += 1
#             print(f"[bold green][SUCCESS][/bold green] crate {crate}")
#
#     print(f"[bold green][SUCCESS] {success}")
#     print(f"[bold red][FAILED] {len(crates_to_build)-success}")
#     return
#

#@app.command()
#def build_analyze_all(
#    opt_lvl: Annotated[str, typer.Argument()],
#    #bit: Annotated[int, typer.Argument()],
#    filetype: Annotated[str, typer.Argument()],
#    target: Annotated[str, typer.Argument(help="crate target")],
#    stop_on_fail: Annotated[bool, typer.Option()] = False,
#    force_build_all: Annotated[bool, typer.Option()] = False,
#    build_arm: Annotated[bool, typer.Option()] = False,
#):
#    '''
#    Build and analyze pkgs
#    '''
#
#    # Opt lvl call back
#    try:
#        opt = opt_lvl_callback(opt_lvl)
#    except Exception as e:
#        print(e)
#        return
#
#    target_enum = get_enum_type(RustcTarget, target)
#
#    # List of crate current installed that can be built
#    crates_to_build = [
#        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
#        if x.is_dir()
#    ]
#
#    # If we don't have to build all the crates, find the crates that
#    # are already built with the specified optimization and arch
#    # an dremovet that from the list of installed crates
#    if not force_build_all:
#
#        for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
#            info_file = parent / 'info.json'
#            info = {}
#            try:
#                with open(info_file, 'r') as f:
#                    info = json.load(f)
#            except FileNotFoundError:
#                print(f"File not found: {info_file}")
#                continue
#            except json.JSONDecodeError as e:
#                print(f"JSON decoding error: {e}")
#                continue
#            except Exception as e:
#                print(f"An error occurred: {e}")
#                continue
#
#            if info['optimization'].upper() in opt_lvl and \
#                info['target'].upper() in target_enum.value.upper():
#                # Remove this file from the installed crates list
#                if (x := info['binary_name']) in crates_to_build:
#                    crates_to_build.remove(x)
#
#    # Any crates that are already built with the same target don't rebuild or analyze
#
#    # Need to get all the analysis for the given optimization and target...
#    crates_with_no_interest = Path(
#        f"~/.crates_io/uninteresting_crates_cache_{target_enum.value}"
#    ).expanduser()
#
#    boring_crates = []
#    # If the file doesn't exist throw in the empty list
#    if not crates_with_no_interest.exists():
#        crates_with_no_interest.touch()
#        with open(crates_with_no_interest, 'w') as f:
#            json.dump({'names': boring_crates}, f)
#
#    # Add to the boring crates that aren't being built if we are
#    # not forcing the build of all crates
#    if not force_build_all:
#        # If the file does exist read it, ex
#        with open(crates_with_no_interest, 'r') as f:
#            boring_crates.extend(json.load(f)['names'])
#
#    # Dont build any crate that have been found to have no executable
#    crates_to_build = [x for x in crates_to_build if x not in boring_crates]
#
#    #for x in boring_crates:
#    #    if x in crates_to_build:
#    #        crates_to_build.remove(x)
#
#    success = 0
#
#    # Build and analyze each crate
#    for crate in alive_it(crates_to_build):
#        #TODO: the following conditional is here because when building for
#        #       x86_64 linux I know that cargo will work, and I know
#        #       cargo's toolchain version
#        res = 0
#        if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
#            try:
#                res = build_analyze_crate(crate,
#                                          opt,
#                                          target_enum,
#                                          filetype,
#                                          RustcStripFlags.NOSTRIP,
#                                          use_cargo=True)
#            except CrateBuildException:
#                print(f"Failed to build crate {crate}")
#        else:
#            try:
#                res = build_analyze_crate(crate,
#                                          opt,
#                                          target_enum,
#                                          filetype,
#                                          RustcStripFlags.NOSTRIP,
#                                          use_cargo=False)
#            except CrateBuildException:
#                print(f"Failed to build crate {crate}")
#                continue
#        if res == 99:
#            boring_crates.append(crate)
#            print(f"Success build but adding {crate} to boring crates")
#            with open(crates_with_no_interest, 'w') as f:
#                json.dump({'names': boring_crates}, f)
#        else:
#            success += 1
#            print(f"[SUCCESS] crate {crate}")
#
#    print(f"Total build success: {success}")


def get_text_functions(bin_path: Path):
    '''
    '''
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

    # This enumerate the .text byte and sees which ones are functions
    for i, _ in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            func_addrs.append(address)
            func_names.append(func_start_addrs[address][0])

    # Return the addrs and names
    func_addrs = np.array(func_addrs)
    return FoundFunctions(func_addrs, func_names)


def gen_strip_file(bin_path: Path):
    '''
    Strip the passed file and return the path of the 
    stripped file
    '''

    # Copy the bin and strip it
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(['strip', f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    return strip_bin


@app.command()
def DatasetStats(
    dataset: Annotated[str, typer.Argument(help="Input dataset")], func_size: Annotated[
        int,
        typer.Argument(
            help="Minimum size of function to be considered function")]):
    '''
    Get info on dataset. Expects a dataset to be all binaries, and all nonstripped
    '''

    bins = list(Path(dataset).glob('*'))

    stats = DatasetStat(0, 0, 0, 0, 0, 0, 0)

    # Get the size of the stripped bins
    for bin in alive_it(bins):

        stats.files += 1
        stats.file_size += bin.stat().st_size

        functions = get_functions(bin)
        name_counts = Counter([x.name for x in functions])

        alias_count = sum(
            [count for _, count in name_counts.items() if count >= 2])
        stats.alias_count += alias_count

        min_size_functions = [x for x in functions if x.size >= func_size]
        stats.functions += len(min_size_functions)
        stats.text_section_functions += len(get_text_functions(bin).addresses)

        stripped_bin = gen_strip_file(bin)
        stats.stripped_size += stripped_bin.stat().st_size
        stripped_bin.unlink()

        bin = lief.parse(str(bin.resolve()))

        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content
        stats.text_section_size += len(text_bytes)
    print(stats)
    return

if __name__ == "__main__":

    banner = text2art("Ripkit", "random")
    console.print(banner, highlight=False)
    app()
