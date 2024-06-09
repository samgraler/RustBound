"""
cli.py

CLI interface to extract detected function with ghidra
"""

from dataclasses import dataclass, asdict
import typer
import math
import os
from typing import List
from pathlib import Path
import time
from multiprocessing import Pool
import matplotlib.pyplot as plt
from typing_extensions import Annotated
import subprocess
import shutil
from alive_progress import alive_it
import json
import sys
import lief
import numpy as np

from rich.console import Console


ripkit_dir = Path("../ripkit").resolve()
import sys

sys.path.append(str(ripkit_dir))
from ripkit.score import (
    score_start_plus_len,
    load_ghidra_prediction,
    gnd_truth_start_plus_len,
)
from ripkit.ripbin import (
    FoundFunctions,
    calc_metrics,
    ConfusionMatrix,
    get_functions,
    save_raw_experiment,
    iterable_path_shallow_callback,
    iterable_path_deep_callback,
)

app = typer.Typer()
console = Console()


# TODO: log dictionarires of the GhidraBenchResults
@dataclass
class GhidraBenchResult:
    stripped_bin: bool
    without_analysis: bool
    bin_name: str
    ground_truth: List[int]
    functions: List[int]
    runtime: float
    # exact_ghid_command : str


@dataclass
class ListCompare:
    intersection: List[str]
    a_only: List[str]
    b_only: List[str]


def gen_strip_file(bin_path: Path):
    """
    Strip the passed file and return the path of the
    stripped file
    """

    # Copy the bin and strip it
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(["strip", f"{strip_bin.resolve()}"])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    return strip_bin


def remove_paths(paths):
    """
    Remove all the paths given, including directories
    """
    for path in paths:
        # If the path exists check to see if it a dir or file
        # and handle it accordingly
        if path.exists():
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
    return


def call_ghidra(
    bin_path: Path,
    ghid_args: List[str],
    analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless")
    .expanduser()
    .resolve(),
    hide_output=True,
):

    cmd_base_str = [
        f"{analyzer.parent}/./{analyzer.name}",
        "/tmp",
        "tmp_proj",
        "-import",
        f"{bin_path}",
    ]

    # print(f"GHID ARGS {ghid_args}")
    for x in ghid_args:
        cmd_base_str.append(x)

    cmd_str = cmd_base_str
    # print(f"THE COMMAND STR {cmd_str}")

    try:
        # remove the temporary paths from previous runs
        paths_to_remove = ["/tmp/tmp_proj.rep", "/tmp/tmp_proj.gpr"]
        paths_to_remove = [Path(x) for x in paths_to_remove]
        remove_paths(paths_to_remove)

        # Record the start time of the ghidra process
        start = time.time()

        # Run the ghidra commad, capturing all of its output
        output = subprocess.run(
            cmd_str, text=True, capture_output=True, universal_newlines=True
        )
        # print(output.stdout)

        # Get the runtime
        runtime = time.time() - start

        return output, runtime
    except subprocess.CalledProcessError as e:
        print(f"COMMAND IS : {cmd_str}")
        print("Error running command:", e)
        return []
    finally:
        paths_to_remove = ["/tmp/tmp_proj.rep", "/tmp/tmp_proj.gpr"]
        paths_to_remove = [Path(x) for x in paths_to_remove]
        remove_paths(paths_to_remove)
    return


def get_ghidra_functions(
    bin_path,
    post_script: Path = Path(
        "~/ghidra_scripts/List_Function_and_Entry.py"
    ).expanduser(),
    other_flags: List[str] = [],
):

    # Add to the flags
    other_flags.extend(["-postScript", f"{post_script.resolve()}"])

    print(f"FLAGS: {other_flags}")

    # Run ghidra
    res, runtime = call_ghidra(bin_path, other_flags)

    # If it was a good run read the stdout
    # TODO: Check for bad run
    res = res.stdout

    # Parse for functions and return the functions
    return parse_for_functions(res), runtime


def get_ghidra_bounds(
    bin_path,
    post_script: Path = Path("~/ghidra_scripts/ghidra_bounds_script.py").expanduser(),
    other_flags: List[str] = [],
):

    # Add to the flags
    other_flags.extend(["-postScript", f"{post_script.resolve()}"])

    # print(f"FLAGS: {other_flags}")

    # Run ghidra
    res, runtime = call_ghidra(bin_path, other_flags)

    # If it was a good run read the stdout
    # TODO: Check for bad run
    res = res.stdout

    # Parse for functions and return the functions
    return parse_for_bounds(res), runtime


def append_bnext(inp_list):
    """
    given a list integers, calculate the distane
    until the next integer.

    Make a tuple of (integer, till_next_int)
    """

    new_list = []

    # Generate a list of addrs and the # bytes till the next addr
    for i, fun in enumerate(inp_list):
        if i < len(inp_list) - 1:
            to_next = int(inp_list[i + 1]) - int(inp_list[i])
        else:
            to_next = 0
        new_list.append((fun, to_next))

    return new_list


def find_offset(lief_addrs, ghidra_addrs):
    """
    Ghidra adds an offset to it's addrs, this function
    finds that offset
    """

    # The idea here is to...
    # 1. Find the space (in bytes) between all the functions
    # 2. Make a list of tuples of:
    #       (function_start_address, bytes_til_next_function)

    # Once we have this we can try to "slide" the function
    #  addresses until the two lists of bytes_til_next match

    ghid_addr_bnext = append_bnext(ghidra_addrs)
    lief_addrs = append_bnext(lief_addrs)
    offset = 0
    found_offset = False
    for i, (addr, btnext) in enumerate(lief_addrs):
        if found_offset:
            break
        for i, (ghid_addr, ghid_btnext) in enumerate(ghid_addr_bnext):
            if found_offset:
                break
            if ghid_btnext == btnext:
                offset = ghid_addr - addr
                return offset
    return offset


def get_lief_functions(bin_path: Path):
    """ """
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

    # This enumerate the .text byte and sees which ones are functions
    for i, _ in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            func_addrs.append(address)
            func_names.append(func_start_addrs[address][0])
            func_lengths.append(func_start_addrs[address][1])

    # Get the functions from the bin
    functions = get_functions(bin_path)

    # Return the addrs and names
    func_addrs = np.array(func_addrs)
    func_lens = np.array(func_lengths)
    return FoundFunctions(func_addrs, func_names, func_lens)


def inbetween_inc(x, min, max):
    return x <= max and x >= min


def get_ghid_bounds(
    bin_path, ghidra_flags, use_offset: bool, strip_the_bin: bool = True
):
    """
    Run a test of lief vs ghidra

    Seeing how the function address compare for a binary

    NOTICE: Stripping the file will temporarily make a new file
    """

    # Get the functions from lief
    lief_functions = get_lief_functions(bin_path)

    # Strip the file is desired:
    post_script = Path(os.path.abspath(__file__)).parent / "ghidra_bounds_script.py"

    # Get the functons from ghidra
    ghidra_functions, runtime = get_ghidra_bounds(
        bin_path, post_script=post_script.resolve(), other_flags=ghidra_flags
    )

    if strip_the_bin:
        bin_path = gen_strip_file(bin_path)
    try:
        offset = find_offset(
            list(lief_functions.addresses), list(ghidra_functions.addresses)
        )
    finally:
        if strip_the_bin:
            bin_path.unlink()

    # Apply the offset
    offset_ghid_funcs = np.array([x - offset for x in ghidra_functions.addresses])

    if use_offset:
        func_len_array = np.concatenate(
            (
                offset_ghid_funcs.T.reshape(-1, 1),
                ghidra_functions.lengths.T.reshape(-1, 1),
            ),
            axis=1,
        )
    else:
        func_len_array = np.concatenate(
            (
                ghidra_functions.addresses.T.reshape(-1, 1),
                ghidra_functions.lengths.T.reshape(-1, 1),
            ),
            axis=1,
        )
    return func_len_array, runtime


# def test_lief_v_ghid(bin_path, ghidra_flags, strip_file, save_to_location: Path = None ):
#    """
#    Run a test of lief vs ghidra
#
#    Seeing how the function address compare for a binary
#
#    NOTICE: Stripping the file will temporarily make a new file
#    """
#
#    # Get the functions from lief
#    lief_functions =  get_lief_functions(bin_path)
#
#
#    # Strip the file is desired:
#    if strip_file:
#        bin_path = gen_strip_file(bin_path)
#
#    post_script = Path(os.path.abspath(__file__)).parent / "List_Function_and_Entry.py"
#
#    # Get the functons from ghidra
#    ghidra_functions, runtime = get_ghidra_functions(bin_path, post_script=post_script.resolve(),
#                                    other_flags=ghidra_flags)
#
#    #TODO: Offset
#    # Need to apply the offset to the ghidra functions
#    # Need to find out under what conditions the functions
#    # are slid
#    offset = find_offset(list(lief_functions.addresses),
#                         list(ghidra_functions.addresses))
#
#
#    # Ghidra includes functions that are not in the .text range
#    # therefore only include functions that are within the bounds
#    # of the lief functions
#    ghid_funcs = [x for x in ghidra_functions.addresses if
#                  x >= min(lief_functions.addresses) and
#                  x <= max(lief_functions.addresses)]
#
#    # Apply the offset
#    offset_ghid_funcs = [x-offset for x in ghidra_functions.addresses if
#        (x-offset) >= min(lief_functions.addresses) and
#        (x-offset) <= max(lief_functions.addresses)]
#
#    # BUG: The offset
#    # TODO: This is related to the above, find out exactly when the offset
#    #       needs to be applied
#    use_offset = True
#    if not use_offset:
#        # Compare the lists
#        same = np.intersect1d(lief_functions.addresses, ghid_funcs)
#
#        lief_only = np.setdiff1d( lief_functions.addresses, ghid_funcs)
#
#        ghid_only = np.setdiff1d( ghid_funcs, lief_functions.addresses )
#
#    else:
#        print(f"Using an offset of {offset}")
#        # Compare the lists
#        same = np.intersect1d(lief_functions.addresses, offset_ghid_funcs)
#
#        lief_only = np.setdiff1d( lief_functions.addresses, offset_ghid_funcs)
#
#        ghid_only = np.setdiff1d(  offset_ghid_funcs, lief_functions.addresses )
#
#    # If we have a temporary file remove it
#    if strip_file:
#        bin_path.unlink()
#
#    return same, lief_only, ghid_only, runtime


def score_worker(bins_and_preds: List[tuple[Path, Path]]):
    """
    Worker processes to score a file
    """
    # Save the results here
    total_start_conf = ConfusionMatrix(0, 0, 0, 0)
    total_bound_conf = ConfusionMatrix(0, 0, 0, 0)
    total_end_conf = ConfusionMatrix(0, 0, 0, 0)

    for bin, pred in bins_and_preds:
        # 1. Load gnd truth
        gnd_info, gnd = gnd_truth_start_plus_len(bin)

        # 2. Load prediction
        pred = load_ghidra_prediction(pred, gnd)

        # 3. Score the prediction
        start_conf, end_conf, bound_conf = score_start_plus_len(
            gnd, pred, gnd_info.text_first_addr, gnd_info.text_last_addr
        )
        # Update the total start conf
        total_start_conf.tp += start_conf.tp
        total_start_conf.fp += start_conf.fp
        total_start_conf.fn += start_conf.fn

        # Update the total start conf
        total_end_conf.tp += end_conf.tp
        total_end_conf.fp += end_conf.fp
        total_end_conf.fn += end_conf.fn

        # Update the total start conf
        total_bound_conf.tp += bound_conf.tp
        total_bound_conf.fp += bound_conf.fp
        total_bound_conf.fn += bound_conf.fn

    return total_start_conf, total_end_conf, total_bound_conf


@app.command()
def read_results(
    results: Annotated[
        str,
        typer.Argument(
            callback=iterable_path_deep_callback,
            help="A directory that is full of results",
        ),
    ],
    bin_dir: Annotated[
        str,
        typer.Argument(
            callback=iterable_path_shallow_callback,
            help="The directory of binaires that correspond to results",
        ),
    ],
    workers: Annotated[int, typer.Option(help="Number of workers to use")] = 24,
    verbose: Annotated[bool, typer.Option(help="verbosity level")] = False,
    save_to_tex: Annotated[
        Path, typer.Option(help="Save results to a .tex file to copy and paste")
    ] = Path(""),
):
    """
    Read the results from the input dir
    """

    # Need to make sure every bin has a matching prediction file
    matching_files = {}
    for bin in bin_dir:
        for res_file in result_dir:
            if ".npz" not in res_file.name:
                continue
            elif res_file.name.replace("_result.npz", "") == bin.name:
                matching_files[bin] = res_file

    if len(matching_files.keys()) != len(bin_dir):
        print("Some bins don't have matching result file")
        raise Exception

    total_start_conf = ConfusionMatrix(0, 0, 0, 0)
    total_bound_conf = ConfusionMatrix(0, 0, 0, 0)
    total_end_conf = ConfusionMatrix(0, 0, 0, 0)

    chunk_size = int(len(matching_files.keys()) / workers)
    chunks = []
    cur_index = 0
    keys = list(matching_files.keys())

    # Divy up the work.
    for i in range(workers):
        # The last worker need to take extra bins if there was a remainder
        if i == workers - 1:
            bins = keys[cur_index::]
            # chunks.append([(bin, matching_files[bin]) for bin in ])
        else:
            bins = keys[cur_index : cur_index + chunk_size]
            # @chunks.append([(bin, matching_files[bin]) for bin in bins])
            # keys[cur_index:cur_index+chunk_size]])

        # Add a list of tuple: [(bin, prediction), (bin,prediction), ...]
        chunks.append([(bin, matching_files[bin]) for bin in bins])
        cur_index += chunk_size

    # Runs the process pool to read the results
    with Pool(processes=workers) as pool:
        results = pool.map(score_worker, chunks)

    for start_conf, end_conf, bound_conf in results:
        # Update the total start conf
        total_start_conf.tp += start_conf.tp
        total_start_conf.fp += start_conf.fp
        total_start_conf.fn += start_conf.fn

        # Update the total start conf
        total_end_conf.tp += end_conf.tp
        total_end_conf.fp += end_conf.fp
        total_end_conf.fn += end_conf.fn

        # Update the total start conf
        total_bound_conf.tp += bound_conf.tp
        total_bound_conf.fp += bound_conf.fp
        total_bound_conf.fn += bound_conf.fn

    if save_to_tex != Path(""):
        with open(save_to_tex, "w") as f:
            # Save to the file.
            # start:
            # end:
            # bounds: tp tn fp fn
            f.write("CONFUSION MATRIX:\n\n")
            cols = f" & ".join(k for k, _ in asdict(total_start_conf).items())
            f.write(cols + " \\\\ \n")
            print(asdict(total_start_conf))
            start_line = " & ".join(
                str(val) for k, val in asdict(total_start_conf).items()
            )
            f.write(start_line + " \\\\ \n")
            ends_line = " & ".join(
                str(val) for k, val in asdict(total_end_conf).items()
            )
            f.write(ends_line + " \\\\ \n")
            bounds_line = " & ".join(
                str(val) for k, val in asdict(total_bound_conf).items()
            )
            f.write(bounds_line + " \\\\ \n")

            f.write("METRICS:\n")
            start_res = calc_metrics(total_start_conf)
            cols = f" & ".join(k for k, _ in asdict(start_res).items())
            f.write(cols + " \\\\ \n")
            start_res_line = f" & ".join(
                str(val) for _, val in asdict(start_res).items()
            )
            f.write(start_res_line + " \\\\ \n")
            end_res = calc_metrics(total_end_conf)
            end_res_line = f" & ".join(str(val) for k, val in asdict(end_res).items())
            f.write(end_res_line + " \\\\ \n")
            bound_res = calc_metrics(total_bound_conf)
            bound_res_line = f" & ".join(
                str(val) for k, val in asdict(bound_res).items()
            )
            f.write(bound_res_line + " \\\\ \n")

    print(f"Total Metrics")
    print(f"Starts: {total_start_conf}")
    print(f"Starts: {calc_metrics(total_start_conf)}")
    print(f"Ends: {total_end_conf}")
    print(f"Ends: {calc_metrics(total_end_conf)}")
    print(f"Bounds: {total_bound_conf}")
    print(f"Bounds: {calc_metrics(total_bound_conf)}")
    return


# TODO: Wrapper for timing
# TODO: Choose to use an existing wrapper?
def timed_ghidra_run(
    bin_path: Path,
    post_script: Path = Path(
        "~/ghidra_scripts/List_Function_and_Entry.py"
    ).expanduser(),
    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
    analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless")
    .expanduser()
    .resolve(),
    no_analysis=False,
):

    start_time = time.time()
    # res = run_ghidra(bin_path , post_script, script_path, analyzer)
    res = NEW_run_ghidra(
        bin_path, post_script, script_path, analyzer, no_analysis=no_analysis
    )
    nonstrip_runtime = time.time() - start_time

    return res, nonstrip_runtime


def find_ghidra_offset(lief_addrs, ghidra_addrs):
    """
    Ghidra adds an offset to it's addrs, this function
    finds that offset
    """

    # The idea here is to...
    # 1. Find the space (in bytes) between all the functions
    # 2. Make a list of tuples of:
    #       (function_start_address, bytes_til_next_function)

    # Once we have this we can try to "slide" the function
    #  addresses until the two lists of bytes_til_next match

    ghid_addr_bnext = []

    # Generate a list of addrs and the # bytes till the next addr
    for i, fun in enumerate(ghidra_addrs):
        if i < len(ghidra_addrs) - 1:
            to_next = int(ghidra_addrs[i + 1]) - int(ghidra_addrs[i])
        else:
            to_next = 0
        ghid_addr_bnext.append((fun, to_next))

    offset = 0
    found_offset = False
    for i, (addr, btnext) in enumerate(lief_addrs):
        if found_offset:
            break
        for i, (ghid_addr, ghid_btnext) in enumerate(ghid_addr_bnext):
            if found_offset:
                break
            if ghid_btnext == btnext:
                offset = ghid_addr - addr
                return offset
    return offset


# def func_addrs_timed_bench(
#    bin_path: Path,
#    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
#    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
#    analyzer: Path =
#        Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
#    no_analysis=False):
#
#    # Run ghidra on unstripped binary and get function list
#    res, runtime = timed_ghidra_run(bin_path,
#                                post_script, script_path, analyzer,
#                                    no_analysis=no_analysis)
#
#    # Parse the result from the ghidra run
#    funcs = parse_for_functions(res.stdout)
#    print(f"IN FUNCS: {len(funcs.addresses)}")
#
#    return list(funcs.addresses), runtime


def create_dual_plots(
    bar_value1, bar_value2, bar_value3, pie_found, pie_total, labels_bar, labels_pie
):
    # Create a figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Bar chart
    values = [bar_value1, bar_value2, bar_value3]
    # labels = ['Value 1', 'Value 2', 'Value 3']
    labels = labels_bar
    ax1.bar(labels, values)
    ax1.set_xlabel("Metrics")
    ax1.set_ylabel("Score")
    ax1.set_title("Bar Chart")

    # Pie chart
    sizes = [pie_found, pie_total - pie_found]
    labels = labels_pie
    ax2.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90)
    ax2.axis("equal")  # Equal aspect ratio ensures that pie is drawn as a circle.
    ax2.set_title("Pie Chart")

    # Display the plots
    plt.tight_layout()
    return plt


# @app.command()
# def ghidra_funcs(
#    binary: Annotated[str, typer.Argument()],
#    cache_results: Annotated[bool, typer.Option()]=True,
#    opt_lvl: Annotated[str, typer.Option()]="",
#    ):
#
#    f_path = Path(binary)
#    if not f_path.exists():
#        print(f"No file {f_path}")
#        return
#
#    # Run the ghidra command
#    #res = run_ghidra(f_path,print_cmd=True).stdout
#    res = NEW_run_ghidra(f_path).stdout
#    #print(res)
#    if cache_results:
#        if opt_lvl == "" or opt_lvl.lower() not in ['o0','o1','o2','o3','oz','os']:
#            print("Need a good opt lvl to cache")
#
#        root_dir = Path(".ghidra_bench")
#        if not root_dir.exists():
#            root_dir.mkdir()
#
#        FILE_DATA = root_dir / Path(f"{f_path.name}_{opt_lvl.upper()}")
#
#        # Cache the result of the run
#        with open(FILE_DATA, 'w') as f:
#            json.dump({f_path.name : res},f)
#        print(f"Results for {f_path.name} cached")
#    return

# @app.command()
# def count_lief(
#    binary: Annotated[str, typer.Argument()],
#    ):
#
#    bin_path = Path(binary)
#
#    bin = lief.parse(binary)
#    text_section = bin.get_section(".text")
#    text_start = bin.imagebase + text_section.virtual_address
#    text_end = text_start + len(text_section.content)
#
#    func_starts = get_functions(bin_path)
#
#    funcs = [x for x in func_starts if x.addr > text_start and
#                                        x.addr < text_end]
#    print("Start: ", hex(text_start))
#    print("End: ", hex(text_end))
#    print("Functions in .text: ", len(funcs))
#    print("Functions: ", len(func_starts))
#    return


# @app.command()
# def count_inbetween(
#    binary: Annotated[str, typer.Argument()],
#    addr1: Annotated[str, typer.Argument()],
#    addr2: Annotated[str, typer.Argument()],
#    ):
#
#    f_path =  Path(f".ghidra_bench/{binary}.json")
#    if not f_path.exists():
#        print(f"No log for {binary}")
#        return
#
#    with open(f_path, 'r') as f:
#        res = json.load(f)
#    res = list(res.values())[0]
#
#
#
#    # True Positive
#    strip_total_func = res[1][0]
#
#    total_funcs = [ x for x in strip_total_func if
#        hex(int(x[1],16)) > hex(int(addr1,16)) and
#        hex(int(x[1],16)) < hex(int(addr2,16))]
#
#    # Total functions is true_pos + false_neg
#    print(f"True Pos + False Neg of result (total funcs): {len(strip_total_func)}")
#    print(f"In between : {len(total_funcs)}")
#    print(f"Start {hex(int(addr1,16))}")
#    print(f"End {hex(int(addr2,16))}")
#
#    return


@app.command()
def install_ghidra():
    """
    Install ghidra
    """

    # get the path of this file
    install_script = Path(os.path.abspath(__file__))

    # Install ghidra
    cmd = f"{install_script.resolve()}/setup.sh"

    try:
        os.system(cmd)
        # _ = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    # Make the ghidra_scripts dir and place the
    #  List_Function_and_Entry.py file there
    scripts = Path("~/ghidra_scripts").expanduser().resolve()
    if not scripts.exists():
        scripts.mkdir()

    # Copy the file to the location
    script_file = f"{install_script.parent}/List_Function_and_Entry.py"
    shutil.copy2(script_file, scripts)
    return


@app.command()
def test_bounds(
    bin_dir: Annotated[str, typer.Argument(help="A directory of binaires to test on")],
    output_dir: Annotated[
        str, typer.Argument(help="A directory to save the result to")
    ],
    strip_file: Annotated[
        bool, typer.Option(help="Strip the binaries before testing")
    ] = False,
    use_offset: Annotated[
        bool,
        typer.Option(
            help="Ghidra applies an 'offset' to addresses, set to True to auto detect this offset and adjust accordingly"
        ),
    ] = True,
):
    """
    Run ghidra to detect the bounds on the input files. Save results to a directory
    to be later read
    """

    # Create the pathlib objects
    binary_dir_path = Path(binary_dir)
    save_path = Path(output_dir)

    # Make the save directory
    if not save_path.exists():
        save_path.mkdir()

    # Iteravte oover the binaries and run the test
    for bin in alive_it(list(binary_dir_path.glob("*"))):
        # Make sure the bin is a file
        if not bin.is_file():
            continue

        # Make the flags list
        flags = []
        # if noanalysis:
        #    flags = ["-noanalysis"]
        # else:
        #    flags = []

        func_len_array, runtime = get_ghid_bounds(bin, flags, use_offset, strip_file)
        result_path = save_path.joinpath(f"{bin.name}")
        save_raw_experiment(bin, runtime, func_len_array, result_path)
    return


def parse_for_bounds(inp):
    """
    Parse the output from the ghidra headless analyzer to get the found
    function names and addresses
    """

    in_list = False
    names = []
    addrs = []
    lengths = []
    for line in inp.split("\n"):
        if "END FUNCTION LIST" in line:
            break
        if in_list:
            if "RIPKIT_FOUND_FUNC" in line:
                line = line.split("<RIPKIT_SEP>")
                line = [x.strip() for x in line]
                names.append(line[1])
                addrs.append(int(line[2], 16))
                lengths.append(line[3])
        if "BEGIN FUNCTION LIST" in line:
            in_list = True

    found_funcs = FoundFunctions(
        addresses=np.array(addrs), names=names, lengths=np.array(lengths)
    )
    return found_funcs


if __name__ == "__main__":
    app()
