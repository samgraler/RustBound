from dataclasses import dataclass
import typer
import os
from typing import List
from pathlib import Path
import time
import re
from itertools import chain
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
from rich.table import Table
from rich.progress import track

console = Console()


#from ripkit.cargo_picky import (
#  is_executable,
#)
ripkit_dir = Path("../ripkit").resolve()
import sys
sys.path.append (
    str(ripkit_dir)
)
from ripkit.ripbin import (
    FoundFunctions,
    calc_metrics,
    ConfusionMatrix,
    lief_gnd_truth,
    get_functions,
    save_raw_experiment,
)

app = typer.Typer()


#TODO: log dictionarires of the GhidraBenchResults
@dataclass 
class GhidraBenchResult:
    stripped_bin: bool
    without_analysis: bool
    bin_name: str
    ground_truth: List[int] 
    functions: List[int] 
    runtime: float 
    #exact_ghid_command : str

@dataclass
class ListCompare():
    intersection: List[str]
    a_only: List[str]
    b_only: List[str]



def gen_strip_file(bin_path:Path):
    '''
    Strip the passed file and return the path of the 
    stripped file
    '''

    # Copy the bin and strip it 
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
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
               analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
               hide_output=True):

    cmd_base_str = [f"{analyzer.parent}/./{analyzer.name}", "/tmp", 
               "tmp_proj", "-import", f"{bin_path}"]

    #print(f"GHID ARGS {ghid_args}")
    for x in ghid_args:
        cmd_base_str.append(x)

    cmd_str = cmd_base_str
    #print(f"THE COMMAND STR {cmd_str}")

    try:
        # remove the temporary paths from previous runs
        paths_to_remove = ["/tmp/tmp_proj.rep", "/tmp/tmp_proj.gpr"]
        paths_to_remove = [Path(x) for x in paths_to_remove]
        remove_paths(paths_to_remove)

        # Record the start time of the ghidra process 
        start = time.time()

        # Run the ghidra commad, capturing all of its output
        output = subprocess.run(cmd_str, text=True,
                                capture_output=True,
                                universal_newlines=True)
        #print(output.stdout)

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

def get_ghidra_functions(bin_path, post_script: Path = 
                         Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(), 
                         other_flags: List[str] = [] ):

    # Add to the flags
    other_flags.extend(['-postScript', f'{post_script.resolve()}'])

    print(f"FLAGS: {other_flags}")

    # Run ghidra 
    res, runtime = call_ghidra(bin_path, other_flags)

    # If it was a good run read the stdout
    #TODO: Check for bad run 
    res = res.stdout

    # Parse for functions and return the functions
    return parse_for_functions(res), runtime


def get_ghidra_bounds(bin_path, post_script: Path = 
                Path("~/ghidra_scripts/ghidra_bounds_script.py").expanduser(), 
                         other_flags: List[str] = [] ):

    # Add to the flags
    other_flags.extend(['-postScript', f'{post_script.resolve()}'])

    #print(f"FLAGS: {other_flags}")

    # Run ghidra 
    res, runtime = call_ghidra(bin_path, other_flags)

    # If it was a good run read the stdout
    #TODO: Check for bad run 
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
            to_next = int(inp_list[i+1]) - int(inp_list[i])
        else:
            to_next = 0
        new_list.append((fun, to_next))

    return new_list


def find_offset(lief_addrs, ghidra_addrs):
    '''
    Ghidra adds an offset to it's addrs, this function 
    finds that offset
    '''

    # The idea here is to...
    # 1. Find the space (in bytes) between all the functions 
    # 2. Make a list of tuples of:
    #       (function_start_address, bytes_til_next_function)

    # Once we have this we can try to "slide" the function 
    #  addresses until the two lists of bytes_til_next match

    ghid_addr_bnext =  append_bnext(ghidra_addrs)
    lief_addrs =  append_bnext(lief_addrs)



    # BUG: This is temp make sure to take it away 
    # BUG Write this to save the bnext to files 
    with open("GHID_FUNC", 'w') as f:
        for i, (func, bnext) in enumerate(ghid_addr_bnext):
            f.write(f"{func} : {bnext}\n")

    with open("LIEF_FUNC", 'w') as f:
        for i, (func,bnext) in enumerate(lief_addrs):
            f.write(f"{func} : {bnext}\n")





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

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}
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


def inbetween_inc(x,min,max):
    return x <= max and x >= min

def get_ghid_bounds(bin_path, ghidra_flags, use_offset:bool, strip_the_bin: bool = True):
    """
    Run a test of lief vs ghidra 

    Seeing how the function address compare for a binary

    NOTICE: Stripping the file will temporarily make a new file 
    """

    # Get the functions from lief
    lief_functions =  get_lief_functions(bin_path)

    # Strip the file is desired:
    post_script = Path(os.path.abspath(__file__)).parent / "ghidra_bounds_script.py"

    # Get the functons from ghidra 
    ghidra_functions, runtime = get_ghidra_bounds(bin_path, 
                                        post_script=post_script.resolve(),
                                        other_flags=ghidra_flags)

    if strip_the_bin:
        bin_path = gen_strip_file(bin_path)
    try:
        offset = find_offset(list(lief_functions.addresses), 
                             list(ghidra_functions.addresses))
    finally:
        if strip_the_bin:
            bin_path.unlink()

    # Apply the offset
    offset_ghid_funcs = np.array([x-offset for x in ghidra_functions.addresses] )

    if use_offset:
        func_len_array = np.concatenate((offset_ghid_funcs.T.reshape(-1,1), 
                                ghidra_functions.lengths.T.reshape(-1,1)), axis=1)
    else:
        func_len_array = np.concatenate((ghidra_functions.addresses.T.reshape(-1,1), 
                                         ghidra_functions.lengths.T.reshape(-1,1)), axis=1)
    return func_len_array, runtime

#def test_lief_v_ghid(bin_path, ghidra_flags, strip_file, save_to_location: Path = None ):
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


@app.command()
def read_bounds_raw(
    input_dir : Annotated[str,typer.Argument()],
    bin_dir: Annotated[str, typer.Argument()],
    verbose: Annotated[bool, typer.Option()] = False,
    ):
    '''
    Read the input dir and compute results using the lief module
    '''

    input_path = Path(input_dir)
    if not input_path.exists(): 
        print(f"Inp dir {input_dir} is not a dir")
        return

    bin_path = Path(bin_dir)
    if not bin_path.exists():
        print(f"Bin dir {bin_dir} is not a dir")
        return

    matching_files = {}
    for bin in bin_path.glob('*'):
        for res_file in input_path.rglob('*'):
            if ".npz" not in res_file.name:
                continue
            elif res_file.name.replace("_result.npz","") == bin.name:
                matching_files[bin] = res_file

    if len(matching_files.keys()) != len(list(bin_path.glob('*'))):
        print(f"Some bins don't have matching result file")
        raise Exception


    total_start_conf = ConfusionMatrix(0,0,0,0)
    total_bound_conf = ConfusionMatrix(0,0,0,0)
    total_bytes = 0

    for bin in alive_it(list(matching_files.keys())):
        # Init the confusion matrix for this bin
        start_conf = ConfusionMatrix(0,0,0,0)
        bound_conf = ConfusionMatrix(0,0,0,0)


        # 1  - Ground truth for bin file 
        gnd_truth = lief_gnd_truth(bin.resolve())
        gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                                    gnd_truth.func_lens.T.reshape(-1,1)), axis=1)


        # 2 - Find the npz with the ghidra funcs and addrs, chop of functions that 
        #     are out-of-bounds of the lief functions (these are functions that are
        #       likely outside of the .text section)
        ghid_funcs = read_ghid_npz(matching_files[bin])

        # 3 - Apply the offset to the ghidra funcs
        offset = find_offset(sorted(gnd_matrix[:,0].tolist()), 
                             sorted((ghid_funcs[:,0].tolist())))

        offset_funcs = ghid_funcs.copy()
        offset_funcs[:,0] += offset

        # 4 - Mask the array so we only include bytes in .text
        mask = ((ghid_funcs[:,0] <= np.max(gnd_truth.func_addrs)) & 
                    ghid_funcs[:,0] >= np.min(gnd_truth.func_addrs))
        filt_ghid_funcs= ghid_funcs[mask]

        mask = ((offset_funcs[:,0]  < np.max(gnd_truth.func_addrs)) & 
                    (offset_funcs[:,0] >  np.min(gnd_truth.func_addrs)))
        filt_offset_funcs = offset_funcs[mask]

        # 3 - Compare the two lists

        # Get all the start addrs that are in both, in ghid only, in gnd_trush only
        start_conf.tp=len(np.intersect1d(gnd_matrix[:,0], filt_offset_funcs[:,0]))
        start_conf.fp=len(np.setdiff1d( filt_offset_funcs[:,0], gnd_matrix[:,0] ))
        start_conf.fn=len(np.setdiff1d(gnd_matrix[:,0], filt_offset_funcs[:,0]))

        # tp + fp = Total predicted
        if not start_conf.tp + start_conf.fp == filt_offset_funcs.shape[0]:
            print(f"{start_conf.tp}")
            print(f"{start_conf.fp}")
            print(f"{filt_offset_funcs.shape[0]}")
            raise Exception

        # tp + fn = total pos
        if not start_conf.tp + start_conf.fn == gnd_matrix.shape[0]:
            print(f"{start_conf.fp}")
            print(f"{start_conf.fn}")
            print(f"{filt_offset_funcs.shape[0]}")
            raise Exception

        # Check the predicted bounds for correctness
        for row in filt_offset_funcs:
            if np.any(np.all(row == gnd_matrix, axis=1)): 
                bound_conf.tp+=1
            else:
                bound_conf.fp+=1

        # Check to see how many false negative there were 
        for row in gnd_matrix:
            if not np.any(np.all(row == filt_offset_funcs, axis=1)):
                bound_conf.fn+=1

        total_bytes += gnd_truth.num_bytes

        total_start_conf.tp += start_conf.tp
        total_start_conf.fp += start_conf.fp
        total_start_conf.fn += start_conf.fn

        total_bound_conf.tp += bound_conf.tp
        total_bound_conf.fp += bound_conf.fp
        total_bound_conf.fn += bound_conf.fn

        if verbose:
            print(f"binary: {bin.name}")
            print(f"Starts: {start_conf}")
            print(f"Metrics: {calc_metrics(start_conf)}")
            print(f"Bounds: {bound_conf}")
            print(f"Metrics: {calc_metrics(bound_conf)}")

    print(f"Total Metrics")
    print(f"Starts: {calc_metrics(total_start_conf)}")
    print(f"Bounds: {calc_metrics(total_bound_conf)}")

    return 

def read_ghid_npz(inp: Path)->np.ndarray:
    '''
    Read the ghid npz
    '''
    npz_file = np.load(inp)
    return npz_file[list(npz_file.keys())[0]].astype(int)

@app.command()
def read_comparison_file(
    input : Annotated[str,typer.Argument()],
    list_fn: Annotated[bool, typer.Option(help="List the false neg's")] = False,
    list_fp: Annotated[bool, typer.Option(help="List the false pos's")] = False,
    ):
    '''
    Read a single comparison file
    '''

    # Read the file if it exists
    if not (file:=Path(input)).exists():
        return
    else:
        with open(file, 'r') as f:
            data = json.load(f)

    if data == {}:
        print(f"No data in file {file}")
        return


    # Read in the results 
    tp = len(data['same'])
    fp = len(data['ghid_only'])
    fn = len(data['lief_only'])
    filesize = data['filesize']
    runtime = data['runtime']


    if list_fn:
        print("FN | int | hex")
        for addr in data['lief_only']:
            print(f"FN | {addr} | {hex(addr)}")

    if list_fp:
        print("FP | int | hex")
        for addr in data['ghid_only']:
            print(f"FP | {addr} | {hex(addr)}")

    print(f"BPS: {filesize / runtime}")

    if tp > 0:
        prec = tp/(tp+fp)
        recall = tp/(tp+fn)
        f1 = 2 * prec* recall / (prec+recall)

        print(f"Prec: {prec}")
        print(f"Recall: {recall}")
        print(f"F1 : {f1}")
    else:
        print(f"Analyzed tp is 0")
    return

@app.command()
def read_comparison_dir(
    dir : Annotated[str,typer.Argument()],
    ):


    #keys = ['tp', 'fp', 'fn', 'runtime']
    keys = ['tp', 'fp', 'fn', 'runtime', 'filesize']

    analyzed = { k: 0 for k in keys}
    not_analyzed = { k: 0 for k in keys}


    for file in alive_it(Path(dir).glob('*')):
        # IF STRIPPED in name it was stripped 
        # IF analysis in the name it was anaylzed

        data = {}
        with open(file, 'r') as f:
            data = json.load(f)

        if data == {}:
            continue

        if "NOANALYSIS" in file.name:
            was_analyzed = False
        else:
            was_analyzed = True
        
        if "STRIPPED" in file.name:
            stripped = True
        else:
            stripped = False


        if stripped and was_analyzed:
            analyzed['tp'] += len(data['same'])
            analyzed['fp'] += len(data['ghid_only'])
            analyzed['fn'] += len(data['lief_only'])
            analyzed['filesize'] += data['filesize']
            analyzed['runtime'] += data['runtime']


        if stripped and not was_analyzed:
            not_analyzed['tp'] += len(data['same'])
            not_analyzed['fp'] += len(data['ghid_only'])
            not_analyzed['fn'] += len(data['lief_only'])
            not_analyzed['runtime'] += data['runtime']
            not_analyzed['filesize'] += data['filesize']

    print("ANALYZED:")
    for key in analyzed.keys():
        print(f"{key} : {analyzed[key]}")

    print(f"BPS: {analyzed['filesize'] / analyzed['runtime']}")

    if analyzed['tp'] > 0:
        prec = analyzed['tp']/(analyzed['tp']+analyzed['fp'])
        recall = analyzed['tp']/(analyzed['tp']+analyzed['fn'])
        f1 = 2 * prec* recall / (prec+recall)

        print(f"Prec: {prec}")
        print(f"Recall: {recall}")
        print(f"F1 : {f1}")
    else:
        print(f"Analyzed tp is 0")



    print("+=====================+")
    print("NOT ANALYZED:")
    for key in not_analyzed.keys():
        print(f"{key} : {not_analyzed[key]}")

    if not_analyzed['tp'] > 0:
        prec = not_analyzed['tp']/(not_analyzed['tp']+not_analyzed['fp'])
        recall = not_analyzed['tp']/(not_analyzed['tp']+not_analyzed['fn'])
        f1 = 2 * prec* recall / (prec+recall)
        print(f"Prec: {prec}")
        print(f"Recall: {recall}")
        print(f"F1 : {f1}")

    return

def save_comparison(bin, stripped: bool, same, ghid_only, lief_only, noanalysis:bool, out_file:Path, runtime: int):
    """
    Save the comparison to a result json
    """

    # If the file is to be stripepd strip it now 
    bin = gen_strip_file(bin)

    # Creat the data dictionary to be saved
    data = {
        'binary_name' : bin.name,
        'stripped' : stripped,
        'noanalysis' : noanalysis,
        'same' : same.tolist(),
        'ghid_only' : ghid_only.tolist(),
        'lief_only' : lief_only.tolist(),
        'runtime' : runtime,
        'filesize' : bin.stat().st_size
    }

    # Delete the stripped version of the binary
    bin.unlink()

    # Dump the file to the json file
    with open(out_file, 'w') as f:
        json.dump(data,f)
    return


#@app.command()
#def cli_test(
#    binary: Annotated[str, typer.Argument()],
#    noanalysis: Annotated[bool, typer.Option()]=True,
#    strip_file: Annotated[bool,typer.Option()]=False,
#    save_results: Annotated[str,typer.Option()]=None,
#    show_summary: Annotated[bool,typer.Option()]=False,
#    ):
#
#    # Make a pathlib obj for the binary
#    bin_path = Path(binary).resolve()
#
#    # Return if the bin doesn't exist
#    if not bin_path.exists():
#        print(f"Bin {bin_path} doesn't exist")
#        return
#
#    # Make the flags list 
#    if noanalysis:
#        flags = ["-noanalysis"]
#    else:
#        flags = []
#
#    # Run the ghidra compare
#    same, lief_only, ghid_only, runtime = test_lief_v_ghid(bin_path,flags, strip_file)
#
#    if save_results is not None:
#        save_comparison(bin_path, strip_file, same, ghid_only, lief_only, noanalysis, Path(save_results), runtime)
#
#    if show_summary:
#        # Calc metrics
#        print(f"Ghid tp: {len(same)}")
#        print(f"Ghid fp: {len(ghid_only)}")
#        print(f"Ghid fn: {len(lief_only)}")
#
#        print(f"Total lief : {len(same)+len(lief_only)}")
#        print(f"Total ghid: {len(same)+len(ghid_only)}")
#
#    return


@app.command()
def test_bounds(
        binary_dir: Annotated[str, typer.Argument()],
        output_dir: Annotated[str,typer.Argument()],
        #noanalysis: Annotated[bool, typer.Option()]=False,
        strip_file: Annotated[bool,typer.Option()]=False,
        use_offset: Annotated[bool, typer.Option()]=True,
    ):

    # Create the pathlib objects 
    binary_dir_path = Path(binary_dir)
    save_path = Path(output_dir)

    # Make the save directory
    if not save_path.exists():
        save_path.mkdir()

    # Iteravte oover the binaries and run the test
    for bin in alive_it(list(binary_dir_path.glob('*'))):
        # Make sure the bin is a file
        if not bin.is_file():
            continue

        # Make the flags list 
        flags = []
        #if noanalysis:
        #    flags = ["-noanalysis"]
        #else:
        #    flags = []

        func_len_array, runtime = get_ghid_bounds(bin, flags, use_offset, strip_file)
        result_path = save_path.joinpath(f"{bin.name}")
        save_raw_experiment(bin, runtime, func_len_array, result_path)
    return





#@app.command()
#def batch_test_ghidra(
#        binary_dir: Annotated[str, typer.Argument()],
#        save_results_dir: Annotated[str,typer.Option()],
#        noanalysis: Annotated[bool, typer.Option()]=False,
#        strip_file: Annotated[bool,typer.Option()]=False,
#        show_running_res: Annotated[bool, typer.Option()]=False,
#    ):
#
#    # Create the pathlib objects 
#    binary_dir_path = Path(binary_dir)
#    save_path = Path(save_results_dir)
#
#    # Make the save directory
#    if not save_path.exists():
#        save_path.mkdir()
#
#    # Decide the postfixes for the names
#    if strip_file:
#        strip_post = "STRIPPED"
#    else:
#        strip_post = "NONSTRIPPED"
#    if noanalysis:
#        analysis_post = "NOANALYSIS"
#    else:
#        analysis_post = "ANALYSIS"
#
#    tp = 0
#    fp = 0
#    fn = 0
#
#    # Iteravte oover the binaries and run the test
#    for bin in alive_it(list(binary_dir_path.glob('*'))):
#        # Make sure the bin is a file
#        if not bin.is_file():
#            continue
#
#        # Make the flags list 
#        if noanalysis:
#            flags = ["-noanalysis"]
#            print("analysis OFF")
#        else:
#            print("analysis ON")
#            flags = []
#
#        # Run the ghidra compare
#        same, lief_only, ghid_only, runtime = test_lief_v_ghid(bin, 
#                                            flags, strip_file)
#        tp += len(same)
#        fn += len(lief_only)
#        fp += len(ghid_only)
#
#        if show_running_res:
#            tot_bytes = len(lief_only) + len(same)
#            print(f"tp: {tp}")
#            print(f"fp: {fn}")
#            print(f"fn: {fp}")
#            print(f"Runtime: {runtime}")
#            print(f"Total bytes: {tot_bytes}")
#            print(f"Byte per second = {runtime/tot_bytes}")
#
#        # define the result path 
#        result_path = save_path / Path(f"{bin.name}_{strip_post}_{analysis_post}")
#
#        # Save the results
#        save_comparison(bin, strip_file, same, ghid_only, lief_only, noanalysis, result_path, runtime)
#
#    return




def NEW_run_ghidra(
               bin_path: Path, 
               post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
               script_path: Path = Path("~/ghidra_scripts/").expanduser(),
               analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
                no_analysis: bool = False, 
               hide_output=True):
 
    if no_analysis:
        print(f"Running without analysis on {bin_path}")
        cmd_str = [f"{analyzer.parent}/./{analyzer.name}", "/tmp", 
               "tmp_proj", "-import", f"{bin_path}", "-scriptPath", 
               f"{script_path}", "-postScript", f"{post_script.name}", 
               "-noanalysis"
               ]
    else: 
 
        cmd_str = [f"{analyzer.parent}/./{analyzer.name}", "/tmp", 
                   "tmp_proj", "-import", f"{bin_path}", 
                   "-scriptPath", f"{script_path}",
                   "-postScript", f"{post_script.name}",
               ]
    try:
        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
        for path in paths_to_remove:
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()


        output = subprocess.run(cmd_str, text=True,
                                capture_output=True,
                                universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"COMMAND IS : {cmd_str}")
        print("Error running command:", e)
        return []
    finally:
        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
        for path in paths_to_remove:
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()

def parse_for_bounds(inp):
    '''
    Parse the output from the ghidra headless analyzer to get the found 
    function names and addresses
    '''

    in_list = False
    names = []
    addrs = []
    lengths = []
    for line in inp.split("\n"):
        if "END FUNCTION LIST" in line:
            break
        if in_list:
            if "RIPKIT_FOUND_FUNC" in line:
                line = line.split('<RIPKIT_SEP>')
                line = [x.strip() for x in line]
                names.append(line[1])
                addrs.append(int(line[2],16))
                lengths.append(line[3])
        if "BEGIN FUNCTION LIST" in line:
            in_list = True

    found_funcs = FoundFunctions(addresses = np.array(addrs), names=names, lengths=np.array(lengths))
    return found_funcs



def parse_for_functions(inp):
    '''
    Parse the output from the ghidra headless analyzer to get the found 
    function names and addresses
    '''

    in_list = False
    names = []
    addrs = []
    for line in inp.split("\n"):
        if "END FUNCTION LIST" in line:
            break
        if in_list:
            if "FOUND_FUNC" in line:
                line = line.replace("FOUND_FUNC","")
                # The fist element is the empty string, drop it 
                name_addr = line.strip().replace('(','').replace(')','').split('<BENCH_SEP>')[1::]
                # Strip the name and addr 
                name_addr = [x.strip() for x in name_addr]
                # The addr is in hex, convert to int
                name_addr[1] = int(name_addr[1],16)
                #res.append(name_addr)
                names.append(name_addr[0])
                addrs.append(name_addr[1])
        if "BEGIN FUNCTION LIST" in line:
            in_list = True

    found_funcs = FoundFunctions(addresses = np.array(addrs), names=names, lengths=np.array([]))

    return found_funcs


def parse_ground_truth(bin_path: Path):
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


    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}
    ret_list = []


    # This enumerate the .text byte and sees which ones are functions
    for i, _ in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            ret_list.append(address)

    # This will hold the address of each byte, and the number of 
    # bytes until the next function start 
    # This help with finding the offset for ghidra
    addrs_btill_next = []
    for i, addr in enumerate(ret_list):
        if i < len(ret_list) -1:
            till_next = ret_list[i+1] - addr
        else:
            till_next = 0
        addrs_btill_next.append((addr,till_next))
    return addrs_btill_next

#def list_operations_raw_values(list_a, list_b):
#
#    # Calculate the intersection of the two lists
#    intersection = list(set(list_a) & set(list_b))
#
#    # Calculate elements in list A that are not in list B
#    a_not_in_b = list(set(list_a) - set(list_b))
#
#    # Calculate elements in list B that are not in list A
#    b_not_in_a = list(set(list_b) - set(list_a))
#
#    return intersection, a_not_in_b, b_not_in_a


    
#TODO: Wrapper for timing
#TODO: Choose to use an existing wrapper?
def timed_ghidra_run(bin_path: Path, 
    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
    analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
    no_analysis=False
                     ):

    start_time = time.time()
    #res = run_ghidra(bin_path , post_script, script_path, analyzer)
    res = NEW_run_ghidra(bin_path , post_script, script_path, analyzer,
                         no_analysis=no_analysis)
    nonstrip_runtime = time.time() - start_time

    return res, nonstrip_runtime

def find_ghidra_offset(lief_addrs, ghidra_addrs):
    '''
    Ghidra adds an offset to it's addrs, this function 
    finds that offset
    '''

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
            to_next = int(ghidra_addrs[i+1]) - int(ghidra_addrs[i])
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

def func_addrs_timed_bench(
    bin_path: Path, 
    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
    analyzer: Path = 
        Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
    no_analysis=False):

    # Run ghidra on unstripped binary and get function list
    res, runtime = timed_ghidra_run(bin_path, 
                                post_script, script_path, analyzer,
                                    no_analysis=no_analysis)

    # Parse the result from the ghidra run
    funcs = parse_for_functions(res.stdout)
    print(f"IN FUNCS: {len(funcs.addresses)}")

    return list(funcs.addresses), runtime

def create_dual_plots(bar_value1, bar_value2, bar_value3, pie_found, pie_total, labels_bar, labels_pie):
    # Create a figure with two subplots
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Bar chart
    values = [bar_value1, bar_value2, bar_value3]
    #labels = ['Value 1', 'Value 2', 'Value 3']
    labels = labels_bar
    ax1.bar(labels, values)
    ax1.set_xlabel('Metrics')
    ax1.set_ylabel('Score')
    ax1.set_title('Bar Chart')

    # Pie chart
    sizes = [pie_found, pie_total - pie_found]
    labels = labels_pie
    ax2.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax2.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    ax2.set_title('Pie Chart')

    # Display the plots
    plt.tight_layout()
    return plt



@app.command()
def ghidra_funcs(
    binary: Annotated[str, typer.Argument()],
    cache_results: Annotated[bool, typer.Option()]=True,
    opt_lvl: Annotated[str, typer.Option()]="",
    ):

    f_path = Path(binary)
    if not f_path.exists():
        print(f"No file {f_path}")
        return

    # Run the ghidra command
    #res = run_ghidra(f_path,print_cmd=True).stdout
    res = NEW_run_ghidra(f_path).stdout
    #print(res)
    if cache_results:
        if opt_lvl == "" or opt_lvl.lower() not in ['o0','o1','o2','o3','oz','os']:
            print("Need a good opt lvl to cache")

        root_dir = Path(".ghidra_bench")
        if not root_dir.exists():
            root_dir.mkdir()

        FILE_DATA = root_dir / Path(f"{f_path.name}_{opt_lvl.upper()}")

        # Cache the result of the run
        with open(FILE_DATA, 'w') as f:
            json.dump({f_path.name : res},f)
        print(f"Results for {f_path.name} cached")
    return

@app.command()
def count_lief(
    binary: Annotated[str, typer.Argument()],
    ):

    bin_path = Path(binary)

    bin = lief.parse(binary)
    text_section = bin.get_section(".text")
    text_start = bin.imagebase + text_section.virtual_address
    text_end = text_start + len(text_section.content)

    func_starts = get_functions(bin_path)

    funcs = [x for x in func_starts if x.addr > text_start and
                                        x.addr < text_end]
    print("Start: ", hex(text_start))
    print("End: ", hex(text_end))
    print("Functions in .text: ", len(funcs))
    print("Functions: ", len(func_starts))
    return


@app.command()
def count_inbetween(
    binary: Annotated[str, typer.Argument()],
    addr1: Annotated[str, typer.Argument()],
    addr2: Annotated[str, typer.Argument()],
    ):

    f_path =  Path(f".ghidra_bench/{binary}.json")
    if not f_path.exists():
        print(f"No log for {binary}")
        return

    with open(f_path, 'r') as f:
        res = json.load(f)
    res = list(res.values())[0]



    # True Positive
    strip_total_func = res[1][0]

    total_funcs = [ x for x in strip_total_func if 
        hex(int(x[1],16)) > hex(int(addr1,16)) and 
        hex(int(x[1],16)) < hex(int(addr2,16))]

    # Total functions is true_pos + false_neg
    print(f"True Pos + False Neg of result (total funcs): {len(strip_total_func)}")
    print(f"In between : {len(total_funcs)}")
    print(f"Start {hex(int(addr1,16))}")
    print(f"End {hex(int(addr2,16))}")

    return

@app.command()
def install_ghidra():
    '''
    Install ghidra
    '''

    # get the path of this file
    install_script = Path(os.path.abspath(__file__)).parent

    # Install ghidra
    cmd = f"{install_script.resolve()}/setup.sh"

    try:
        os.system(cmd)
        #_ = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    # Make the ghidra_scripts dir and place the 
    #  List_Function_and_Entry.py file there
    scripts = Path("~/ghidra_scripts")
    if not scripts.exists():
        scripts.mkdir()

    # Copy the file to the location
    script_file = install_script.parent / "List_Function_and_Entry.py"
    shutil.copy2(script_file, scripts)

    return


if __name__ == "__main__":
    app()
