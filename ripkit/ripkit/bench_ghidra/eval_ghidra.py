from dataclasses import dataclass
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
    get_functions,
)
import typer

app = typer.Typer()



@dataclass
class FoundFunctions():
    addresses: np.ndarray
    names: List[str]

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

    print(f"GHID ARGS {ghid_args}")
    for x in ghid_args:
        cmd_base_str.append(x)

    cmd_str = cmd_base_str
    print(f"THE COMMAND STR {cmd_str}")

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

    # Start time of process
    start = time.time()

    # Run ghidra 
    res, runtime = call_ghidra(bin_path, other_flags)



    # If it was a good run read the stdout
    #TODO: Check for bad run 
    res = res.stdout

    # Parse for functions and return the functions
    return parse_for_functions(res), runtime


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
    #with open("GHID_FUNC", 'w') as f:
    #    for i, (func, bnext) in enumerate(ghid_addr_bnext):
    #        f.write(f"{func} : {bnext}\n")

    #with open("LIEF_FUNC", 'w') as f:
    #    for i, (func,bnext) in enumerate(lief_addrs):
    #        f.write(f"{func} : {bnext}\n")





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

    # This enumerate the .text byte and sees which ones are functions
    for i, _ in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            func_addrs.append(address)
            func_names.append(func_start_addrs[address][0])

    # Get the functions from the bin 
    functions = get_functions(bin_path)

    # Return the addrs and names 
    func_addrs = np.array(func_addrs)
    return FoundFunctions(func_addrs, func_names)


def inbetween_inc(x,min,max):
    return x <= max and x >= min

def test_lief_v_ghid(bin_path, ghidra_flags, strip_file, save_to_location: Path = None ):
    """
    Run a test of lief vs ghidra 

    Seeing how the function address compare for a binary

    NOTICE: Stripping the file will temporarily make a new file 
    """

    # Get the functions from lief
    lief_functions =  get_lief_functions(bin_path)

    # Strip the file is desired:
    if strip_file:
        bin_path = gen_strip_file(bin_path)

    # Get the functons from ghidra 
    ghidra_functions, runtime = get_ghidra_functions(bin_path,
                                    other_flags=ghidra_flags)

    #TODO: Offset 
    # Need to apply the offset to the ghidra functions 
    # Need to find out under what conditions the functions 
    # are slid
    offset = find_offset(list(lief_functions.addresses), 
                         list(ghidra_functions.addresses))


    # Ghidra includes functions that are not in the .text range
    # therefore only include functions that are within the bounds
    # of the lief functions
    ghid_funcs = [x for x in ghidra_functions.addresses if 
                  x >= min(lief_functions.addresses) and 
                  x <= max(lief_functions.addresses)]

    # Apply the offset
    offset_ghid_funcs = [x-offset for x in ghidra_functions.addresses if 
        (x-offset) >= min(lief_functions.addresses) and 
        (x-offset) <= max(lief_functions.addresses)]

    # BUG: The offset 
    # TODO: This is related to the above, find out exactly when the offset
    #       needs to be applied
    use_offset = True
    if not use_offset:
        # Compare the lists 
        same = np.intersect1d(lief_functions.addresses, ghid_funcs)

        lief_only = np.setdiff1d( lief_functions.addresses, ghid_funcs)

        ghid_only = np.setdiff1d( ghid_funcs, lief_functions.addresses )

    else:
        print(f"Using an offset of {offset}")
        # Compare the lists 
        same = np.intersect1d(lief_functions.addresses, offset_ghid_funcs)

        lief_only = np.setdiff1d( lief_functions.addresses, offset_ghid_funcs)

        ghid_only = np.setdiff1d(  offset_ghid_funcs, lief_functions.addresses )

    # If we have a temporary file remove it
    if strip_file:
        bin_path.unlink()

    return same, lief_only, ghid_only, runtime

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

    # Dump the file to the json file
    with open(out_file, 'w') as f:
        json.dump(data,f)
    return


@app.command()
def cli_test(
    binary: Annotated[str, typer.Argument()],
    noanalysis: Annotated[bool, typer.Option()]=True,
    strip_file: Annotated[bool,typer.Option()]=False,
    save_results: Annotated[str,typer.Option()]=None,
    show_summary: Annotated[bool,typer.Option()]=False,
    ):

    # Make a pathlib obj for the binary
    bin_path = Path(binary).resolve()

    # Return if the bin doesn't exist
    if not bin_path.exists():
        print(f"Bin {bin_path} doesn't exist")
        return

    # Make the flags list 
    if noanalysis:
        flags = ["-noanalysis"]
    else:
        flags = []

    # Run the ghidra compare
    same, ghid_only, lief_only, runtime = test_lief_v_ghid(bin_path,flags, strip_file)

    if save_results is not None:
        save_comparison(bin_path, strip_file, same, ghid_only, lief_only, noanalysis, Path(save_results), runtime)

    if show_summary:
        # Calc metrics
        print(f"Ghid tp: {len(same)}")
        print(f"Ghid fp: {len(ghid_only)}")
        print(f"Ghid fn: {len(lief_only)}")

        print(f"Total lief : {len(same)+len(lief_only)}")
        print(f"Total ghid: {len(same)+len(ghid_only)}")

    return

@app.command()
def batch_test_ghidra(
        binary_dir: Annotated[str, typer.Argument()],
        save_results_dir: Annotated[str,typer.Option()],
        noanalysis: Annotated[bool, typer.Option()]=False,
        strip_file: Annotated[bool,typer.Option()]=False,
        show_running_res: Annotated[bool, typer.Option()]=False,
    ):

    # Create the pathlib objects 
    binary_dir_path = Path(binary_dir)
    save_path = Path(save_results_dir)

    # Make the save directory
    if not save_path.exists():
        save_path.mkdir()

    # Decide the postfixes for the names
    if strip_file:
        strip_post = "STRIPPED"
    else:
        strip_post = "NONSTRIPPED"
    if noanalysis:
        analysis_post = "NOANALYSIS"
    else:
        analysis_post = "ANALYSIS"

    tp = 0
    fp = 0
    fn = 0

    # Iteravte oover the binaries and run the test
    for bin in alive_it(list(binary_dir_path.glob('*'))):
        # Make sure the bin is a file
        if not bin.is_file():
            continue

        # Make the flags list 
        if noanalysis:
            flags = ["-noanalysis"]
            print("analysis OFF")
        else:
            print("analysis ON")
            flags = []

        # Run the ghidra compare
        same, ghid_only, lief_only, runtime = test_lief_v_ghid(bin, 
                                            flags, strip_file)
        tp += len(same)
        fn += len(lief_only)
        fp += len(ghid_only)

        if show_running_res:
            tot_bytes = len(lief_only) + len(same)
            print(f"tp: {tp}")
            print(f"fp: {fn}")
            print(f"fn: {fp}")
            print(f"Runtime: {runtime}")
            print(f"Total bytes: {tot_bytes}")
            print(f"Byte per second = {runtime/tot_bytes}")

        # define the result path 
        result_path = save_path / Path(f"{bin.name}_{strip_post}_{analysis_post}")

        # Save the results
        save_comparison(bin, strip_file, same, ghid_only, lief_only, noanalysis, result_path, runtime)
    return




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

    found_funcs = FoundFunctions(addresses = np.array(addrs), names=names)

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

def list_operations_raw_values(list_a, list_b):

    # Calculate the intersection of the two lists
    intersection = list(set(list_a) & set(list_b))

    # Calculate elements in list A that are not in list B
    a_not_in_b = list(set(list_a) - set(list_b))

    # Calculate elements in list B that are not in list A
    b_not_in_a = list(set(list_b) - set(list_a))

    return intersection, a_not_in_b, b_not_in_a




def list_operations(list_a, list_b):

    # Calculate the intersection of the two lists
    intersection = list(set(list_a) & set(list_b))

    # Calculate elements in list A that are not in list B
    a_not_in_b = list(set(list_a) - set(list_b))

    # Calculate elements in list B that are not in list A
    b_not_in_a = list(set(list_b) - set(list_a))

    res = ListCompare(intersection, a_not_in_b, b_not_in_a)

    return res



    
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

    return list(funcs.addresses), runtime
   

def NEW_ghidra_bench_functions(
    bin_path: Path, 
    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
    analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
    verbose=False,
    no_analysis=False):


    # Load ground truth 
    ground_truth = parse_ground_truth(bin_path)
    gnd_addrs = [x[0] for x in ground_truth]

    # Run ghidra and get the address of the function and the runtime 
    # for ghidra's analysis
    nonstrip_funcs, nonstrip_runtime = func_addrs_timed_bench(bin_path,
                                post_script, script_path, analyzer,
                                no_analysis=no_analysis)

    # Find the offset for the ghidra addrs and apply it
    offset =  find_ghidra_offset(ground_truth, nonstrip_funcs)

    print(f"The max nonstrip func is {max(nonstrip_funcs)}")
    print(f"The min nonstrip func is {min(nonstrip_funcs)}")

    nonstrip_func_addrs = [x-offset for x in nonstrip_funcs
            if x-offset > min(gnd_addrs) and 
                x-offset < max(gnd_addrs)]


    # Copy the bin and strip it 
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    strip_bin = strip_bin.resolve()
    shutil.copy(bin_path, Path(strip_bin))
    print(f"The new bin is at {strip_bin}")

    try:
        _ = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return []

    # Run ghidra on stripped bin and get function list - and time it 
    strip_res, strip_runtime = timed_ghidra_run(strip_bin , post_script, 
                                                script_path, analyzer,
                                                no_analysis=no_analysis)

    #TODO: Why doesn't ghidra apply the offset for the 
    #   stripped version of files
    # BUG It does appy the offset for stripped version with no anaylsis 
    strip_funcs = parse_for_functions(strip_res.stdout)
    strip_funcs = list(strip_funcs.addresses)

    if no_analysis is True:
        offset =  find_ghidra_offset(ground_truth, strip_funcs)
        print(f"Using an offset of {offset}")
        strip_funcs = [x-offset for x in strip_funcs]

    print(f"The length of strip funcs is {len(strip_funcs)}")

    # Delete the stripped binary
    strip_bin.unlink()

    # Only include the addrs that are in the .text section
    strip_func_addrs = [x for x in strip_funcs if 
        x > min(gnd_addrs) and x < max(gnd_addrs) 
    ]

    # Get the overlaps and unique values in the lists
    #nonstrip_v_truth = list_operations(nonstrip_func_addrs, gnd_addrs)
    #strip_v_truth = list_operations(strip_func_addrs, gnd_addrs)
    #nonstrip_v_strip = list_operations(nonstrip_func_addrs, gnd_addrs)

    nonstrip_v_truth = list_operations_raw_values(nonstrip_func_addrs, gnd_addrs)

    print("NONSTRIP !!!!!!!!!!!!!!!!!!!!!!!!!")
    print(f"Nonstrip TP: {len(nonstrip_v_truth[0])}")

    strip_v_truth = list_operations_raw_values(strip_func_addrs, gnd_addrs)
    nonstrip_v_strip = list_operations_raw_values(nonstrip_func_addrs, gnd_addrs)

    print("NONSTRIP !!!!!!!!!!!!!!!!!!!!!!!!!")
    print(f"AGAIN Nonstrip TP: {len(nonstrip_v_truth[0])}")

    print("HHHHHHHHHHHHHHHEEEEEEEEEEEEEEEEEEEEEEEEEEEERRRRRRR")
    print(f" strip_v_truch...")
    print(f"Strip has {len(strip_func_addrs)}")
    print(f"The interesetiob has {len(strip_v_truth[0])}")
    print(f"The strip has unique {len(strip_v_truth[1])})")
    print(f"The gnd has unqie {len(strip_v_truth[2])})")

    #if verbose:
    #    print(f"Lief first func : {min(ground_truth)}")
    #    print(f"Ghid first func : {min(nonstrip_func_addrs)}")
    #          
    #    print(f"Total lief functions {len(ground_truth)}")
    #    print(f"Total ghidra in .text {len(nonstrip_func_addrs)}")

    #    print(f"Nonstrip: {len(nonstrip_v_truth.intersection)} true pos")
    #    print(f"Nonstrip: {len(nonstrip_v_truth.b_only)} false neg")
    #    print(f"Nonstrip: {len(nonstrip_v_truth.a_only)} false pos")

    #    print(f"strip: {len(strip_v_truth.intersection)} tru pos")
    #    print(f"strip: {len(strip_v_truth.b_only)} false neg")
    #    print(f"strip: {len(strip_v_truth.a_only)} false pos")

    result = {
            'nonstrip_v_gnd' : nonstrip_v_truth,
            'strip_v_gnd' : strip_v_truth,
            'nonstrip_v_strip' : nonstrip_v_strip,
            'nonstrip_runtime' : nonstrip_runtime,
            'strip_runtime' : strip_runtime,
            'gnd_addrs' :  gnd_addrs,
            }

    return result 
 

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
    
# TODO: rewrite this to follow the standard in cli_test 
#       and batch_test_ghidra
#@app.command()
def bench_single(
        bin_file: Annotated[str, typer.Argument()],
        no_analysis: Annotated[bool, typer.Argument()]):


    file = Path(bin_file)

    #res =  ghidra_bench_functions(file,verbose=True)
    res =  NEW_ghidra_bench_functions(file,verbose=True, 
                                      no_analysis=no_analysis)

    # False neg 
    #false_neg = res['strip_v_gnd'].b_only
    false_neg = res['strip_v_gnd'][2]

    # False Positive
    #false_pos = res['strip_v_gnd'].a_only
    false_pos = res['strip_v_gnd'][1]

    # True Positive
    true_pos = res['strip_v_gnd'][0]

    # Recall 
    # Precision 
    # F1
    recall = len(true_pos) / (len(true_pos) + len(false_neg))
    precision = len(true_pos) / (len(true_pos) + len(false_pos))
    f1 = 2 * precision * recall / (precision+recall)

    print(len(true_pos))
    print(len(false_pos))
    print(len(false_neg))
    print(f"F1 : {f1}")
    return


#@app.command()
# TODO: Rewrite to follow the standard set in cli_test
def bench(
    opt_lvl: Annotated[str, typer.Argument()],
    output_dir: Annotated[str, typer.Option()] = "ghidra_bench_results/",
    cache_analysis_info: Annotated[bool,typer.Option()] = True,
    show_summary: Annotated[bool,typer.Option()] = True,
    verbose: Annotated[bool,typer.Option()] = False,
    no_analysis: Annotated[bool,typer.Option()] = False,
    ):

    if opt_lvl.upper() not in ['O0','O1', 'O2', 'O3','OS', 'OZ']:
        print("Unknown opt lvl")
        return

    # The base output dir
    OUT_DIR = Path(output_dir)

    # Summary file
    LOG_FILE = Path(f"GHIDRA_RUN_{opt_lvl}.json")

    # If the summary file exists append a value to the new ones
    count = 0
    while LOG_FILE.exists():
        LOG_FILE = Path(f"GHIDRA_RUN_{opt_lvl}_rev{count}.json")
        count+=1

    bins = []
    for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
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

        if info['optimization'] == opt_lvl[1]:
            #npz_file = parent / "onehot_plus_func_labels.npz"
            bin = [x for x in parent.iterdir() 
                if ".npz" not in x.name and ".json" not in x.name][0]
            bins.append(bin)

    # Only run on the last 30 files
    bins = bins[31:]
    #total_results = []

    tot_true_pos = 0
    tot_true_neg = 0
    tot_false_pos = 0
    tot_false_neg = 0
    for bin_path in alive_it(bins):

        if not bin_path.exists():
            continue

        if verbose:
            print(f"Running ghidra on binary {bin_path.name}")

        # The file data
        FILE_DATA =  OUT_DIR / f"{bin_path.name}_{opt_lvl}.json"

        if FILE_DATA.exists():
            with open(FILE_DATA,'r') as inp_f:
                res = json.load(inp_f)
            res = list(res.values())[0]
            print(f"Using cache for {bin_path.name} at {FILE_DATA.parent}/{FILE_DATA.name}")
        else:
            #res =  ghidra_bench_functions(bin_path)
            res =  NEW_ghidra_bench_functions(bin_path, no_analysis=no_analysis)
        #total_results.append(res)

        if verbose:
            print(f"Results: {bin_path}")
            print("=========")
            print(f"Nonstrip | Functions: {len(res[0][0])} Unique {len(res[0][1])}")
            print(f"Strip | Functions: {len(res[1][0])} Unique {len(res[1][1])}")


        # False Negative - Functions in nonstrip that arent in strip
        false_neg = res[0][1]
        tot_false_neg += len(false_neg)

        # False Positive
        false_pos = res[1][1]
        tot_false_pos += len(false_pos)

        # True Positive
        strip_total_func = res[1][0]
        true_pos = [x for x in strip_total_func if x not in false_pos]
        tot_true_pos += len(true_pos)


        # Recall 
        recall = len(true_pos) / (len(true_pos) + len(false_neg))

        # Precision 
        precision = len(true_pos) / (len(true_pos) + len(false_pos))

        # F1
        f1 = 2 * precision * recall / (precision+recall)


        data = {
            'name': bin_path.name,
            'true_pos' : true_pos,
            'false_neg': false_neg,
            'false_pos': false_pos,
            'recall' : recall,
            'precision' : precision,
            'f1' : f1,
        }



        if not OUT_DIR.exists():
            OUT_DIR.mkdir()


        # Cache the result of the run
        if cache_analysis_info:
            with open(FILE_DATA, 'w') as f:
                json.dump({FILE_DATA.name : res},f)

        cur_data = {}
        if LOG_FILE.exists():
            with open(LOG_FILE,'r') as f:
                cur_data = json.load(f)
                cur_data[bin_path.name] = data
        with open(LOG_FILE,'w') as f:
            json.dump(cur_data,f)

    if show_summary:

        # Recall 
        recall = tot_true_pos / (tot_true_pos + tot_false_neg)

        # Precision 
        precision = tot_true_pos / (tot_true_pos + tot_false_pos)

        # F1
        f1 = 2 * precision * recall / (precision+recall)


        print(f"Results for {opt_lvl}... {len(bins)} files")
        print("------------------------------------------")
        print(f"Total functions: {tot_true_pos+tot_false_neg}")
        print(f"True Positive: {tot_true_pos}")
        print(f"False Negative: {tot_false_neg}")
        print(f"False Positive: {tot_false_pos}")
        print(f"Precision: {precision}")
        print(f"Recall: {recall}")
        print(f"f1: {f1}")
    return 

# TODO: New implementation of this that uses the standard 
#       set in cli_test and batch_test_
#@app.command()
def timed_bench_all(
    output_dir: Annotated[str, typer.Option()] = ".NEW_timed_ghidra_bench/",
    cache_analysis_info: Annotated[bool,typer.Option()] = True,
    show_summary: Annotated[bool,typer.Option()] = True,
    cache_dataset: Annotated[bool,typer.Option()] = True,
    verbose: Annotated[bool,typer.Option()] = False,
    bin_file_name: Annotated[str,typer.Option()] = "",
    ):

    using_bin_file = False 
    if bin_file_name != "":
        using_bin_file = True
        with open('XDA_DATASET_SPLITS', 'r') as f:
            list_o_bins = [x.strip() for x in f.read().split(',')]

        #print(list_o_bins)
        print(f"Using {len(list_o_bins)} bins")

    opt_lvls = ['O0','O1', 'O2', 'O3','OS', 'OZ']

    # The base output dir
    OUT_DIR = Path(output_dir)

    bins_per_opt_lvl = {}
    for opt_lvl in opt_lvls:
        bins = []
        for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
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

            if info['optimization'].upper() == opt_lvl[1]:
                #npz_file = parent / "onehot_plus_func_labels.npz"

                if using_bin_file:
                    bin_name = info['binary_name'].lower()
                    if bin_name in list_o_bins:
                        bin = parent / info['binary_name']
                        bins.append(bin)
                        print(f"Bin len {len(bins)}")
                        #print(f"skipping bin {bin_name}")
                else:
                    bin = parent / info['binary_name']
                    bins.append(bin)

        # Add this list of binary files to the bins_per_opt_lvl with the 
        # opt lvl as keey
        bins_per_opt_lvl[opt_lvl] = bins


    # Need a set of all binaries in the dictionary
    testable_binary_names = [x.name for x in set(chain.from_iterable(bins_per_opt_lvl.values()))]
    #print(testable_binary_names)

    testable_binary_dict = {k:[x for x in v if x.name in testable_binary_names] for k,v in bins_per_opt_lvl.items() }
    testable_binary_dict_stringify = {k:[x.name for x in v if x.name in testable_binary_names] for k,v in bins_per_opt_lvl.items() }


    if cache_dataset:
        cache_dir = Path(".ghidra_cached_dataset")
        if not cache_dir.exists():
            cache_dir.mkdir()

        dataset_file = cache_dir / Path("cached_dataset.json")

        with open(dataset_file, 'w') as f:
            json.dump(testable_binary_dict_stringify,f)


    for opt_lvl in opt_lvls:
        # Summary file
        LOG_FILE = Path(f"GHIDRA_RUN_{opt_lvl}.json")

        # If the summary file exists append a value to the new ones
        count = 0
        while LOG_FILE.exists():
            LOG_FILE = Path(f"GHIDRA_RUN_{opt_lvl}_rev{count}.json")
            count+=1

        bins = testable_binary_dict[opt_lvl]

        tot_true_pos = 0
        tot_false_pos = 0
        tot_false_neg = 0
        noa_tot_true_pos = 0
        noa_tot_false_pos = 0
        noa_tot_false_neg = 0
        for bin_path in alive_it(bins):

            if not bin_path.exists():
                continue

            if verbose:
                print(f"Running ghidra on binary {bin_path.name}")

            # The file data
            FILE_DATA =  OUT_DIR / f"{bin_path.name}_{opt_lvl}.json"

            # Get the results from the bench functions
            res =  NEW_ghidra_bench_functions(bin_path)

            # Run the noanalysis bench mark
            noanalysis_res = NEW_ghidra_bench_functions(bin_path,
                                                    no_analysis=True)

            # False Negative - Functions in nonstrip that arent in strip
            #false_neg = res['strip_v_gnd'].b_only
            false_neg = res['nonstrip_v_gnd'][2]
            tot_false_neg += len(false_neg)

            # False Positive
            #false_pos = res['strip_v_gnd'].a_only
            false_pos = res['nonstrip_v_gnd'][1]
            tot_false_pos += len(false_pos)

            # True Positive
            true_pos = res['nonstrip_v_gnd'][0]
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print(f"DIFFERENT TURE POS {true_pos}")
            tot_true_pos += len(true_pos)

            # Recall 
            # Precision 
            # F1
            if len(true_pos) + len(false_neg) != 0 :
                recall = len(true_pos) / (len(true_pos) + len(false_neg))
            else:
                recall = 0

            if len(true_pos) + len(false_pos) != 0 :
                precision = len(true_pos) / (len(true_pos) + len(false_pos))
            else: 
                precision = 0

            if precision+recall != 0 :
                f1 = 2 * precision * recall / (precision+recall)
            else:
                f1 = 0

            # FAlse neg - only in ghida
            #noa_false_neg = noanalysis_res['strip_v_gnd'].b_only
            noa_false_neg = noanalysis_res['strip_v_gnd'][2]
            noa_tot_false_neg += len(noa_false_neg)

            # False Positive
            #noa_false_pos = noanalysis_res['strip_v_gnd'].a_only
            noa_false_pos = noanalysis_res['strip_v_gnd'][1]
            noa_tot_false_pos += len(noa_false_pos)

            # True Positive
            noa_true_pos = noanalysis_res['strip_v_gnd'][0]
            noa_tot_true_pos += len(noa_true_pos)

            # Recall 
            # Precision 
            # F1
            noa_recall = len(noa_true_pos) / (len(noa_true_pos) + len(noa_false_neg))
            noa_precision = len(noa_true_pos) / (len(noa_true_pos) + len(noa_false_pos))
            noa_f1 = 2 * noa_precision * noa_recall / (noa_precision+noa_recall)
            if verbose:
                print(f"Bin {bin_path.name}")
                print(f"|Analysis.......")
                print(f"|F1: {f1}")
                print(f"|Prec: {precision}")
                print(f"|recall: {recall}")
                print(f">|No Analysis.......")
                print(f">|F1: {noa_f1}")
                print(f">|Prec: {noa_precision}")
                print(f">|recall: {noa_recall}")



            data = {
                'name': bin_path.name,
                'true_pos' : len(true_pos),
                'false_neg': len(false_neg),
                'false_pos': len(false_pos),
                #'nonstripped_wall_time': res[2][0],
                'nonstripped_wall_time': int(res['nonstrip_runtime']),
                #'stripped_wall_time': res[2][1],
                'stripped_wall_time': int(res['strip_runtime']),
                #------------------
                'noanalysis_true_pos' :  len(noa_true_pos),
                'noanalysis_false_neg':  len(noa_false_neg),
                'noanalysis_false_pos':  len(noa_false_pos),
                'noanalysis_nonstripped_wall_time': float(noanalysis_res['nonstrip_runtime']),
                'noanalysis_stripped_wall_time': float(noanalysis_res['strip_runtime']),
            }


            if not OUT_DIR.exists():
                OUT_DIR.mkdir()



            # Cache the result of the run
            if cache_analysis_info:
                with open(FILE_DATA, 'w') as f:
                    json.dump({FILE_DATA.name : data},f)

            cur_data = {}
            if LOG_FILE.exists():
                with open(LOG_FILE,'r') as f:
                    cur_data = json.load(f)
                    cur_data[bin_path.name] = data
            with open(LOG_FILE,'w') as f:
                json.dump(cur_data,f)

        if show_summary:

            # Recall 
            recall = tot_true_pos / (tot_true_pos + tot_false_neg)

            # Precision 
            precision = tot_true_pos / (tot_true_pos + tot_false_pos)

            # F1
            f1 = 2 * precision * recall / (precision+recall)


            print(f"Results for {opt_lvl}... {len(bins)} files")
            print("------------------------------------------")
            print(f"Total functions: {tot_true_pos+tot_false_neg}")
            print(f"True Positive: {tot_true_pos}")
            print(f"False Negative: {tot_false_neg}")
            print(f"False Positive: {tot_false_pos}")
            print(f"Precision: {precision}")
            print(f"Recall: {recall}")
            print(f"f1: {f1}")
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

    return


if __name__ == "__main__":
    app()
