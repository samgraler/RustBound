from dataclasses import dataclass
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

from ripkit.cargo_picky import (
  is_executable,
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
    exact_ghid_command : str

@dataclass
class ListCompare():
    intersection: List[str]
    a_only: List[str]
    b_only: List[str]


def NEW_run_ghidra(
               bin_path: Path, 
               post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
               script_path: Path = Path("~/ghidra_scripts/").expanduser(),
               analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
                no_analysis: bool = False, 
               hide_output=True):
 
    if no_analysis:
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
    return



    return 

#def run_ghidra_noanalysis(
#               bin_path: Path, 
#               post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
#               script_path: Path = Path("~/ghidra_scripts/").expanduser(),
#               analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
#               print_cmd = False,
#               hide_output=True):
#    '''
#    Run the analyze headless mode with ghidra
#    '''
#    
#    cmd_str = [f"{analyzer.parent}/./{analyzer.name}", "/tmp", "tmp_proj",
#               "-import", f"{bin_path}", "-scriptPath", f"{script_path}",
#               "-postScript", f"{post_script.name}", "-noanalysis"
#               ]
#    if print_cmd:
#        print(" ".join(x for x in cmd_str))
#
#    try:
#        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
#        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
#        for path in paths_to_remove:
#            if path.exists():
#                if path.is_dir():
#                    shutil.rmtree(path)
#                else:
#                    path.unlink()
#
#
#        output = subprocess.run(cmd_str, text=True,
#                                capture_output=True,
#                                universal_newlines=True)
#        return output
#    except subprocess.CalledProcessError as e:
#        print(f"COMMAND IS : {cmd_str}")
#        print("Error running command:", e)
#        return []
#    finally:
#        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
#        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
#        for path in paths_to_remove:
#            if path.exists():
#                if path.is_dir():
#                    shutil.rmtree(path)
#                else:
#                    path.unlink()
#    return
#
#
#def run_ghidra(bin_path: Path, 
#               post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
#               script_path: Path = Path("~/ghidra_scripts/").expanduser(),
#               analyzer: Path = Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
#               print_cmd = False,
#               hide_output=True):
#    '''
#    Run the analyze headless mode with ghidra
#    '''
#    
#    cmd_str = [f"{analyzer.parent}/./{analyzer.name}", "/tmp", "tmp_proj",
#               "-import", f"{bin_path}", "-scriptPath", f"{script_path}",
#               "-postScript", f"{post_script.name}",
#               ]
#    if print_cmd:
#        print(" ".join(x for x in cmd_str))
#
#    try:
#        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
#        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
#        for path in paths_to_remove:
#            if path.exists():
#                if path.is_dir():
#                    shutil.rmtree(path)
#                else:
#                    path.unlink()
#
#
#        output = subprocess.run(cmd_str, text=True,
#                                capture_output=True,
#                                universal_newlines=True)
#        return output
#    except subprocess.CalledProcessError as e:
#        print(f"COMMAND IS : {cmd_str}")
#        print("Error running command:", e)
#        return []
#    finally:
#        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
#        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
#        for path in paths_to_remove:
#            if path.exists():
#                if path.is_dir():
#                    shutil.rmtree(path)
#                else:
#                    path.unlink()


def parse_for_functions(inp):
    '''
    Parse the output from the ghidra headless analyzer to get the found 
    function names and addresses
    '''


    #res = []

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


def function_list_comp(func_list1, func_list2,):
    '''
    Helper function to get the unique functions 
    to each list, common functions
    '''


    unique_list1 = [x for x in func_list1 if x[1] not in [y[1] for y in func_list2]]

    unique_list2 = [x for x in func_list2 if x[1] not in [y[1] for y in func_list1]]

    return unique_list1, unique_list2
 
#def ghidra_noanalysis_bench_functions(bin_path: Path, 
#    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
#    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
#    analyzer: Path = 
#    Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve()
#                           ):
#
#    # Run ghidra on unstripped binary and get function list
#    print(f"Running on binary {bin_path}")
#    start_time = time.time()
#    #nonstrip_res = run_ghidra_noanalysis(bin_path, post_script, script_path, analyzer,no_analysis=True)
#    nonstrip_res = NEW_run_ghidra(bin_path, post_script, script_path, analyzer,no_analysis=True)
#    nonstrip_runtime = time.time() - start_time
#    nonstrip_funcs = parse_for_functions(nonstrip_res.stdout)
#
#
#    # Copy the bin and strip it 
#    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
#    shutil.copy(bin_path, Path(strip_bin))
#
#    try:
#        output = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
#    except subprocess.CalledProcessError as e:
#        print("Error running command:", e)
#        return []
#
#    print(f"Running on {bin_path.name} stripped")
#
#    # Run ghidra on stripped bin and get function list - and time it 
#    start_time = time.time()
#    #strip_res = run_ghidra_noanalysis(strip_bin , post_script, script_path, analyzer)
#    strip_res = NEW_run_ghidra(strip_bin , post_script, script_path, analyzer, no_analysis=True)
#    strip_runtime = time.time() - start_time
#
#    strip_funcs = parse_for_functions(strip_res.stdout)
#
#    # Delete the stripped binary
#    strip_bin.unlink()
#
#    # Get the number of unique functions to each
#    unique_nonstrip, unique_strip = function_list_comp(nonstrip_funcs, 
#                                                       strip_funcs)
#
#    # Return a list of functions for each, and unqiue functions for each
#    return [(nonstrip_funcs, unique_nonstrip), (strip_funcs, unique_strip), (nonstrip_runtime, strip_runtime)]


def parse_ground_truth(bin_path: Path):
    '''
    '''

    bin = lief.parse(str(bin_path.resolve()))

    text_section = bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = bin.imagebase

    functions = get_functions(bin_path)


    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}
    ret_list = []

    sorted_dict_keys = {k: func_start_addrs[k] for k in sorted(func_start_addrs.keys())}

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

def list_operations(list_a, list_b):

    # Calculate the intersection of the two lists
    intersection = list(set(list_a) & set(list_b))

    # Calculate elements in list A that are not in list B
    a_not_in_b = list(set(list_a) - set(list_b))

    # Calculate elements in list B that are not in list A
    b_not_in_a = list(set(list_b) - set(list_a))

    res = ListCompare
    res.intersection = intersection
    res.a_only = a_not_in_b
    res.b_only = b_not_in_a

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
    #addrs = [x[1] for x in funcs]

    return list(funcs.addresses), runtime


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

def smol_ghid_bench(
     bin_path: Path, 
    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
    analyzer: Path = 
    Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
    no_analysis=False,
    strip_file=False):

    # Generate ground turth
    ground_truth = parse_ground_truth(bin_path)
    gnd_addrs = [x[0] for x in ground_truth]

    #TODO: Every test should be on stripped file
    if strip_file:
        strip_bin_path = gen_strip_file(bin_path)

        # Run the timed bench mark
        funcs, runtime = func_addrs_timed_bench(strip_bin_path, 
                                    post_script, script_path, 
                                    analyzer,
                                    no_analysis=no_analysis)

        strip_bin_path.unlink()
    else: 
        # Run the timed bench mark
        funcs, runtime = func_addrs_timed_bench(bin_path, post_script,
                                    script_path, analyzer,
                                    no_analysis=no_analysis)

        # Find the offset for the ghidra addrs and apply it
        offset =  find_ghidra_offset(ground_truth, funcs)

        funcs = [x-offset for x in funcs
                if x-offset > min(gnd_addrs) and 
                    x-offset < max(gnd_addrs)]

    # Consturct the ghidra result object
    res = GhidraBenchResult(strip_file, no_analysis, 
                bin_path.name, gnd_addrs, funcs,
                            runtime)


    return  res

   

def NEW_ghidra_bench_functions(
    bin_path: Path, 
    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
    analyzer: Path = 
    Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
    verbose=False,
    no_analysis=False):


    #TODO: : Use smol_ghid_bech 
    # save every result of smol ghid bench
    # smol_ghid_bench(bin_path, strip=True, no_analyiss=False
    # smol_ghid_bench(bin_path, strip=True, no_analyiss=True

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

    nonstrip_func_addrs = [x-offset for x in nonstrip_funcs
            if x-offset > min(gnd_addrs) and 
                x-offset < max(gnd_addrs)]


    # Copy the bin and strip it 
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return []

    # Run ghidra on stripped bin and get function list - and time it 
    strip_res, strip_runtime = timed_ghidra_run(strip_bin , post_script, script_path, analyzer)

    #TODO: Why doesn't ghidra apply the offset for the 
    #   stripped version of files
    strip_funcs = parse_for_functions(strip_res.stdout)


    # Delete the stripped binary
    strip_bin.unlink()

    # Only include the addrs that are in the .text section
    strip_func_addrs = [x for x in list(strip_funcs.addresses) if 
        x > min(gnd_addrs) and x < max(gnd_addrs) 
    ]

    # Get the overlaps and unique values in the lists
    nonstrip_v_truth = list_operations(nonstrip_func_addrs, gnd_addrs)
    strip_v_truth = list_operations(strip_func_addrs, gnd_addrs)
    nonstrip_v_strip = list_operations(nonstrip_func_addrs, gnd_addrs)

    if verbose:
        print(f"Lief first func : {min(ground_truth)}")
        print(f"Ghid first func : {min(nonstrip_func_addrs)}")
              
        print(f"Total lief functions {len(ground_truth)}")
        print(f"Total ghidra in .text {len(nonstrip_func_addrs)}")

        print(f"Nonstrip: {len(nonstrip_v_truth.intersection)} true pos")
        print(f"Nonstrip: {len(nonstrip_v_truth.b_only)} false neg")
        print(f"Nonstrip: {len(nonstrip_v_truth.a_only)} false pos")

        print(f"strip: {len(strip_v_truth.intersection)} tru pos")
        print(f"strip: {len(strip_v_truth.b_only)} false neg")
        print(f"strip: {len(strip_v_truth.a_only)} false pos")

    result = {
            'nonstrip_v_gnd' : nonstrip_v_truth,
            'strip_v_gnd' : strip_v_truth,
            'nonstrip_v_strip' : nonstrip_v_strip,
            'nonstrip_runtime' : nonstrip_runtime,
            'strip_runtime' : strip_runtime,
            'gnd_addrs' :  gnd_addrs,
            }
    #res = GhidraBenchResult(
    #    bin_name = bin_path.name

    #)
    return result 
 


    
#def ghidra_bench_functions(
#    bin_path: Path, 
#    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
#    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
#    analyzer: Path = 
#    Path("~/ghidra_10.3.3_PUBLIC/support/analyzeHeadless").expanduser().resolve(),
#    verbose=False):
#
#    # Load ground truth 
#    ground_truth = parse_ground_truth(bin_path)
#    gnd_addrs = [x[0] for x in ground_truth]
#
#    # Run ghidra and get the address of the function and the runtime 
#    # for ghidra's analysis
#    nonstrip_funcs, nonstrip_runtime = func_addrs_timed_bench(bin_path,
#                                post_script, script_path, analyzer)
#
#    # Find the offset for the ghidra addrs and apply it
#    offset =  find_ghidra_offset(ground_truth, nonstrip_funcs)
#
#    nonstrip_func_addrs = [x-offset for x in nonstrip_funcs
#            if x-offset > min(gnd_addrs) and 
#                x-offset < max(gnd_addrs)]
#
#
#    # Copy the bin and strip it 
#    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
#    shutil.copy(bin_path, Path(strip_bin))
#
#    try:
#        _ = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
#    except subprocess.CalledProcessError as e:
#        print("Error running command:", e)
#        return []
#
#    # Run ghidra on stripped bin and get function list - and time it 
#    strip_res, strip_runtime = timed_ghidra_run(strip_bin , post_script, script_path, analyzer)
#
#    #TODO: Why doesn't ghidra apply the offset for the 
#    #   stripped version of files
#    strip_funcs = parse_for_functions(strip_res.stdout)
#
#    # Delete the stripped binary
#    strip_bin.unlink()
#
#    # Only include the addrs that are in the .text section
#    strip_func_addrs = [x[1] for x in strip_funcs if 
#        x[1] > min(gnd_addrs) and x[1] < max(gnd_addrs) 
#    ]
#
#    # Get the overlaps and unique values in the lists
#    nonstrip_v_truth = list_operations(nonstrip_func_addrs, gnd_addrs)
#    strip_v_truth = list_operations(strip_func_addrs, gnd_addrs)
#    nonstrip_v_strip = list_operations(nonstrip_func_addrs, gnd_addrs)
#
#    if verbose:
#        print(f"Lief first func : {min(ground_truth)}")
#        print(f"Ghid first func : {min(nonstrip_func_addrs)}")
#              
#        print(f"Total lief functions {len(ground_truth)}")
#        print(f"Total ghidra in .text {len(nonstrip_func_addrs)}")
#
#        print(f"Nonstrip: {len(nonstrip_v_truth.intersection)} true pos")
#        print(f"Nonstrip: {len(nonstrip_v_truth.b_only)} false neg")
#        print(f"Nonstrip: {len(nonstrip_v_truth.a_only)} false pos")
#
#        print(f"strip: {len(strip_v_truth.intersection)} tru pos")
#        print(f"strip: {len(strip_v_truth.b_only)} false neg")
#        print(f"strip: {len(strip_v_truth.a_only)} false pos")
#
#    result = {
#            'nonstrip_v_gnd' : nonstrip_v_truth,
#            'strip_v_gnd' : strip_v_truth,
#            'nonstrip_v_strip' : nonstrip_v_strip,
#            'nonstrip_runtime' : nonstrip_runtime,
#            'strip_runtime' : strip_runtime,
#            }
#
#    # Return a list of functions for each, and unqiue functions for each
#    #TODO: Change every func that depends on this
#    return result 
    #return [(nonstrip_funcs, unique_nonstrip), (strip_funcs, unique_strip), (nonstrip_runtime, strip_runtime)]



#def open_and_read_log(log_path: Path = Path("GHIDRA_BENCH_RESULTS.json")):
#
#    # Read json data 
#    with open(log_path,'r') as f:
#        data = json.load(f)
#
#    # Totals 
#    total_strip_unique = 0
#    total_non_strip_unique = 0
#    total_funcs = 0
#    total_strip_non_unique  = 0
#    for _, bin_data in data.items():
#        # Unqiue functions in non-strip: Missed funcs 
#        #                           -or- False Negative
#        # Unqiue funciotns in strip: False Positive
#
#        # Non-unique functions in strip: True Positive
#
#        total_strip_unique += bin_data['strip_unique_funcs']
#        total_non_strip_unique += bin_data['nonstrip_unique_funcs']
#        total_strip_non_unique += bin_data['strip_funcs']
#        total_funcs += bin_data['nonstrip_funcs']
#
#    false_negative = total_non_strip_unique
#    false_positive = total_strip_unique
#
#    # Every thing that correctly labeled
#    true_positive = total_strip_non_unique
#
#
#    # Recall 
#    recall = true_positive / (true_positive + false_negative)
#
#    # Precision 
#    precision = true_positive / (true_positive + false_positive)
#
#    # F1
#    f1 = 2 * precision * recall / (precision+recall)
#
#
#    print("Stats:")
#    print("==================")
#    print(f"Number of functions: {total_funcs}")
#    print(f"Funcs correctly identified: {true_positive}")
#    print(f"False neg: {false_negative}")
#    print(f"False pos: {false_positive}")
#    print(f"strip unique: {total_strip_unique}")
#    print(f"nonstrip unique: {total_non_strip_unique}")
#    print(f"Number of files: {len(data.keys())}")
#    print(f"Precision {precision}")
#    print(f"Recall: {recall}")
#    print(f"F1: {f1}")


#    plt = create_dual_plots(1, recall, f1, true_positive, total_funcs,
#                            ['Precision', 'Recall', 'F1'],
#                            ['Found','Not Found'])
#
#    plt.savefig("dual_plot")
#    return 

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
def read_summary(
    opt_lvl: Annotated[str, typer.Argument()],
    show_diff: Annotated[bool, typer.Option()]=False,
    ):

    log_path = Path(f"GHIDRA_RUN_{opt_lvl}.json")
    if not log_path.exists():
        print(f"No file {log_path}")
        return


    # Read json data 
    with open(log_path,'r') as f:
        data = json.load(f)

    # Totals 
    false_positive = 0
    false_negative= 0
    true_positive = 0
    concat_false_pos = []
    concat_false_neg = []

    for _, bin_data in data.items():
        # Unqiue functions in non-strip: Missed funcs 
        #                           -or- False Negative
        # Unqiue funciotns in strip: False Positive

        # Non-unique functions in strip: True Positive

        false_positive += len(bin_data['false_pos'])
        false_negative += len(bin_data['false_neg'])
        true_positive += len(bin_data['true_pos'])

        if show_diff:
            concat_false_neg.extend(bin_data['false_neg'])
            concat_false_pos.extend(bin_data['false_pos'])

    total_funcs = true_positive + false_negative

    # Recall 
    recall = true_positive / (true_positive + false_negative)

    # Precision 
    precision = true_positive / (true_positive + false_positive)

    # F1
    f1 = 2 * precision * recall / (precision+recall)

    if show_diff:
        for name_addr in concat_false_pos:
            print(f"{name_addr[0]:>4} | {name_addr[1]}: False pos")
        for name_addr in concat_false_neg:
            print(f"{name_addr[0]:>4} | {name_addr[1]}: False neg")

    print("Stats:")
    print("==================")
    print(f"Number of functions: {total_funcs}")
    print(f"Funcs correctly identified: {true_positive}")
    print(f"False neg: {false_negative}")
    print(f"False pos: {false_positive}")
    print(f"Number of files: {len(data.keys())}")
    print(f"Precision {precision}")
    print(f"Recall: {recall}")
    print(f"F1: {f1}")



    return


@app.command()
def read_log(
    binary: Annotated[str, typer.Argument()],
    show_unique: Annotated[bool, typer.Option()] = False,
    show_tru_pos: Annotated[bool, typer.Option()] = False,
    ):

    f_path =  Path(f".ghidra_bench/{binary}.json")
    if not f_path.exists():
        print(f"No log for {binary}")
        return

    with open(f_path, 'r') as f:
        res = json.load(f)
    res = list(res.values())[0]

    # False Negative - Functions in nonstrip that arent in strip
    false_neg = res[0][1]

    # False Positive
    false_pos = res[1][1]

    # True Positive
    strip_total_func = res[1][0]
    true_pos = [x for x in strip_total_func if x not in false_pos]


    # Recall 
    recall = len(true_pos) / (len(true_pos) + len(false_neg))

    # Precision 
    precision = len(true_pos) / (len(true_pos) + len(false_pos))

    # F1
    f1 = 2 * precision * recall / (precision+recall)

    print(f"Total functions: {len(true_pos)+len(false_neg)}")
    print(f"True Positive: {len(true_pos)}")
    print(f"False Negative: {len(false_neg)}")
    print(f"False Positive: {len(false_pos)}")
    print(f"Precision: {precision}")
    print(f"Recall: {recall}")
    print(f"F1: {f1}")

    if show_tru_pos:
        print(f"Displaying the True Positive addrs")
        for name_addr in true_pos:
            print(f"{name_addr}")

    if show_unique:
        print(f"FALSE NEGATIVE ==================================")
        for name_addr in false_neg:
            name = name_addr[0]
            addr = name_addr[1]
            print(f"{addr:<4} | {name}")
        print(f"FALSE POSITIVE ==================================")
        for name_addr in false_pos:
            name = name_addr[0]
            addr = name_addr[1]
            print(f"{addr:<4} | {name}")
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
def bench_single(
        bin_file: Annotated[str, typer.Argument()]):


    file = Path(bin_file)

    #res =  ghidra_bench_functions(file,verbose=True)
    res =  NEW_ghidra_bench_functions(file,verbose=True)

    return


@app.command()
def bench(
    opt_lvl: Annotated[str, typer.Argument()],
    output_dir: Annotated[str, typer.Option()] = ".ghidra_bench/",
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

@app.command()
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

        print(list_o_bins)
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
        #total_results = []

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

            #if FILE_DATA.exists():
            #    with open(FILE_DATA,'r') as inp_f:
            #        res = json.load(inp_f)
            #    res = list(res.values())[0]
            #    print(f"Using cache for {bin_path.name} at {FILE_DATA.parent}/{FILE_DATA.name}")
            #else:
                # Returns a dict of results
                #res =  ghidra_bench_functions(bin_path)
            res =  NEW_ghidra_bench_functions(bin_path)


            #total_results.append(res)

            # Run the noanalysis bench mark
            #noanalysis_res = ghidra_noanalysis_bench_functions(bin_path)
            noanalysis_res = NEW_ghidra_bench_functions(bin_path,no_analysis=True)


            # False Negative - Functions in nonstrip that arent in strip
            #false_neg = res[0][1]
            false_neg = res['strip_v_gnd'].b_only
            tot_false_neg += len(false_neg)

            # False Positive
            #false_pos = res[1][1]
            false_pos = res['strip_v_gnd'].a_only
            tot_false_pos += len(false_pos)

            # True Positive
            #strip_total_func = res[1][0]
            true_pos = res['gnd_addrs']
            #true_pos = [x for x in strip_total_func if x not in false_pos]
            tot_true_pos += len(true_pos)

            # Recall 
            # Precision 
            # F1
            recall = len(true_pos) / (len(true_pos) + len(false_neg))
            precision = len(true_pos) / (len(true_pos) + len(false_pos))
            f1 = 2 * precision * recall / (precision+recall)

            # FAlse neg - only in ghida
            #noa_false_neg = noanalysis_res[0][1]
            noa_false_neg = noanalysis_res['strip_v_gnd'].b_only
            noa_tot_false_neg += len(noa_false_neg)

            # False Positive
            #noa_false_pos = noanalysis_res[1][1]
            noa_false_pos = noanalysis_res['strip_v_gnd'].a_only
            noa_tot_false_pos += len(noa_false_pos)

            # True Positive
            #noa_strip_total_func = noanalysis_res[1][0]
            noa_true_pos = noanalysis_res['gnd_addrs']

            #noa_true_pos = [x for x in noa_strip_total_func if x not in noa_false_pos]
            noa_tot_true_pos += len(noa_true_pos)

            # Recall 
            # Precision 
            # F1
            noa_recall = len(noa_true_pos) / (len(noa_true_pos) + len(noa_false_neg))
            noa_precision = len(noa_true_pos) / (len(noa_true_pos) + len(noa_false_pos))
            noa_f1 = 2 * noa_precision * noa_recall / (noa_precision+noa_recall)



            data = {
                'name': bin_path.name,
                'true_pos' : list(true_pos),
                'false_neg': list(false_neg),
                'false_pos': list(false_pos),
                'recall' : recall,
                'precision' : precision,
                'f1' : f1,
                #'nonstripped_wall_time': res[2][0],
                'nonstripped_wall_time': int(res['nonstrip_runtime']),
                #'stripped_wall_time': res[2][1],
                'stripped_wall_time': int(res['strip_runtime']),
                #------------------
                'noanalysis_true_pos' :  list(noa_true_pos),
                'noanalysis_false_neg':  list(noa_false_neg),
                'noanalysis_false_pos':  list(noa_false_pos),
                'noanalysis_recall' :    noa_recall,
                'noanalysis_precision' : noa_precision,
                'noanalysis_f1' : noa_f1,
                'noanalysis_nonstripped_wall_time': noanalysis_res['nonstrip_runtime'],
                'noanalysis_stripped_wall_time': noanalysis_res['strip_runtime'],
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
def read_timed_summary(
    file: Annotated[str, typer.Argument()],
    #opt_lvl: Annotated[str, typer.Argument()],
    show_diff: Annotated[bool, typer.Option()]=False,
    # TODO: Ability to provide a list of binary names 
    #       that I want the summary of 
    #       so that I can provide the exact lis tthat the 
    #       rnn was tested on 
    binary_name_file: Annotated[str, 
                typer.Option(help='json file with bin names to include')] = '',
    ):


    binary_names = []
    if binary_name_file != '':
        bin_name_file = Path(binary_name_file)
        if not bin_name_file.exists():
            print(f"Binary name file {binary_name_file} does not exist")
            return
        with open(bin_name_file, 'r') as f:
            binary_names = f.readlines()
            #binary_names = json.load(f)['names']

    log_path = Path(file)
    if not log_path.exists():
        print(f"No file {log_path}")
        return


    # Read json data 
    with open(log_path,'r') as f:
        data = json.load(f)

    # Totals 
    stripped_time = 0
    nonstripped_time = 0
    false_positive = 0
    false_negative= 0
    true_positive = 0
    concat_false_pos = []
    concat_false_neg = []
    noa_stripped_time = 0
    noa_nonstripped_time = 0
    noa_false_positive = 0
    noa_false_negative= 0
    noa_true_positive = 0
    total_files = 0



    for _, bin_data in data.items():
        if binary_names != []:
            if bin_data['name'] not in binary_names:
                continue

        total_files += 1
        # Unqiue functions in non-strip: Missed funcs 
        #                           -or- False Negative
        # Unqiue funciotns in strip: False Positive

        # Non-unique functions in strip: True Positive
        stripped_time += bin_data['stripped_wall_time']
        nonstripped_time += bin_data['nonstripped_wall_time']

        false_positive += len(bin_data['false_pos'])
        false_negative += len(bin_data['false_neg'])
        true_positive += len(bin_data['true_pos'])

        noa_stripped_time += bin_data['noanalysis_stripped_wall_time']
        noa_nonstripped_time += bin_data['noanalysis_nonstripped_wall_time']

        noa_false_positive += len(bin_data['noanalysis_false_pos'])
        noa_false_negative += len(bin_data['noanalysis_false_neg'])
        noa_true_positive +=  len(bin_data['noanalysis_true_pos'])
        if show_diff:
            concat_false_neg.extend(bin_data['false_neg'])
            concat_false_pos.extend(bin_data['false_pos'])

    total_funcs = true_positive + false_negative

    # metrics
    recall = true_positive / (true_positive + false_negative)
    precision = true_positive / (true_positive + false_positive)
    f1 = 2 * precision * recall / (precision+recall)

    noa_total_funcs = noa_true_positive + noa_false_negative

    # metrics
    noa_recall = noa_true_positive / (noa_true_positive + noa_false_negative)
    noa_precision = noa_true_positive / (noa_true_positive + noa_false_positive)
    noa_f1 = 2 * noa_precision * noa_recall / (noa_precision+noa_recall)



    if show_diff:
        for name_addr in concat_false_pos:
            print(f"{name_addr[0]:>4} | {name_addr[1]}: False pos")
        for name_addr in concat_false_neg:
            print(f"{name_addr[0]:>4} | {name_addr[1]}: False neg")

    print("Stats:")
    print("==================")
    print("With analysis:")
    print(f"Number of functions: {total_funcs}")
    print(f"Funcs correctly identified: {true_positive}")
    print(f"False neg: {false_negative}")
    print(f"False pos: {false_positive}")
    print(f"Number of files: {total_files}")
    print(f"Precision {precision}")
    print(f"Recall: {recall}")
    print(f"F1: {f1}")
    print(f"Time, nonstripped: {nonstripped_time}")
    print(f"Time, stripped: {stripped_time}")
    print("Without analysis:")
    print(f"Number of functions: {noa_total_funcs}")
    print(f"Funcs correctly identified: {noa_true_positive}")
    print(f"False neg: {noa_false_negative}")
    print(f"False pos: {noa_false_positive}")
    print(f"Number of files: {total_files}")
    print(f"Precision {noa_precision}")
    print(f"Recall: {noa_recall}")
    print(f"F1: {noa_f1}")
    print(f"Time, nonstripped: {noa_nonstripped_time}")
    print(f"Time, stripped: {noa_stripped_time}")
    return



if __name__ == "__main__":
    app()
