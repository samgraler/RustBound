import typer 
import shutil
import os
import subprocess
from typing_extensions import Annotated
import rich 
from rich.console import Console
from pathlib import Path
from alive_progress import alive_it

#from ripkit.cargo_picky import (
#  is_executable,
#)

ripkit_dir = Path("../ripkit").resolve()
import sys
sys.path.append (
    str(ripkit_dir)
)
from ripkit.ripbin import (
    save_raw_experiment,
    get_functions,
)

from dataclasses import dataclass

from typing import List 
import numpy as np
import lief
import time


console = Console()
app = typer.Typer()

@dataclass
class FoundFunctions():
    addresses: np.ndarray
    names: List[str]
    lengths: np.ndarray



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

    # Return the addrs and names 
    func_addrs = np.array(func_addrs)
    return FoundFunctions(func_addrs, func_names)

def generate_ida_cmd(
        binary: Path,
        logfile: Path,
        ida_script: Path):
    '''
    Geneate a command to run IDA with the selected script

    binary: Path
        Binary to analyze with IDA Pro
    logfile: Path
        The output file for the analysis, typically is parsed for results
    ida_script: Path
        Script using IDA Pro's API to run for analysis
    '''

    ida = Path("~/idapro-8.3/idat64").expanduser()
    return f'{ida.resolve()} -c -A -S"{ida_script.resolve()}" -L{logfile.resolve()} {binary.resolve()}'

#TODO: Bad implementation... hard coded, but fast 
def generate_ida_cmd_bounds(binary: Path, logfile: Path):
    '''
    Generate command to run IDA with the selected script 

    binary: Path 
        The binary to run IDA on 

    logile: Path
        The output file for the analysis, typically is parsed for results
    '''

    bound_list = Path(os.path.abspath(__file__)).parent / "function_bounds_list.py"
    bound_list = bound_list.resolve()

    clear_cmd = f"rm {binary.resolve()}.i64"

    return generate_ida_cmd(binary, logfile, bound_list), clear_cmd




def make_ida_cmd(binary: Path, logfile: Path):

    #func_list = Path("function_list.py").resolve()

    func_list = Path(os.path.abspath(__file__)).parent / "function_list.py"
    func_list = func_list.resolve()
    ida = Path("~/idapro-8.3/idat64").expanduser()

    cmd = f'{ida.resolve()} -c -A -S"{func_list.resolve()}" -L{logfile.resolve()} {binary.resolve()}'

    #TODO: This only works for i64 
    clear_cmd = f"rm {binary.resolve()}.i64"

    return cmd, clear_cmd


@dataclass
class FoundFunction:
    start_addr: str
    end_addr: str
    name: str


def read_bounds_log(rawlog: Path)->List[FoundFunction]:
    '''
    Parse raw log generated from ida on command
    '''

    # Function tuples 
    func_tuples = []

    # Read the log 
    with open(rawlog, 'r') as f:

        # The lines in the output will have 
        # FUNCTION, addr, function_name
        for line in f.readlines():
            if "FUNCTION," in line:
                _, start_addr, length, name = line.split(',')
                start_addr = start_addr.strip()
                length = length.strip()
                end_addr = start_addr + length
                name = name.strip()
                #func_tuples.append((start_addr, end_addr, name))
                func_tuples.append(FoundFunction(start_addr, end_addr, name))

    return func_tuples


def read_raw_log(rawlog: Path):
    '''
    Parse raw log generated from ida on command
    '''

    # Function tuples 
    func_tuples = []

    # Read the log 
    with open(rawlog, 'r') as f:

        # The lines in the output will have 
        # FUNCTION, addr, function_name
        for line in f.readlines():
            if "FUNCTION," in line:
                _, addr, name = line.split(',')
                addr = addr.strip()
                name = name.strip()
                func_tuples.append((addr, name))

    return func_tuples


@app.command()
def ida_bounds(
           binary: Annotated[str, typer.Argument(help="bin to run on")], 
           resfile: Annotated[str, typer.Argument(help="name of result file")],
    ):

    bin = Path(binary)
    if not bin.exists():
        print(f"Bin {bin} does not exist")
        return
    
    funcs, runtime = get_ida_bounds(bin)

    with open(Path(resfile), 'w') as f:
        for func in funcs:
            f.write(f"{func.start_addr}, {func.end_addr}\n")

    print(f"Runtime: {runtime}")
    return


@app.command()
def ida_on(
           binary: Annotated[str, typer.Argument(help="bin to run on")], 
           logfile: Annotated[str, typer.Argument(help="bin to run on")],
           resfile: Annotated[str, typer.Argument(help="name of result file")]):
    '''
    Report the IDA detected funtions to the resfile
    '''

    # Generate the ida command 
    cmd, clear_cmd = make_ida_cmd(Path(binary), Path(logfile))
    print(cmd)

    # Run the command to run ida 
    res = subprocess.check_output(cmd,shell=True)
    #res = subprocess.run(cmd,text=True,capture_output=True,
    #                     universal_newlines=True)
    print(res)

    funcs = read_raw_log(Path(logfile))
    print(f"Num funcs {len(funcs)}")

    with open(Path(resfile), 'w') as f:
        for func in funcs:
            f.write(f"{func[0].strip()}, {func[1].strip()}\n")

    # Remove the database file 
    res = subprocess.check_output(clear_cmd, shell=True)
    return




def get_ida_bounds(file: Path):
    '''
    Run the IDA analysis for function boundaries 
    '''

    # To get the functions, ida logs all the std to a log file 
    #ida_log_file = file.resolve().parent / f"{file.name}_IDA_LOG.log"
    ida_log_file = Path(".") / f"{file.name}_IDA_LOG.log"

    # Get the commands to run ida and clear the extra files 
    cmd, clear_cmd = generate_ida_cmd_bounds(file, ida_log_file)
    start = time.time()

    # Run the command to run ida 
    res = subprocess.check_output(cmd,shell=True)

    #res = subprocess.run(cmd,text=True,capture_output=True,
    #                     universal_newlines=True)

    runtime = time.time() - start

    # Fet the functions from the log file 
    funcs = read_bounds_log(ida_log_file)

    # Delete the log file 
    ida_log_file.unlink()

    # Remove the database file 
    res = subprocess.check_output(clear_cmd, shell=True)

    return funcs, runtime



def get_ida_funcs(file: Path):

    # To get the functions, ida logs all the std to a log file 
    #ida_log_file = file.resolve().parent / f"{file.name}_IDA_LOG.log"
    ida_log_file = Path(".") / f"{file.name}_IDA_LOG.log"

    # Get the commands to run ida and clear the extra files 
    cmd, clear_cmd = make_ida_cmd(file, ida_log_file)

    start = time.time()

    # Run the command to run ida 
    res = subprocess.check_output(cmd,shell=True)
    print(res)

    #res = subprocess.run(cmd,text=True,capture_output=True,
    #                     universal_newlines=True)

    runtime = time.time() - start

    # Fet the functions from the log file 
    funcs = read_raw_log(ida_log_file)

    # Delete the log file 
    ida_log_file.unlink()

    # Remove the database file 
    res = subprocess.check_output(clear_cmd, shell=True)

    return funcs, runtime

@app.command()
def count_funcs(
    inp_file: Annotated[str, typer.Argument(help="Input file")], 
    ):


    funcs, runtime = get_ida_funcs(Path(inp_file))

    print(f"{len(funcs)} functions")

    return

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


@app.command()
def batch_get_bounds(
               inp_dir: Annotated[str, typer.Argument(help="Directory with bins")],
               out_dir: Annotated[str, typer.Argument(help="Directory to output logs")], 
               strip: Annotated[bool, typer.Option(help="Strip the files before running")] = False, 
               ):
    '''
    Run IDA on the dataset and retrieve the detected function bounds
    '''

    out_path = Path(out_dir)

    if not out_path.exists():
        out_path.mkdir()
        return

    # Make the time dir
    time_dir = out_path.parent / f"{Path(out_dir).name}_TIME"
    if not time_dir.exists():
        time_dir.mkdir()

    # Get a list of files
    files = list(Path(inp_dir).rglob('*'))

    if len(files) == 0:
        print("No files...")

    # For each file get the functions from IDA 
    for file in alive_it(files):

        # If strip, strip the file 
        if strip:
            nonstrip = file
            file =  gen_strip_file(file)

        # Ge the ida funcs
        funcs , runtime = get_ida_bounds(file)
        func_len_array = np.concatenate((funcs.addresses.T, funcs.lengths.T), axis=1)


        # Delete the stripped file
        if strip:
            file.unlink()
            file = nonstrip

        # The result file a a path obj
        #resfile = Path(out_dir) / f"{file.name}_RESULT"
        #time_file = time_dir / f"{resfile.name}_runtime"

        result_path = Path(out_dir).joinpath(f"{bin.name}")
        save_raw_experiment(file, runtime, func_len_array, result_path)


        # Save the funcs to the out file
        #with open(Path(resfile), 'w') as f:
        #    for func in funcs:
        #        f.write(f"{func..strip()}, {func[1].strip()}\n")
        #with open(time_file, 'w') as f:
        #    f.write(f"{runtime}")

        #with open(Path(resfile), 'w') as f:
        #    for func in funcs:
        #        f.write(f"{func.start_addr}, {func.end_addr}, {func.name}\n")
        #with open(time_file, 'w') as f:
        #    f.write(f"{runtime}")
    return 



@app.command()
def batch_get_funcs(
               inp_dir: Annotated[str, typer.Argument(help="Directory with bins")],
               out_dir: Annotated[str, typer.Argument(help="Directory to output logs")], 
               strip: Annotated[bool, typer.Option(help="Strip the files before running")] = False, 
               ):
    '''
    Batch run ida on bins
    '''

    out_path = Path(out_dir)

    if not out_path.exists():
        out_path.mkdir()
        return

    # Make the time dir
    time_dir = out_path.parent / f"{Path(out_dir).name}_TIME"
    if not time_dir.exists():
        time_dir.mkdir()

    # Get a list of files
    files = list(Path(inp_dir).rglob('*'))

    # For each file get the functions from IDA 
    for file in alive_it(files):

        # If strip, strip the file 
        if strip:
            nonstrip = file
            file =  gen_strip_file(file)

        # Ge the ida funcs
        funcs, runtime = get_ida_funcs(file)

        # Delete the stripped file
        if strip:
            file.unlink()
            file = nonstrip

        # The result file a a path obj
        resfile = Path(out_dir) / f"{file.name}_RESULT"
        time_file = time_dir / f"{resfile.name}_runtime"

        # Save the funcs to the out file
        with open(Path(resfile), 'w') as f:
            for func in funcs:
                f.write(f"{func[0].strip()}, {func[1].strip()}\n")
        with open(time_file, 'w') as f:
            f.write(f"{runtime}")

    return 



@dataclass
class ConfusionMatrix:
    tp: int
    fp: int
    tn: int
    fn: int


@dataclass
class FileBundles:
    same: np.ndarray
    lief_unique: np.ndarray
    ida_unique: np.ndarray

#TODO: Remove new format as it gets phased out 
#TODO: This function only works when I am using the specific IDA script,
#       I should specificy somewhere that this ONLY works for list_function_bounds
def read_res(inp:Path, bin, new_format=True):
    '''
    Parse the IDA log file for a given analysis on a binary for functions
    '''

    lief_funcs = get_functions(bin)
    gnd = {x.addr : (x.name, x.size) for x in lief_funcs}
    gnd_start = np.array([int(x) for x in gnd.keys()])
    gnd_ends = np.array([int(x+gnd[x][1]) for x in gnd.keys()])

    ida_starts = [] 
    ida_ends = [] 


    # Read the result 
    with open(inp, 'r') as f:
        for line in f.readlines():
            if new_format:
                ida_starts.append(line.strip().split(',')[0].strip())
                ida_ends.append(line.strip().split(',')[1].strip())
                #res.append((int(start_addr),int(end_addr)))
            else:
                line = line.strip().split(',')[0].strip()
                ida_starts.append(int(line,16))

    starts_bundle = FileBundles(
        np.intersect1d(gnd_start, ida_starts),
        np.setdiff1d( gnd_start, ida_starts),
        np.setdiff1d( ida_starts, gnd_start),
    )

    # Each is a list of addresses
    #starts_same = np.intersect1d(gnd_start, ida_starts)
    #starts_lief_only = np.setdiff1d( gnd_start, ida_starts)
    #starts_ida_only = np.setdiff1d( ida_starts, gnd_start )

    # Get the ends results 
    if new_format:
        ends_bundle = FileBundles(
            np.intersect1d(gnd_ends, ida_ends),
            np.setdiff1d( gnd_ends, ida_ends),
            np.setdiff1d( ida_ends, gnd_ends),
        )
    else:
        ends_bundle = FileBundles(np.array([]),np.array([]), np.array([]))

    return starts_bundle, ends_bundle
    #return starts_same, starts_lief_only, starts_ida_only


#TODO: Convert the old logs, which logged found functions using hex, to the new logs, which 
#      logs found funcs using base 10
@app.command()
def read_results(
        inp_dir: Annotated[str, typer.Argument(help="Directory with results")],
        bin_dir: Annotated[str, typer.Argument(help="Directory with bins")],
        time_dir: Annotated[str, typer.Argument(help="Directory with time")],
        is_new_format: Annotated[bool, typer.Option(help="Switch to off if results seem low. Older logs require this option to be false")]=True,
    ):

    files = Path(inp_dir).glob('*')
    bins = Path(bin_dir).glob('*')

    tot_size = 0
    # Get the size of the stripped bins 
    for bin in bins:
        stripped_bin = gen_strip_file(bin)
        tot_size+=stripped_bin.stat().st_size
        stripped_bin.unlink()

    tot_time = 0
    for bin in Path(time_dir).rglob('*'):
        with open(bin, 'r') as inp:
            tot_time += float(inp.readline().strip())


    src = []
    for file in files:
        bin = Path(f"{bin_dir}/{file.name.replace('_RESULT','')}")
        src .append((file,bin))


    starts_conf_matrix = ConfusionMatrix(0,0,0,0)
    ends_conf_matrix = ConfusionMatrix(0,0,0,0)


    for (file,bin) in alive_it(src):
        if is_new_format:
            #same, lief_o, ida_o = read_res(file,bin,new_format=False)
            starts, ends = read_res(file,bin,new_format=True)
        else:
            starts, ends = read_res(file,bin,new_format=False)
            #same, lief_o, ida_o = read_res(file,bin)

        starts_conf_matrix.tp += len(starts.same)
        starts_conf_matrix.fp += len(starts.ida_unique)
        starts_conf_matrix.fn += len(starts.lief_unique)

        ends_conf_matrix.tp += len(ends.same)
        ends_conf_matrix.fp += len(ends.ida_unique)
        ends_conf_matrix.fn += len(ends.lief_unique)


        #tot_same += len(same)
        #tot_lief_only += len(lief_o)
        #tot_ida_only += len(ida_o)

    try:
        starts_recall = starts_conf_matrix.tp / (starts_conf_matrix.tp + starts_conf_matrix.fn)
        ends_recall = ends_conf_matrix.tp / (ends_conf_matrix.tp + ends_conf_matrix.fn)

        starts_prec = starts_conf_matrix.tp / (starts_conf_matrix.tp + starts_conf_matrix.fp)
        ends_prec = ends_conf_matrix.tp / (ends_conf_matrix.tp + ends_conf_matrix.fp)

        start_f1 = (2*starts_prec*starts_recall)/(starts_prec+starts_recall)
        end_f1 = (2*ends_prec*ends_recall)/(ends_prec+ends_recall)
    except ZeroDivisionError as e:
        print(f"One of the tests resulted in: precision+recall == 0, or fp+tp=0, or tp+fn=0")
        print(e)
        print(starts_conf_matrix)
        print(ends_conf_matrix)
        return

    # Recall = # Correct Pos lbls /  # Ground Trurth Pos lbls
    # Recall = tp / (tp+fn) 
    #recall = tot_same / (tot_same+tot_lief_only)

    # Prec = #pos_lbl / #
    # Prec = tp / (tp+fp)
    #prec = tot_same / (tot_same + tot_ida_only)

    # F1 
    #f1 = (2*prec*recall)/(prec+recall)

    print(f"Starts............")
    print(f"Recall:{starts_recall}")     
    print(f"Prev:{starts_prec}")
    print(f"F1:{start_f1}")
    print(f"=========== ENDS ============")
    print(f"Recall:{ends_recall}")     
    print(f"Prev:{ends_prec}")
    print(f"F1:{end_f1}")
    print(f"Size:{tot_size}")
    print(f"Time:{tot_time}")
    print(f"BPS:{tot_size/tot_time}")
    print(f"============ START CONF MARTIX ==========")
    print(starts_conf_matrix)
    print(f"============ END CONF MARTIX ==========")
    print(ends_conf_matrix)
    return




if __name__ == "__main__":
    app()
