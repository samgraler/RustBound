import typer 
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


def make_ida_cmd(binary: Path, logfile: Path):

    #func_list = Path("function_list.py").resolve()

    func_list = Path(os.path.abspath(__file__)).parent / "function_list.py"
    func_list = func_list.resolve()
    ida = Path("~/idapro-8.3/idat64").expanduser()

    cmd = f'{ida.resolve()} -c -A -S"{func_list.resolve()}" -L{logfile.resolve()} {binary.resolve()}'

    #TODO: This only works for i64 
    clear_cmd = f"rm {binary.resolve()}.i64"

    return cmd, clear_cmd



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
def ida_on(binary: Annotated[str, typer.Argument(help="bin to run on")], 
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
    print(res)

    funcs = read_raw_log(Path(logfile))
    print(f"Num funcs {len(funcs)}")

    with open(Path(resfile), 'w') as f:
        for func in funcs:
            f.write(f"{func[0].strip()}, {func[1].strip()}\n")

    # Remove the database file 
    res = subprocess.check_output(clear_cmd, shell=True)
    return

def get_ida_funcs(file: Path):

    # To get the functions, ida logs all the std to a log file 
    #ida_log_file = file.resolve().parent / f"{file.name}_IDA_LOG.log"
    ida_log_file = Path(".") / f"{file.name}_IDA_LOG.log"

    # Get the commands to run ida and clear the extra files 
    cmd, clear_cmd = make_ida_cmd(file, ida_log_file)

    start = time.time()

    # Run the command to run ida 
    res = subprocess.check_output(cmd,shell=True)

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


@app.command()
def batch_get_funcs(
               inp_dir: Annotated[str, typer.Argument(help="Directory with bins")],
               out_dir: Annotated[str, typer.Argument(help="Directory to output logs")], 
               ):
    '''
    Batch run ida on bins
    '''

    if not Path(out_dir).exists():
        print(f"{out_dir} does nto exist")
        return

    time_dir = Path(out_dir).parent / f"{Path(out_dir).name}_TIME"
    time_dir.mkdir()

    # For each file get the functions from IDA 
    for file in alive_it(Path(inp_dir).rglob('*')):

        # Ge the ida funcs
        funcs, runtime = get_ida_funcs(file)

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


def read_res(inp:Path, bin, debug=False):

    lief_funcs = get_functions(bin)
    gnd = {x.addr : (x.name, x.size) for x in lief_funcs}
    gnd_start = np.array([int(x) for x in gnd.keys()])

    res = []
    # Read the result 
    with open(inp, 'r') as f:
        for line in f.readlines():
            line = line.strip().split(',')[0].strip()
            res.append(int(line,16))


    if debug: 
        with open('IDA_FUNC', 'w') as f:
            for addr in res:
                f.write(f'{addr}\n')
        with open('LIEF_FUNC', 'w') as f:
            gnd_start.sort()
            for addr in gnd_start:
                f.write(f'{addr}\n')

    # Each is a list of addresses
    same = np.intersect1d(gnd_start, res)
    lief_only = np.setdiff1d( gnd_start, res)
    ida_only = np.setdiff1d( res, gnd_start )


    return same, lief_only, ida_only


@app.command()
def read_results(
        inp_dir: Annotated[str, typer.Argument(help="Directory with results")],
        bin_dir: Annotated[str, typer.Argument(help="Directory with bins")],
    ):

    files = Path(inp_dir).glob('*')
    bins = Path(bin_dir).glob('*')

    #src = zip(files,bins)
    src = []
    for file in files:
        bin = Path(f"{bin_dir}/{file.name.replace('_RESULT','')}")
        src .append((file,bin))

    tot_same = 0
    tot_lief_only = 0
    tot_ida_only = 0
    debug=True
    for (file,bin) in alive_it(src):
        same, lief_o, ida_o = read_res(file,bin,debug)
        debug=False

        tot_same += len(same)
        tot_lief_only += len(lief_o)
        tot_ida_only += len(ida_o)

    # Recall = # Correct Pos lbls /  # Ground Trurth Pos lbls
    # Recall = tp / (tp+fn) 
    recall = tot_same / (tot_same+tot_lief_only)

    # Prec = #pos_lbl / #
    # Prec = tp / (tp+fp)
    prec = tot_same / (tot_same + tot_ida_only)

    # F1 
    f1 = (2*prec*recall)/(prec+recall)

    print(f"Recall:{recall}")     
    print(f"Prev:{prec}")
    print(f"F1:{f1}")

    return




if __name__ == "__main__":
    app()
