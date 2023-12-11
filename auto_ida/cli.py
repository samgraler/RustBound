import typer 
import subprocess
from typing_extensions import Annotated
import rich 
from rich.console import Console
from pathlib import Path

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

    func_list = Path("function_list.py").resolve()

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
    ida_log_file = file.resolve().parent / f"{file.name}_IDA_LOG.log"

    # Get the commands to run ida and clear the extra files 
    cmd, clear_cmd = make_ida_cmd(file, ida_log_file)


    # Run the command to run ida 
    res = subprocess.check_output(cmd,shell=True)

    # Fet the functions from the log file 
    funcs = read_raw_log(ida_log_file)

    # Delete the log file 
    ida_log_file.unlink()

    # Remove the database file 
    res = subprocess.check_output(clear_cmd, shell=True)

    return funcs

@app.command()
def batch_get_funcs(inp_dir: Annotated[str, typer.Argument(help="Directory with bins")],
               out_dir: Annotated[str, typer.Argument(help="Directory to output logs")], 
               ):
    '''
    Batch run ida on bins
    '''

    # For each file get the functions from IDA 
    for file in Path(inp_dir).rglob('*'):
        funcs = get_ida_funcs(file)


    return 




if __name__ == "__main__":
    app()
