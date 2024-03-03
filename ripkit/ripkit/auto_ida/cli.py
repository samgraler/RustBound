import typer 
from scipy import stats
import shutil
import os
import subprocess
from typing_extensions import Annotated
from rich.console import Console
from pathlib import Path
from alive_progress import alive_it
from dataclasses import dataclass
from typing import List 
import numpy as np
import time
ripkit_dir = Path("../ripkit").resolve()
import sys
import matplotlib.pyplot as plt 
sys.path.append (
    str(ripkit_dir)
)
from ripkit.ripbin import (
    lief_gnd_truth,
    FoundFunctions,
    ConfusionMatrix,
    calc_metrics,
    save_raw_experiment,
    #get_functions,
    #new_file_super_careful_callback,
    new_file_callback,
    #must_be_file_callback,
    iterable_path_shallow_callback,
    iterable_path_deep_callback,
)


console = Console()
app = typer.Typer()

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

#def new_file_super_careful_callback(inp_bin: str)->Path:
#    '''
#    Assert that nothing exists at the new file location
#    '''
#    if Path(inp_bin).exists():
#        raise typer.BadParameter(f"Path {inp_bin} already exists")
#    return Path(inp_bin)
#
#def new_file_callback(inp_bin: str)->Path:
#    '''
#    Assert that the location for the new file does not exist as a 
#    directory. This WILL overwrite existing files with the same name
#    '''
#
#    if Path(inp_bin).is_dir():
#        raise typer.BadParameter(f"File {inp_bin} already exists and is a directory!")
#    return Path(inp_bin)
#
#def must_be_file_callback(inp_bin: str)->Path:
#    '''
#    Callback to guarentee a file exists
#    '''
#    if Path(inp_bin).is_file():
#        return Path(inp_bin)
#    raise typer.BadParameter("Must must a valid file")
#
#def iterable_path_shallow_callback(inp_dir: str)->List[Path]:
#    '''
#    Callback for iterable paths 
#
#    This is useful when a parameter can be a file or a directory of files
#    '''
#    inp_path = Path(inp_dir)
#
#    if inp_path.is_file():
#        return [inp_path]
#    elif inp_path.is_dir():
#        return list(x for x in inp_path.glob('*'))
#    else: 
#        raise typer.BadParameter("Must pass a file or directory path")
#
#
#def iterable_path_deep_callback(inp_dir: str)->List[Path]:
#    '''
#    Callback for iterable paths 
#
#    This is useful when a parameter can be a file or a directory of files
#    '''
#    inp_path = Path(inp_dir)
#
#    if inp_path.is_file():
#        return [inp_path]
#    elif inp_path.is_dir():
#        return [Path(x) for x in inp_path.rglob('*')]
#    raise typer.BadParameter("Must pass a file or directory path")



def make_ida_cmd(binary: Path, logfile: Path):
    '''
    Generate the IDA command that will the selected script and log information
    including any time 'prints' that are called in the selected script to the 
    logfile 
    '''
    func_list = Path(os.path.abspath(__file__)).parent / "function_list.py"
    func_list = func_list.resolve()
    ida = Path("~/idapro-8.3/idat64").expanduser()

    cmd = f'{ida.resolve()} -c -A -S"{func_list.resolve()}" -L{logfile.resolve()} {binary.resolve()}'

    #TODO: This only works for i64 
    clear_cmd = f"rm {binary.resolve()}.i64"
    return cmd, clear_cmd

def read_bounds_log(rawlog: Path)->FoundFunctions:
    '''
    Rarse the saved IDA log, generated from analyzing a binary. 

    Return Functions Addrs, Lengths, and Names
    '''

    # Read the log 
    with open(rawlog, 'r') as f:
        # The lines in the output will have 
        # FUNCTION, addr, function_name
        starts = []
        lengths = []
        names = []
        in_funcs = False
        for line in f.readlines():
            if not in_funcs:
                if "FUNCTION_START_IND_RIPKIT" in line:
                    in_funcs = True
                else:
                    continue
            if "FUNCTION_END_IND_RIPKIT" in line:
                starts = np.array(starts)
                lens = np.array(lengths)
                found_funcs = FoundFunctions(starts,names,lens)
                return found_funcs

            if "RIPKIT_FUNCTION" in line:
                _, start_addr, length, name = line.split('<RIP_SEP>')
                start_addr = int(start_addr.strip())
                length = int(length.strip())
                name = name.strip()
                starts.append(start_addr)
                lengths.append(length)
                names.append(name)

    found_funcs = FoundFunctions(np.array(starts), names=names, lengths=np.array(lengths))
    return found_funcs


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


#@app.command()
#def ida_bounds(
#           binary: Annotated[str, typer.Argument(help="bin to run on")], 
#           resfile: Annotated[str, typer.Argument(help="name of result file")],
#    ):
#
#    bin = Path(binary)
#    if not bin.exists():
#        print(f"Bin {bin} does not exist")
#        return
#    
#    funcs, runtime = get_ida_bounds(bin)
#
#    with open(Path(resfile), 'w') as f:
#        for func in funcs:
#            f.write(f"{func.start_addr}, {func.end_addr}\n")
#
#    print(f"Runtime: {runtime}")
#    return


#@app.command()
#def ida_on(
#           binary: Annotated[str, typer.Argument(help="bin to run on")], 
#           logfile: Annotated[str, typer.Argument(help="bin to run on")],
#           resfile: Annotated[str, typer.Argument(help="name of result file")]):
#    '''
#    Report the IDA detected funtions to the resfile
#    '''
#
#    # Generate the ida command 
#    cmd, clear_cmd = make_ida_cmd(Path(binary), Path(logfile))
#    print(cmd)
#
#    # Run the command to run ida 
#    res = subprocess.check_output(cmd,shell=True)
#    print(res)
#
#    funcs = read_raw_log(Path(logfile))
#    print(f"Num funcs {len(funcs)}")
#
#    with open(Path(resfile), 'w') as f:
#        for func in funcs:
#            f.write(f"{func[0].strip()}, {func[1].strip()}\n")
#
#    # Remove the database file 
#    res = subprocess.check_output(clear_cmd, shell=True)
#    return




def get_ida_bounds(file: Path, strip: bool):
    '''
    Run the IDA analysis for function boundaries 
    '''

    # To get the functions, ida logs all the std to a log file 
    ida_log_file = Path(".") / f"{file.name}_IDA_LOG.log"

    try:
        if strip:
            old_file = file
            file = gen_strip_file(file)

        # Get the commands to run ida and clear the extra files 
        cmd, clear_cmd = generate_ida_cmd_bounds(file, ida_log_file)
        start = time.time()
        # Run the command to run ida 
        res = subprocess.check_output(cmd,shell=True)
        print(res)
        runtime = time.time() - start
    except Exception as e:
        raise(e)
    finally:
        if strip:
            file.unlink()
            file = old_file

        # Remove the database file 
        _ = subprocess.check_output(clear_cmd, shell=True)
    try:
        # Fet the functions from the log file 
        funcs = read_bounds_log(ida_log_file)
    except Exception as e:
        raise(e)
    finally:
        # Delete the log file 
        ida_log_file.unlink()
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

#@app.command()
#def count_funcs(
#    inp_file: Annotated[str, typer.Argument(help="Input file")], 
#    ):
#
#
#    funcs, runtime = get_ida_funcs(Path(inp_file))
#
#    print(f"{len(funcs)} functions")
#
#    return

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

    # Make the time dir
    time_dir = out_path.parent / f"{Path(out_dir).name}_TIME"
    if not time_dir.exists():
        time_dir.mkdir()

    # Get a list of files
    files = list(Path(inp_dir).rglob('*'))

    if len(files) == 0:
        print("No files...")

    # For each file get the functions from IDA 
    #for file in alive_it(files):
    for file in alive_it(files):

        # Ge the ida funcs
        funcs , runtime = get_ida_bounds(file,strip)
        func_len_array = np.concatenate((funcs.addresses.T.reshape(-1,1),
                                         funcs.lengths.T.reshape(-1,1)), axis=1)

        result_path = Path(out_dir).joinpath(f"{file.name}")
        save_raw_experiment(file, runtime, func_len_array, result_path)
    return 

@dataclass
class func_len_inspection:
    bin_name: str
    function_incorrect_len: int
    function_correct_len: int 
    function_start_was_correct: bool

    
@dataclass
class completely_missed_fp:
    start_addrs: List[int]
    lengths: List[int]
    was_fp_start: List[bool]
    was_fn_start: List[bool]

@dataclass
class func_incorrect_lens: 
    tp_start_addrs: List[int]
    incorrect_lens: List[int]
    correct_lens: List[int]


@app.command()
def inspect_many_results(
    results: Annotated[str,typer.Argument(
                callback=iterable_path_deep_callback)],
    bins: Annotated[str,typer.Argument(
                callback=iterable_path_shallow_callback)],
    graph_path: Annotated[str, typer.Argument(
                callback=new_file_callback
                    )],
    ):
    '''
    Inspect many results, specifically examine correct function 
    starts that had incorrect lengths
    '''

    matching_files = {}
    results = [x for x in results if x.is_file() and "result.npz" in x.name]

    for bin_path in bins:
        matching = False
        for res_file in [x for x in results ]:
            if res_file.name.replace("_result.npz","") == bin_path.name:
                matching_files[bin_path] = res_file
                matching = True
        if not matching:
            raise typer.Abort("Some bins dont have matching result files")

    # Observe the tp func starts but the incorrect lengths
    tot_missed_ends = func_incorrect_lens([],[],[])
    for bin_path in alive_it(bins):

        # 1  - Ground truth for bin file 
        gnd_truth = lief_gnd_truth(bin_path.resolve())
        gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                                    gnd_truth.func_lens.T.reshape(-1,1)), axis=1)

        # 2 - Find the npz with the ida funcs and addrs, chop of functions that 
        #     are out-of-bounds of the lief functions (these are functions that are
        #       likely outside of the .text section)
        ida_funcs = read_ida_npz(matching_files[bin_path])

        # 4 - Mask the array so we only include bytes in .text
        mask_max = (ida_funcs[:,0] <= np.max(gnd_truth.func_addrs))
        ida_funcs = ida_funcs[mask_max]

        mask_min = (ida_funcs[:,0] >= np.min(gnd_truth.func_addrs))
        filt_ida_funcs = ida_funcs[mask_min]


        # Check to see how many false negative there were 
        for i, row in enumerate(gnd_matrix):
            if row[0] == filt_ida_funcs[i][0] and row[1] !=  filt_ida_funcs[i][1]:
                tot_missed_ends.tp_start_addrs.append(row[0])
                tot_missed_ends.incorrect_lens.append(filt_ida_funcs[i][1])
                tot_missed_ends.correct_lens.append(row[1])
            #if row[0] != filt_ida_funcs[i][0] and row[1] !=  filt_ida_funcs[i][1]:
            #    missed_both.start_addrs.append(row[0])
            #    missed_both.lengths.append(filt_ida_funcs[i][1])

    ends_missed_length = [x-y for (x,y) in zip(tot_missed_ends.correct_lens, tot_missed_ends.incorrect_lens)]
    total_missed_by = sum(ends_missed_length)


    print(f"Total miss length {total_missed_by}")
    avg_missed_ends = total_missed_by / len(tot_missed_ends.incorrect_lens)
    print(f"Avg missed {avg_missed_ends}")
    print(f"Mean: {np.mean(ends_missed_length)}")
    print(f"Median: {np.median(ends_missed_length)}")
    print(f"Mode: {stats.mode(ends_missed_length)}")

    freqs, bin_edges = np.histogram(ends_missed_length, bins=4)

    print(f"Bins edges: {bin_edges}")
    print(f"Count: {freqs}")

    make_simple_plot(tot_missed_ends.tp_start_addrs, ends_missed_length, "TP function start addresses", "Distance between the FP end nearest correct end from gnd truth", "O1 IDA missed by amoutns" , graph_path )

    make_simple_pdf(tot_missed_ends.tp_start_addrs, ends_missed_length, "Bins", "Frequency", "PDF" , Path(f"{graph_path.name}_pdf_graph") )


    return


@app.command()
def inspect_single_results(
    result: Annotated[str,typer.Argument(callback=iterable_path_deep_callback)],
    bin: Annotated[str,typer.Argument(callback=iterable_path_deep_callback)],
    ):
    '''
    Inspect the misses in the file
    '''
    bin_path = bin[0]
    result_path = result[0]

    # Init the confusion matrix for this bin
    start_conf = ConfusionMatrix(0,0,0,0)
    bound_conf = ConfusionMatrix(0,0,0,0)

    # 1  - Ground truth for bin file 
    gnd_truth = lief_gnd_truth(bin_path.resolve())
    gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                                gnd_truth.func_lens.T.reshape(-1,1)), axis=1)

    # 2 - Find the npz with the ida funcs and addrs, chop of functions that 
    #     are out-of-bounds of the lief functions (these are functions that are
    #       likely outside of the .text section)
    ida_funcs = read_ida_npz(result_path)

    # 4 - Mask the array so we only include bytes in .text
    mask_max = (ida_funcs[:,0] <= np.max(gnd_truth.func_addrs))
    ida_funcs = ida_funcs[mask_max]

    mask_min = (ida_funcs[:,0] >= np.min(gnd_truth.func_addrs))
    filt_ida_funcs = ida_funcs[mask_min]


    # 3 - Compare the two lists
    # Get all the start addrs that are in both, in ida only, in gnd_trush only
    start_conf.tp=len(np.intersect1d(gnd_matrix[:,0], filt_ida_funcs[:,0]))
    start_conf.fp=len(np.setdiff1d( filt_ida_funcs[:,0], gnd_matrix[:,0] ))
    start_conf.fn=len(np.setdiff1d(gnd_matrix[:,0], filt_ida_funcs[:,0]))

    # tp + fp = Total predicted
    if not start_conf.tp + start_conf.fp == filt_ida_funcs.shape[0]:
        print(f"{start_conf.tp}")
        print(f"{start_conf.fp}")
        print(f"{filt_ida_funcs.shape[0]}")
        raise Exception

    # tp + fn = total pos
    if not start_conf.tp + start_conf.fn == gnd_matrix.shape[0]:
        print(f"{start_conf.fp}")
        print(f"{start_conf.fn}")
        print(f"{filt_ida_funcs.shape[0]}")
        raise Exception

    # Check the predicted bounds for correctness
    for row in filt_ida_funcs:
        if np.any(np.all(row == gnd_matrix, axis=1)): 
            bound_conf.tp+=1
        else:
            bound_conf.fp+=1

    # Observe the tp func starts but the incorrect lengths
    missed_ends = func_incorrect_lens([],[],[])

    # Observe the fp where the start was fp and the end was wrogn
    missed_both = completely_missed_fp([],[],[],[])

    # Check to see how many false negative there were 
    for i, row in enumerate(gnd_matrix):

        # If the boudns are exauasted these are all false negatives
        if i >= filt_ida_funcs.shape[0]:
            bound_conf.fn+=1
            continue
            
        if row[0] == filt_ida_funcs[i][0] and row[1] !=  filt_ida_funcs[i][1]:
            missed_ends.tp_start_addrs.append(row[0])
            missed_ends.incorrect_lens.append(filt_ida_funcs[i][1])
            missed_ends.correct_lens.append(row[1])
        if row[0] != filt_ida_funcs[i][0] and row[1] !=  filt_ida_funcs[i][1]:
            missed_both.start_addrs.append(row[0])
            missed_both.lengths.append(filt_ida_funcs[i][1])

        # If gnd matrix has any rows that aren't in ida funcs then its a false neg
        if not np.any(np.all(row == filt_ida_funcs, axis=1)):
            bound_conf.fn+=1

    ends_missed_length = [x-y for (x,y) in zip(missed_ends.correct_lens, missed_ends.incorrect_lens)]
    total_missed_by = sum(ends_missed_length)

    print(f"Function start confusion matrix: {start_conf}")
    print(f"Function bound confusion matrix: {bound_conf}")

    print(f"Total miss length {total_missed_by}")
    avg_missed_ends = total_missed_by / len(missed_ends.incorrect_lens)
    print(f"Avg missed {avg_missed_ends}")
    print(f"Mean: {np.mean(ends_missed_length)}")
    print(f"Median: {np.median(ends_missed_length)}")
    print(f"Mode: {stats.mode(ends_missed_length)}")

    freqs, bin_edges = np.histogram(ends_missed_length, bins=8)
    print(f"Bins edges: {bin_edges}")
    print(f"Count: {freqs}")

    make_simple_plot(missed_ends.tp_start_addrs, ends_missed_length, "TP function start addresses", "Distance between the FP end nearest correct end from gnd truth", f"Distance between predicted functions ends and correct function ends vs TP start addres for binary {bin_path.name}",Path(f"{bin_path.name}_ends_plot.png") )

    make_simple_pdf(missed_ends.tp_start_addrs, ends_missed_length, "Distribution of FP distance from TP", "Frequency", f"PDF of FP delta TP for {bin_path.name}",Path(f"{bin_path.name}_ends_pdf.png") )

    return

def make_simple_plot(x,y, label_x:str, label_y:str, title:str, save_path:Path):
    '''
    Super simple scatter plot the plotting the missed functions
    '''

    x = np.array(x)
    y = np.array(y)


    plt.scatter(x,y)
    plt.xlabel(label_x)
    plt.xlabel(label_x)
    plt.title(title)
    plt.grid(True)
    plt.savefig(save_path)
    return

def make_simple_pdf(x,y, label_x: str, label_y: str, title:str, save_path: Path):
    '''
    Make a simple probability density graph
    '''

    y = np.array(y)

    # Define the bin size
    bin_size = 4
    
    # Calculate the histogram
    hist, bins = np.histogram(y, bins=np.arange(min(y), max(y) + bin_size, bin_size))
    
    # Plot the histogram
    plt.bar(bins[:-1], hist, width=bin_size, align='center')
    
    # Set the x-axis to have its center at 0
    plt.xlim(-max(abs(y)), max(abs(y)))
    
    # Add labels and title
    plt.xlabel(label_x)
    plt.ylabel(label_y)
    plt.title(title)

    #print(f"Total miss length {total_missed_by}")
    #avg_missed_ends = total_missed_by / len(tot_missed_ends.incorrect_lens)
    #print(f"Avg missed {avg_missed_ends}")
    #print(f"Mean: {np.mean(ends_missed_length)}")
    #print(f"Median: {np.median(ends_missed_length)}")
    #print(f"Mode: {stats.mode(ends_missed_length)}")

    freqs, bin_edges = np.histogram(ends_missed_length, bins=4)





        # Define bin size
    #bin_size = 8

    #x = np.array(x)
    #y = np.array(y)
    #
    ## Calculate the range of y values
    #y_min = np.min(y)
    #y_max = np.max(y)
    #
    ## Calculate the number of bins
    #num_bins = int(np.ceil((y_max - y_min) / bin_size))
    #
    ## Create bins
    #bins = np.arange(y_min, y_max , num_bins+1 )
    #
    ## Plot histogram
    #plt.hist(y, bins=bins, density=True, edgecolor='black', alpha=0.7)
    #
    ## Add labels and title
    #plt.xlabel('Y Values')
    #plt.ylabel('Frequency')
    #plt.title('Distribution of Y Values')
    
    # Show plot
    plt.savefig(save_path)

    return 



@app.command()
def read_results(
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
        matching = False
        for res_file in input_path.rglob('*'):
            if ".npz" not in res_file.name:
                continue
            if res_file.name.replace("_result.npz","") == bin.name:
                matching_files[bin] = res_file
                matching = True
        if not matching:
            print(f"Never found {bin.name}")


    if len(matching_files.keys()) != len(list(bin_path.glob('*'))):
        msg = f"Found {len(matching_files.keys())}: {matching_files.keys()}"
        print(f"{matching_files.keys()}")
        print(f"Some bins don't have matching result file")
        raise Exception(msg)


    total_start_conf = ConfusionMatrix(0,0,0,0)
    total_bound_conf = ConfusionMatrix(0,0,0,0)
    total_bytes = 0

    for bin in alive_it(list(matching_files.keys())):
        # Init the confusion matrix for this bin
        start_conf = ConfusionMatrix(0,0,0,0)
        bound_conf = ConfusionMatrix(0,0,0,0)

        # 1  - Ground truth for bin file, func addr, len
        gnd_truth = lief_gnd_truth(bin.resolve())
        gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                                    gnd_truth.func_lens.T.reshape(-1,1)), axis=1)

        # 2 - Find the npz with the ida funcs and addrs, chop of functions that 
        #     are out-of-bounds of the lief functions (these are functions that are
        #       likely outside of the .text section)
        ida_funcs = read_ida_npz(matching_files[bin])

        # 4 - Mask the array so we only include bytes in .text
        mask_max = (ida_funcs[:,0] <= np.max(gnd_truth.func_addrs))
        ida_funcs = ida_funcs[mask_max]

        mask_min = (ida_funcs[:,0] >= np.min(gnd_truth.func_addrs))
        filt_ida_funcs = ida_funcs[mask_min]


        # 3 - Compare the two lists
        # Get all the start addrs that are in both, in ida only, in gnd_trush only
        start_conf.tp=len(np.intersect1d(gnd_matrix[:,0], filt_ida_funcs[:,0]))
        start_conf.fp=len(np.setdiff1d( filt_ida_funcs[:,0], gnd_matrix[:,0] ))
        start_conf.fn=len(np.setdiff1d(gnd_matrix[:,0], filt_ida_funcs[:,0]))


        # tp + fp = Total predicted
        if not start_conf.tp + start_conf.fp == filt_ida_funcs.shape[0]:
            print(f"{start_conf.tp}")
            print(f"{start_conf.fp}")
            print(f"{filt_ida_funcs.shape[0]}")
            raise Exception

        # tp + fn = total pos
        if not start_conf.tp + start_conf.fn == gnd_matrix.shape[0]:
            print(f"{start_conf.fp}")
            print(f"{start_conf.fn}")
            print(f"{filt_ida_funcs.shape[0]}")
            raise Exception

        # Check the predicted bounds for correctness
        for row in filt_ida_funcs:
            if np.any(np.all(row == gnd_matrix, axis=1)): 
                bound_conf.tp+=1
            else:
                bound_conf.fp+=1

        # Check to see how many false negative there were 
        for row in gnd_matrix:
            if not np.any(np.all(row == filt_ida_funcs, axis=1)):
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
            print(f"Starts Metrics: {calc_metrics(start_conf)}")
            print(f"Bounds Metrics: {calc_metrics(bound_conf)}")

    print(f"Start conf: {total_start_conf}")
    print(f"Starts Metrics: {calc_metrics(total_start_conf)}")
    print(f"Bound conf: {total_bound_conf}")
    print(f"Bounds Metrics: {calc_metrics(total_bound_conf)}")
    return 

def read_ida_npz(inp: Path)->np.ndarray:
    '''
    Read the ida npz
    '''
    npz_file = np.load(inp)
    return npz_file[list(npz_file.keys())[0]].astype(int)



#@app.command()
#def batch_get_funcs(
#               inp_dir: Annotated[str, typer.Argument(help="Directory with bins")],
#               out_dir: Annotated[str, typer.Argument(help="Directory to output logs")], 
#               strip: Annotated[bool, typer.Option(help="Strip the files before running")] = False, 
#               ):
#    '''
#    Batch run ida on bins
#    '''
#
#    out_path = Path(out_dir)
#
#    if not out_path.exists():
#        out_path.mkdir()
#        return
#
#    # Make the time dir
#    time_dir = out_path.parent / f"{Path(out_dir).name}_TIME"
#    if not time_dir.exists():
#        time_dir.mkdir()
#
#    # Get a list of files
#    files = list(Path(inp_dir).rglob('*'))
#
#    # For each file get the functions from IDA 
#    for file in alive_it(files):
#
#        # If strip, strip the file 
#        if strip:
#            nonstrip = file
#            file =  gen_strip_file(file)
#
#        # Ge the ida funcs
#        funcs, runtime = get_ida_funcs(file)
#
#        # Delete the stripped file
#        if strip:
#            file.unlink()
#            file = nonstrip
#
#        # The result file a a path obj
#        resfile = Path(out_dir) / f"{file.name}_RESULT"
#        time_file = time_dir / f"{resfile.name}_runtime"
#
#        # Save the funcs to the out file
#        with open(Path(resfile), 'w') as f:
#            for func in funcs:
#                f.write(f"{func[0].strip()}, {func[1].strip()}\n")
#        with open(time_file, 'w') as f:
#            f.write(f"{runtime}")
#    return 


#@dataclass
#class FileBundles:
#    same: np.ndarray
#    lief_unique: np.ndarray
#    ida_unique: np.ndarray

#TODO: Remove new format as it gets phased out 
#TODO: This function only works when I am using the specific IDA script,
#       I should specificy somewhere that this ONLY works for list_function_bounds
#def read_res(inp:Path, bin, new_format=True):
#    '''
#    Parse the IDA log file for a given analysis on a binary for functions
#    '''
#
#    lief_funcs = get_functions(bin)
#    gnd = {x.addr : (x.name, x.size) for x in lief_funcs}
#    gnd_start = np.array([int(x) for x in gnd.keys()])
#    gnd_ends = np.array([int(x+gnd[x][1]) for x in gnd.keys()])
#
#    ida_starts = [] 
#    ida_ends = [] 
#
#
#    # Read the result 
#    with open(inp, 'r') as f:
#        for line in f.readlines():
#            if new_format:
#                ida_starts.append(line.strip().split(',')[0].strip())
#                ida_ends.append(line.strip().split(',')[1].strip())
#                #res.append((int(start_addr),int(end_addr)))
#            else:
#                line = line.strip().split(',')[0].strip()
#                ida_starts.append(int(line,16))
#
#    starts_bundle = FileBundles(
#        np.intersect1d(gnd_start, ida_starts),
#        np.setdiff1d( gnd_start, ida_starts),
#        np.setdiff1d( ida_starts, gnd_start),
#    )
#
#    # Each is a list of addresses
#    #starts_same = np.intersect1d(gnd_start, ida_starts)
#    #starts_lief_only = np.setdiff1d( gnd_start, ida_starts)
#    #starts_ida_only = np.setdiff1d( ida_starts, gnd_start )
#
#    # Get the ends results 
#    if new_format:
#        ends_bundle = FileBundles(
#            np.intersect1d(gnd_ends, ida_ends),
#            np.setdiff1d( gnd_ends, ida_ends),
#            np.setdiff1d( ida_ends, gnd_ends),
#        )
#    else:
#        ends_bundle = FileBundles(np.array([]),np.array([]), np.array([]))
#
#    return starts_bundle, ends_bundle
#    #return starts_same, starts_lief_only, starts_ida_only


#TODO: Convert the old logs, which logged found functions using hex, to the new logs, which 
#      logs found funcs using base 10
#@app.command()
#def read_results(
#        inp_dir: Annotated[str, typer.Argument(help="Directory with results")],
#        bin_dir: Annotated[str, typer.Argument(help="Directory with bins")],
#        time_dir: Annotated[str, typer.Argument(help="Directory with time")],
#        is_new_format: Annotated[bool, typer.Option(help="Switch to off if results seem low. Older logs require this option to be false")]=True,
#    ):
#
#    files = Path(inp_dir).glob('*')
#    bins = Path(bin_dir).glob('*')
#
#    tot_size = 0
#    # Get the size of the stripped bins 
#    for bin in bins:
#        stripped_bin = gen_strip_file(bin)
#        tot_size+=stripped_bin.stat().st_size
#        stripped_bin.unlink()
#
#    tot_time = 0
#    for bin in Path(time_dir).rglob('*'):
#        with open(bin, 'r') as inp:
#            tot_time += float(inp.readline().strip())
#
#
#    src = []
#    for file in files:
#        bin = Path(f"{bin_dir}/{file.name.replace('_RESULT','')}")
#        src.append((file,bin))
#
#
#    starts_conf_matrix = ConfusionMatrix(0,0,0,0)
#    ends_conf_matrix = ConfusionMatrix(0,0,0,0)
#
#
#    for (file,bin) in alive_it(src):
#        if is_new_format:
#            #same, lief_o, ida_o = read_res(file,bin,new_format=False)
#            starts, ends = read_res(file,bin,new_format=True)
#        else:
#            starts, ends = read_res(file,bin,new_format=False)
#            #same, lief_o, ida_o = read_res(file,bin)
#
#        starts_conf_matrix.tp += len(starts.same)
#        starts_conf_matrix.fp += len(starts.ida_unique)
#        starts_conf_matrix.fn += len(starts.lief_unique)
#
#        ends_conf_matrix.tp += len(ends.same)
#        ends_conf_matrix.fp += len(ends.ida_unique)
#        ends_conf_matrix.fn += len(ends.lief_unique)
#
#
#        #tot_same += len(same)
#        #tot_lief_only += len(lief_o)
#        #tot_ida_only += len(ida_o)
#
#    try:
#        starts_recall = starts_conf_matrix.tp / (starts_conf_matrix.tp + starts_conf_matrix.fn)
#        ends_recall = ends_conf_matrix.tp / (ends_conf_matrix.tp + ends_conf_matrix.fn)
#
#        starts_prec = starts_conf_matrix.tp / (starts_conf_matrix.tp + starts_conf_matrix.fp)
#        ends_prec = ends_conf_matrix.tp / (ends_conf_matrix.tp + ends_conf_matrix.fp)
#
#        start_f1 = (2*starts_prec*starts_recall)/(starts_prec+starts_recall)
#        end_f1 = (2*ends_prec*ends_recall)/(ends_prec+ends_recall)
#    except ZeroDivisionError as e:
#        print(f"One of the tests resulted in: precision+recall == 0, or fp+tp=0, or tp+fn=0")
#        print(e)
#        print(starts_conf_matrix)
#        print(ends_conf_matrix)
#        return
#
#    # Recall = # Correct Pos lbls /  # Ground Trurth Pos lbls
#    # Recall = tp / (tp+fn) 
#    #recall = tot_same / (tot_same+tot_lief_only)
#
#    # Prec = #pos_lbl / #
#    # Prec = tp / (tp+fp)
#    #prec = tot_same / (tot_same + tot_ida_only)
#
#    # F1 
#    #f1 = (2*prec*recall)/(prec+recall)
#
#    print(f"Starts............")
#    print(f"Recall:{starts_recall}")     
#    print(f"Prev:{starts_prec}")
#    print(f"F1:{start_f1}")
#    print(f"=========== ENDS ============")
#    print(f"Recall:{ends_recall}")     
#    print(f"Prev:{ends_prec}")
#    print(f"F1:{end_f1}")
#    print(f"Size:{tot_size}")
#    print(f"Time:{tot_time}")
#    print(f"BPS:{tot_size/tot_time}")
#    print(f"============ START CONF MARTIX ==========")
#    print(starts_conf_matrix)
#    print(f"============ END CONF MARTIX ==========")
#    print(ends_conf_matrix)
#    return




if __name__ == "__main__":
    app()
