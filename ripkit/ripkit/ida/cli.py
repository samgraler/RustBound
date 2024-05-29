import typer
from scipy import stats
import shutil
from multiprocessing import Pool
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
from ripkit.score import (
    score_start_plus_len,
    load_ida_prediction,
    gnd_truth_start_plus_len,
    analyze_distances,
)

sys.path.append(str(ripkit_dir))
from ripkit.ripbin import (
    lief_gnd_truth,
    FoundFunctions,
    ConfusionMatrix,
    calc_metrics,
    save_raw_experiment,
    # get_functions,
    # new_file_super_careful_callback,
    new_file_callback,
    # must_be_file_callback,
    iterable_path_shallow_callback,
    iterable_path_deep_callback,
)


console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)


def generate_ida_cmd(binary: Path, logfile: Path, ida_script: Path):
    """
    Geneate a command to run IDA with the selected script

    binary: Path
        Binary to analyze with IDA Pro
    logfile: Path
        The output file for the analysis, typically is parsed for results
    ida_script: Path
        Script using IDA Pro's API to run for analysis
    """

    ida = Path("~/idapro-8.3/idat64").expanduser()
    return f'{ida.resolve()} -c -A -S"{ida_script.resolve()}" -L{logfile.resolve()} {binary.resolve()}'


# TODO: Bad implementation... hard coded, but fast
def generate_ida_cmd_bounds(binary: Path, logfile: Path):
    """
    Generate command to run IDA with the selected script

    binary: Path
        The binary to run IDA on

    logile: Path
        The output file for the analysis, typically is parsed for results
    """

    bound_list = Path(os.path.abspath(__file__)).parent / "function_bounds_list.py"
    bound_list = bound_list.resolve()
    clear_cmd = f"rm {binary.resolve()}.i64"
    return generate_ida_cmd(binary, logfile, bound_list), clear_cmd


def make_ida_cmd(binary: Path, logfile: Path):
    """
    Generate the IDA command that will the selected script and log information
    including any time 'prints' that are called in the selected script to the
    logfile
    """
    func_list = Path(os.path.abspath(__file__)).parent / "function_list.py"
    func_list = func_list.resolve()
    ida = Path("~/idapro-8.3/idat64").expanduser()

    cmd = f'{ida.resolve()} -c -A -S"{func_list.resolve()}" -L{logfile.resolve()} {binary.resolve()}'

    # TODO: This only works for i64
    clear_cmd = f"rm {binary.resolve()}.i64"
    return cmd, clear_cmd


def read_bounds_log(rawlog: Path) -> FoundFunctions:
    """
    Rarse the saved IDA log, generated from analyzing a binary.

    Return Functions Addrs, Lengths, and Names
    """

    # Read the log
    with open(rawlog, "r") as f:
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
                found_funcs = FoundFunctions(starts, names, lens)
                return found_funcs

            if "RIPKIT_FUNCTION" in line:
                _, start_addr, length, name = line.split("<RIP_SEP>")
                start_addr = int(start_addr.strip())
                length = int(length.strip())
                name = name.strip()
                starts.append(start_addr)
                lengths.append(length)
                names.append(name)

    found_funcs = FoundFunctions(
        np.array(starts), names=names, lengths=np.array(lengths)
    )
    return found_funcs


def read_raw_log(rawlog: Path):
    """
    Parse raw log generated from ida on command
    """

    # Function tuples
    func_tuples = []

    # Read the log
    with open(rawlog, "r") as f:

        # The lines in the output will have
        # FUNCTION, addr, function_name
        for line in f.readlines():
            if "FUNCTION," in line:
                _, addr, name = line.split(",")
                addr = addr.strip()
                name = name.strip()
                func_tuples.append((addr, name))

    return func_tuples


# @app.command()
# def ida_bounds(
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


# @app.command()
# def ida_on(
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
    """
    Run the IDA analysis for function boundaries
    """

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
        res = subprocess.check_output(cmd, shell=True)
        # print(res)
        runtime = time.time() - start
    except Exception as e:
        raise (e)
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
        raise (e)
    finally:
        # Delete the log file
        ida_log_file.unlink()
    return funcs, runtime


def get_ida_funcs(file: Path):

    # To get the functions, ida logs all the std to a log file
    # ida_log_file = file.resolve().parent / f"{file.name}_IDA_LOG.log"
    ida_log_file = Path(".") / f"{file.name}_IDA_LOG.log"

    # Get the commands to run ida and clear the extra files
    cmd, clear_cmd = make_ida_cmd(file, ida_log_file)

    start = time.time()

    # Run the command to run ida
    res = subprocess.check_output(cmd, shell=True)
    print(res)

    # res = subprocess.run(cmd,text=True,capture_output=True,
    #                     universal_newlines=True)

    runtime = time.time() - start

    # Fet the functions from the log file
    funcs = read_raw_log(ida_log_file)

    # Delete the log file
    ida_log_file.unlink()

    # Remove the database file
    res = subprocess.check_output(clear_cmd, shell=True)

    return funcs, runtime


# @app.command()
# def count_funcs(
#    inp_file: Annotated[str, typer.Argument(help="Input file")],
#    ):
#
#
#    funcs, runtime = get_ida_funcs(Path(inp_file))
#
#    print(f"{len(funcs)} functions")
#
#    return


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


@app.command()
def batch_get_bounds(
    inp_dir: Annotated[str, typer.Argument(help="Directory with bins")],
    out_dir: Annotated[str, typer.Argument(help="Directory to output logs")],
    strip: Annotated[bool, typer.Option(help="Strip the files before running")] = False,
):
    """
    Run IDA on the dataset and retrieve the detected function bounds
    """

    out_path = Path(out_dir)

    if not out_path.exists():
        out_path.mkdir()

    # Make the time dir
    time_dir = out_path.parent / f"{Path(out_dir).name}_TIME"
    if not time_dir.exists():
        time_dir.mkdir()

    # Get a list of files
    files = list(Path(inp_dir).rglob("*"))

    if len(files) == 0:
        print("No files...")

    # For each file get the functions from IDA
    # for file in alive_it(files):
    for file in alive_it(files):

        # Ge the ida funcs
        funcs, runtime = get_ida_bounds(file, strip)
        func_len_array = np.concatenate(
            (funcs.addresses.T.reshape(-1, 1), funcs.lengths.T.reshape(-1, 1)), axis=1
        )

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
    results: Annotated[str, typer.Argument(callback=iterable_path_deep_callback)],
    bins: Annotated[str, typer.Argument(callback=iterable_path_shallow_callback)],
    graph_path: Annotated[str, typer.Argument(callback=new_file_callback)],
):
    """
    Inspect many results, specifically examine correct function
    starts that had incorrect lengths
    """

    matching_files = {}
    results = [x for x in results if x.is_file() and "result.npz" in x.name]

    for bin_path in bins:
        matching = False
        for res_file in [x for x in results]:
            if res_file.name.replace("_result.npz", "") == bin_path.name:
                matching_files[bin_path] = res_file
                matching = True
        if not matching:
            raise typer.Abort("Some bins dont have matching result files")

    # Observe the tp func starts but the incorrect lengths
    tot_missed_ends = func_incorrect_lens([], [], [])
    # Observe the fp where the start was fp and the end was wrogn
    tot_missed_both = completely_missed_fp([], [], [], [])

    for bin_path, result_path in matching_files.items():

        # 1  - Ground truth for bin file
        gnd_truth = lief_gnd_truth(bin_path.resolve())
        gnd_matrix = np.concatenate(
            (
                gnd_truth.func_addrs.T.reshape(-1, 1),
                gnd_truth.func_lens.T.reshape(-1, 1),
            ),
            axis=1,
        )

        # 2 - Find the npz with the ida funcs and addrs, chop of functions that
        #     are out-of-bounds of the lief functions (these are functions that are
        #       likely outside of the .text section)
        ida_funcs = load_ida_prediction(result_path)

        # 4 - Mask the array so we only include bytes in .text
        mask_max = ida_funcs[:, 0] <= np.max(gnd_truth.func_addrs)
        ida_funcs = ida_funcs[mask_max]

        mask_min = ida_funcs[:, 0] >= np.min(gnd_truth.func_addrs)
        filt_ida_funcs = ida_funcs[mask_min]

        # Check to see how many false negative there were
        for i, row in enumerate(gnd_matrix):

            # If the boudns are exauasted these are all false negatives
            if i >= filt_ida_funcs.shape[0]:
                continue

            if row[0] == filt_ida_funcs[i][0] and row[1] != filt_ida_funcs[i][1]:
                tot_missed_ends.tp_start_addrs.append(row[0])
                tot_missed_ends.incorrect_lens.append(filt_ida_funcs[i][1])
                tot_missed_ends.correct_lens.append(row[1])
            if row[0] != filt_ida_funcs[i][0] and row[1] != filt_ida_funcs[i][1]:
                tot_missed_both.start_addrs.append(row[0])
                tot_missed_both.lengths.append(filt_ida_funcs[i][1])

    tot_ends_missed_length = [
        y - x
        for (x, y) in zip(tot_missed_ends.correct_lens, tot_missed_ends.incorrect_lens)
    ]

    print(f"Total miss length {sum(tot_ends_missed_length)}")
    avg_missed_ends = sum(tot_ends_missed_length) / len(tot_ends_missed_length)
    print(f"Avg missed {avg_missed_ends}")
    print(f"Mean: {np.mean(tot_ends_missed_length)}")
    print(f"Median: {np.median(tot_ends_missed_length)}")
    print(f"Mode: {stats.mode(tot_ends_missed_length)}")

    make_simple_plot(
        tot_missed_ends.tp_start_addrs,
        tot_ends_missed_length,
        "TP function start addresses",
        "Distance between the FP end nearest correct end from gnd truth",
        f"Distance between predicted functions ends and correct function ends vs TP start addres for binary {bin_path.name}",
        Path(f"{bin_path.name}_ends_plot.png"),
    )

    make_simple_pdf(
        tot_ends_missed_length,
        "Distribution of FP distance from TP",
        "Frequency",
        f"PDF of FP delta TP ",
        Path(graph_path),
    )
    return


@app.command()
def inspect_single_results(
    result: Annotated[str, typer.Argument(callback=iterable_path_deep_callback)],
    bin: Annotated[str, typer.Argument(callback=iterable_path_deep_callback)],
):
    """
    Inspect the misses in the file
    """
    bin_path = bin[0]
    result_path = result[0]

    # Init the confusion matrix for this bin
    start_conf = ConfusionMatrix(0, 0, 0, 0)
    bound_conf = ConfusionMatrix(0, 0, 0, 0)

    # 1  - Ground truth for bin file
    gnd_truth = lief_gnd_truth(bin_path.resolve())
    gnd_matrix = np.concatenate(
        (gnd_truth.func_addrs.T.reshape(-1, 1), gnd_truth.func_lens.T.reshape(-1, 1)),
        axis=1,
    )

    # 2 - Find the npz with the ida funcs and addrs, chop of functions that
    #     are out-of-bounds of the lief functions (these are functions that are
    #       likely outside of the .text section)
    ida_funcs = load_ida_prediction(result_path)

    # 4 - Mask the array so we only include bytes in .text
    mask_max = ida_funcs[:, 0] <= np.max(gnd_truth.func_addrs)
    ida_funcs = ida_funcs[mask_max]

    mask_min = ida_funcs[:, 0] >= np.min(gnd_truth.func_addrs)
    filt_ida_funcs = ida_funcs[mask_min]

    # 3 - Compare the two lists
    # Get all the start addrs that are in both, in ida only, in gnd_trush only
    start_conf.tp = len(np.intersect1d(gnd_matrix[:, 0], filt_ida_funcs[:, 0]))
    start_conf.fp = len(np.setdiff1d(filt_ida_funcs[:, 0], gnd_matrix[:, 0]))
    start_conf.fn = len(np.setdiff1d(gnd_matrix[:, 0], filt_ida_funcs[:, 0]))

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

    bound_conf.tp = np.count_nonzero(
        np.all(np.isin(filt_ida_funcs, gnd_matrix), axis=1)
    )
    bound_conf.fp = filt_ida_funcs.shape[0] - bound_conf.tp
    bound_conf.fn = gnd_matrix.shape[0] - bound_conf.tp

    # Observe the tp func starts but the incorrect lengths
    missed_ends = func_incorrect_lens([], [], [])

    # Observe the fp where the start was fp and the end was wrogn
    missed_both = completely_missed_fp([], [], [], [])

    # Check to see how many false negative there were
    for i, row in enumerate(gnd_matrix):

        # If the boudns are exauasted these are all false negatives
        if i >= filt_ida_funcs.shape[0]:
            bound_conf.fn += 1
            continue

        if row[0] == filt_ida_funcs[i][0] and row[1] != filt_ida_funcs[i][1]:
            missed_ends.tp_start_addrs.append(row[0])
            missed_ends.incorrect_lens.append(filt_ida_funcs[i][1])
            missed_ends.correct_lens.append(row[1])
        if row[0] != filt_ida_funcs[i][0] and row[1] != filt_ida_funcs[i][1]:
            missed_both.start_addrs.append(row[0])
            missed_both.lengths.append(filt_ida_funcs[i][1])

        # If gnd matrix has any rows that aren't in ida funcs then its a false neg
        if not np.any(np.all(row == filt_ida_funcs, axis=1)):
            bound_conf.fn += 1

    ends_missed_length = [
        y - x for (x, y) in zip(missed_ends.correct_lens, missed_ends.incorrect_lens)
    ]
    total_missed_by = sum(ends_missed_length)

    print(f"Function start confusion matrix: {start_conf}")
    print(f"Function bound confusion matrix: {bound_conf}")

    print(f"Total miss length {total_missed_by}")
    avg_missed_ends = total_missed_by / len(missed_ends.incorrect_lens)
    print(f"Avg missed {avg_missed_ends}")
    print(f"Mean: {np.mean(ends_missed_length)}")
    print(f"Median: {np.median(ends_missed_length)}")
    print(f"Mode: {stats.mode(ends_missed_length)}")

    make_simple_plot(
        missed_ends.tp_start_addrs,
        ends_missed_length,
        "TP function start addresses",
        "Distance between the FP end nearest correct end from gnd truth",
        f"Distance between predicted functions ends and correct function ends vs TP start addres for binary {bin_path.name}",
        Path(f"{bin_path.name}_ends_plot.png"),
    )

    make_simple_pdf(
        ends_missed_length,
        "Distribution of FP distance from TP",
        "Frequency",
        f"PDF of FP delta TP for {bin_path.name}",
        Path(f"{bin_path.name}_ends_pdf.png"),
    )

    return


def make_simple_plot(x, y, label_x: str, label_y: str, title: str, save_path: Path):
    """
    Super simple scatter plot the plotting the missed functions
    """

    x = np.array(x)
    y = np.array(y)

    plt.scatter(x, y)
    plt.xlabel(label_x)
    plt.xlabel(label_x)
    plt.title(title)
    plt.grid(True)
    plt.savefig(save_path)
    return


def make_simple_pdf(y, label_x: str, label_y: str, title: str, save_path: Path):
    """
    Make a simple probability density graph
    """

    y = np.array(y)

    # Define the bin size
    bin_size = 32
    num_bins = int(np.ceil((max(y) - min(y)) / bin_size))

    # Calculate the histogram
    # hist, bins = np.histogram(y, bins=np.arange(min(y), max(y) + bin_size, bin_size))
    freqs, bin_edges = np.histogram(y, bins=num_bins)
    print(f"Frequeness: {freqs}")
    print(f"Bin Edges: {bin_edges}")

    # Plot the histogram
    plt.bar(bin_edges[:-1], freqs, width=bin_size, align="center")

    # Set the x-axis to have its center at 0
    plt.xlim(-2000, 128)  # max(abs(y))-.8*max(abs(y)))
    plt.ylim(0, sorted(freqs)[-3] + 0.1 * (sorted(freqs)[-3]))

    # Add labels and title
    plt.xlabel(label_x)
    plt.ylabel(label_y)
    plt.title("PDF graph")

    # print(f"Total miss length {total_missed_by}")
    # avg_missed_ends = total_missed_by / len(tot_missed_ends.incorrect_lens)
    # print(f"Avg missed {avg_missed_ends}")
    # print(f"Mean: {np.mean(ends_missed_length)}")
    # print(f"Median: {np.median(ends_missed_length)}")
    # print(f"Mode: {stats.mode(ends_missed_length)}")

    # freqs, bin_edges = np.histogram(ends_missed_length, bins=4)

    # Define bin size
    # bin_size = 8

    # x = np.array(x)
    # y = np.array(y)
    #
    ## Calculate the range of y values
    # y_min = np.min(y)
    # y_max = np.max(y)
    #
    ## Calculate the number of bins
    # num_bins = int(np.ceil((y_max - y_min) / bin_size))
    #
    ## Create bins
    # bins = np.arange(y_min, y_max , num_bins+1 )
    #
    ## Plot histogram
    # plt.hist(y, bins=bins, density=True, edgecolor='black', alpha=0.7)
    #
    ## Add labels and title
    # plt.xlabel('Y Values')
    # plt.ylabel('Frequency')
    # plt.title('Distribution of Y Values')

    # Show plot
    plt.savefig(save_path)

    return


def score_worker(bins_and_preds: List[tuple[Path, Path]]):
    """
    Worker processes to score a file
    """
    # Save the results here
    total_start_conf = ConfusionMatrix(0, 0, 0, 0)
    total_bound_conf = ConfusionMatrix(0, 0, 0, 0)
    total_end_conf = ConfusionMatrix(0, 0, 0, 0)

    for bin, pred_npy in bins_and_preds:
        # 1. Load gnd truth
        gnd_info, gnd = gnd_truth_start_plus_len(bin)

        # 2. Load prediction
        pred = load_ida_prediction(pred_npy)

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


# TODO: This has different results than old_read_results
@app.command()
def read_results(
    result_dir: Annotated[str, typer.Argument(callback=iterable_path_deep_callback)],
    bin_dir: Annotated[str, typer.Argument(callback=iterable_path_shallow_callback)],
    workers: Annotated[int, typer.Option()] = 24,
    verbose: Annotated[bool, typer.Option()] = False,
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
    index = 0
    keys = list(matching_files.keys())

    # Divy up the work.
    for i in range(workers):
        # The last worker need to take extra bins if there was a remainder
        bins = keys[index::] if i == workers - 1 else keys[index : index + chunk_size]
        # if i == workers-1:
        #    bins =  keys[cur_index::]
        # else:
        #    bins =  keys[cur_index:cur_index+chunk_size]

        # Add a list of tuple: [(bin, prediction), (bin,prediction), ...]
        chunks.append([(bin, matching_files[bin]) for bin in bins])
        index += chunk_size

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

    print("Total Metrics")
    print(f"Starts: {total_start_conf}")
    print(f"Starts: {calc_metrics(total_start_conf)}")
    print(f"Ends: {total_end_conf}")
    print(f"Ends: {calc_metrics(total_end_conf)}")
    print(f"Bounds: {total_bound_conf}")
    print(f"Bounds: {calc_metrics(total_bound_conf)}")
    return


@app.command()
def analyze_distances_cmd(
    results: Annotated[str, typer.Argument(callback=iterable_path_deep_callback)],
    bins: Annotated[str, typer.Argument(callback=iterable_path_shallow_callback)],
):
    """
    Analyze the distance missed
    """

    matching_files = {}
    results = [x for x in results if x.is_file() and "result.npz" in x.name]

    for bin_path in bins:
        matching = False
        for res_file in results:
            if res_file.name.replace("_result.npz", "") == bin_path.name:
                matching_files[bin_path] = res_file
                matching = True
        if not matching:
            raise typer.Abort("Some bins dont have matching result files")

    print(matching_files)

    tot_ends = []
    for bin, prediction in alive_it(matching_files.items()):
        pred_npy = load_ida_prediction(Path(prediction).resolve())
        pred_matrix = np.concatenate(
            (
                pred_npy[:, 0].reshape(-1, 1),
                (pred_npy[:, 0] + pred_npy[:, 1]).reshape(-1, 1),
            ),
            axis=1,
        )

        gnd_truth = lief_gnd_truth(bin)
        # NOTICE: IMPORTANT... xda seems to the first byte outside of the function
        #               as the end of the function
        lengths_adjusted = gnd_truth.func_lens
        ends = gnd_truth.func_addrs + lengths_adjusted
        gnd_matrix = np.concatenate(
            (gnd_truth.func_addrs.T.reshape(-1, 1), ends.T.reshape(-1, 1)), axis=1
        )

        starts_delta, ends_delta, bounds = analyze_distances(gnd_matrix, pred_matrix)
        tot_ends.extend(list(ends_delta))
        # The pdf now bins the misses, say bin size of 4, center at 0

    tot_ends = np.array(tot_ends)
    ends_delta = tot_ends[(tot_ends >= -2000) & (tot_ends <= 2000)]
    # Define the bin size
    bin_size = 32
    num_bins = int(np.ceil((np.max(ends_delta) - np.min(ends_delta)) / bin_size))

    # Calculate the histogram
    # hist, bins = np.histogram(y, bins=np.arange(min(y), max(y) + bin_size, bin_size))

    freqs, bin_edges = np.histogram(ends_delta, bins=num_bins)

    print(f"max freqs: {np.max(freqs)}")
    print(f"sum freqs: {np.sum(freqs)}")
    print(freqs)
    print(bin_edges)

    # need to make a PDF
    # percent predictions in bin = freq of bin / total predictions
    freqs = freqs / np.sum(freqs)

    bin_edges = np.arange(start=np.min(ends_delta), stop=np.max(ends_delta) + bin_size)
    # print(f"Frequeness: {freqs}")
    # print(f"Bin Edges: {bin_edges}")

    # Plot the histogram
    # plt.bar(bin_edges[:-1], freqs, width=bin_size, align='center')
    # plt.hist(ends_delta, bins=bin_edges, color='red', edgecolor='black')
    plt.hist(freqs, bins=bin_edges, color="red", edgecolor="black")

    # Set the x-axis to have its center at 0
    plt.xlim(-2000, 2000)  # max(abs(y))-.8*max(abs(y)))
    # plt.ylim(0, sorted(freqs)[-3] + .05*(sorted(freqs)[-1]))
    # plt.ylim(0, 5000)

    # Add labels and title
    plt.xlabel("Binned missed distance")
    plt.ylabel("Frequency")
    plt.title("Ends Delta PDF")
    print("Saving...")
    savepath = Path(f"{bin.name}_ends_pdf")
    plt.savefig(savepath)
    print(f"Saved to {savepath.resolve()}...")
    return


if __name__ == "__main__":
    app()
