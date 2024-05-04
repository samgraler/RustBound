from typing_extensions import Annotated
import math
from multiprocessing  import Pool
import multiprocessing
import lief
import shutil
import json
from alive_progress import alive_bar, alive_it
from rich.console import Console
import shlex
from rich.table import Table
from rich.progress import track
from rich import print
import subprocess
from pathlib import Path
import typer
from cli_utils import opt_lvl_callback, get_enum_type

from ripkit.cargo_picky import (
    gen_cargo_build_cmd,
    gen_cross_build_cmd,
    get_target_productions,
    is_executable,
    LocalCratesIO,
    build_crate,
    RustcStripFlags,
    RustcOptimization,
    RustcTarget,
    CrateBuildException,
)

from ripkit.ripbin import (
    stash_bin,
    save_analysis,
    calculate_md5,
    RustFileBundle,
    generate_minimal_labeled_features,
    AnalysisType,
    RustcOptimization,
)
from cli_utils import get_enum_type

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)

CPU_COUNT = multiprocessing.cpu_count()
CPU_COUNT_75 = math.floor(CPU_COUNT * .75)

def build_helper(args):

    crate = args[0]
    opt = args[1]
    target = args[2]
    overwrite_existing = args[3]

    strip=RustcStripFlags.NOSTRIP
    use_cargo=False

    # Build the crate
    try:
        build_crate(crate, opt, target, strip, use_cargo=use_cargo)
    except CrateBuildException as e:
        print(f"[bold red][FAILED][/bold red] Crate {crate} failed to build")

    # Need this to get the build command
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info, this is NOT used
    # to actually exectue a build command
    if use_cargo:
        build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)
    else:
        build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt)

    # Get files of interest from the crate at the target <target>
    files_of_interest = [
        x for x in get_target_productions(crate, target) if is_executable(x)
    ]

    if files_of_interest == []:
        print(f"[bold yellow][BORING][/bold yellow]Crate {crate} had no executable production")
        # TODO: in the crates_io cache which cloned pkgs don't build any
        #       files of interest so they are not rebuilt
        return 99

    print(f"[bold green][SUCCESS][/bold green]Crate {crate}")

    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    filetype = ""

    # Create the file info
    info = RustFileBundle(binary.name, binHash, target.value, filetype,
                          opt.value, binary.name, "", build_cmd)

    try:
        # Save analyiss
        stash_bin(binary, info, overwrite_existing=overwrite_existing)
    except Exception as e:
        print(f"Exception {e} in crate {crate}")

    return



def build_and_stash(
    crate,
    opt,
    target,
    strip=RustcStripFlags.NOSTRIP,
    use_cargo=False,
    overwrite_existing=False,
):
    '''
    Build and stash create in ripbin db
    '''

    # Build the crate
    build_crate(crate, opt, target, strip, use_cargo=use_cargo)

    # Need this to get the build command
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info, this is NOT used
    # to actually exectue a build command
    if use_cargo:
        build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)
    else:
        build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt)

    # Get files of interest from the crate at the target <target>
    files_of_interest = [
        x for x in get_target_productions(crate, target) if is_executable(x)
    ]

    if files_of_interest == []:
        print(f"[bold yellow][BORING][/bold yellow]Crate {crate} had no executable production")
        # TODO: in the crates_io cache which cloned pkgs don't build any
        #       files of interest so they are not rebuilt
        return 99

    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    # Create the file info
    info = RustFileBundle(binary.name, binHash, target.value, filetype,
                          opt.value, binary.name, "", build_cmd)

    try:
        # Save analyiss
        stash_bin(binary, info, overwrite_existing)
    except Exception as e:
        print(f"Exception {e} in crate {crate}")

    return


def build_analyze_crate(crate,
                        opt,
                        target,
                        filetype,
                        strip=RustcStripFlags.NOSTRIP,
                        use_cargo=True):
    '''
    Helper function to build then analyze the crate
    '''

    # Build the crate
    build_crate(crate, opt, target, strip, use_cargo=use_cargo)

    # Need this to get the build command
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info, this is NOT used
    # to actually exectue a build command
    if use_cargo:
        build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)
    else:
        build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt)

    # Get files of interest from the crate at the target <target>
    files_of_interest = [
        x for x in get_target_productions(crate, target) if is_executable(x)
    ]

    if files_of_interest == []:
        print(f"Crate {crate} had no build executable productions")
        # TODO: in the crates_io cache which cloned pkgs don't build any
        #       files of interest so they are not rebuilt
        return 99

    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    # Create the file info
    info = RustFileBundle(binary.name, binHash, target.value, filetype,
                          opt.value, binary.name, "", build_cmd)

    # Generate analysis
    data = generate_minimal_labeled_features(binary)

    try:
        # Save analyiss
        save_analysis(binary,
                      data,
                      AnalysisType.ONEHOT_PLUS_FUNC_LABELS,
                      info,
                      overwrite_existing=False)
    except Exception as e:
        print(f"Exception {e} in crate {crate}")

    return 0


def get_all_target_bins(target: RustcTarget):
    '''
    Get all binaries by the optimization and that are of target target
    '''
    bin_by_opt = {
        '0': [],
        '1': [],
        '2': [],
        '3': [],
        'z': [],
        's': [],
    }

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

        # Define the binary file name
        bin_file = parent / info['binary_name']
        opt = info['optimization']
        bin_target = info['target']

        if opt not in bin_by_opt.keys():
            bin_by_opt[opt] = []

        if target.value in bin_target:
            bin_by_opt[opt].append(bin_file.resolve())
    return bin_by_opt


def get_bins(
    target: RustcTarget,
    optimization: RustcOptimization,
):
    '''
    Get all binaries of the target
    '''

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

        # Define the binary file name
        bin_file = parent / info['binary_name']

        opt = info['optimization']

        if opt in RustcOptimization.value:
            bins.append(bin_file)
    return bins


def get_all_bins() -> dict:
    '''
    Get all the binaries by the optimization
    '''

    bin_by_opt = {
        '0': [],
        '1': [],
        '2': [],
        '3': [],
        'z': [],
        's': [],
    }

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

        # Define the binary file name
        bin_file = parent / info['binary_name']

        opt = info['optimization']

        if opt not in bin_by_opt.keys():
            bin_by_opt[opt] = []
        else:
            bin_by_opt[opt].append(bin_file.resolve())
    return bin_by_opt


@app.command()
def print_rust_targets():
    '''
    Print the rust targets
    '''

    cmd = shlex.split('rustc --print target-list')

    output = subprocess.run(cmd, capture_output=True, universal_newlines=True)
    res = output.stdout
    print(res)
    return

@app.command()
def build_stash_all(
    opt_lvl: Annotated[str, typer.Argument()],
    target: Annotated[str, typer.Argument(help="crate target")],
    num_workers: Annotated[int, typer.Option()] = CPU_COUNT_75,
    overwrite_existing: Annotated[bool, typer.Option()] = False,
):
    '''
    Build the crates in crates io and stash into ripbin db
    '''

    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return

    target_enum = get_enum_type(RustcTarget, target)

    # List of crate current installed that can be built
    crates_to_build = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
        if x.is_dir()
    ]

    # If we don't have to build all the crates, find the crates that
    # are already built with the specified optimization and arch
    # an dremovet that from the list of installed crates
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

        if info['optimization'].upper() in opt_lvl and \
            info['target'].upper() in target_enum.value.upper():
            # Remove this file from the installed crates list
            if (x := info['binary_name']) in crates_to_build:
                crates_to_build.remove(x)

    success = 0
    # Build and analyze each crate
    args = []

    for crate in alive_it(crates_to_build):
        args.append((crate,opt,target_enum,overwrite_existing))

    with Pool(processes=num_workers) as pool:
        results = pool.map(build_helper, args)
    return



@app.command()
def seq_build_all_and_stash(
    opt_lvl: Annotated[str, typer.Argument()],
    target: Annotated[str, typer.Argument(help="crate target")],
    stop_on_fail: Annotated[bool, typer.Option()] = False,
):
    '''
    Build the crates in crates io and stash into ripbin db
    '''

    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return

    target_enum = get_enum_type(RustcTarget, target)

    # List of crate current installed that can be built
    crates_to_build = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
        if x.is_dir()
    ]

    # If we don't have to build all the crates, find the crates that
    # are already built with the specified optimization and arch
    # an dremovet that from the list of installed crates
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

        if info['optimization'].upper() in opt_lvl and \
            info['target'].upper() in target_enum.value.upper():
            # Remove this file from the installed crates list
            if (x := info['binary_name']) in crates_to_build:
                crates_to_build.remove(x)

    success = 0
    # Build and analyze each crate
    for crate in alive_it(crates_to_build):
        res = 0
        try:
            res = build_and_stash(crate, opt, target_enum, use_cargo=False)
        except CrateBuildException as e:
            print(f"[bold red]Failed to build crate {crate}:: {e}[/bold red]")
            continue
        if res != 99:
            success += 1
            print(f"[bold green][SUCCESS][/bold green] crate {crate}")

    print(f"[bold green][SUCCESS] {success}")
    print(f"[bold red][FAILED] {len(crates_to_build)-success}")
    return


@app.command()
def export_dataset(
    target: Annotated[str, typer.Argument(help="Compilation Target")],
    opt: Annotated[str, typer.Argument(help="Opt Lvl of bin")],
    output: Annotated[str,
                      typer.Argument(help="Save the binaries to a directory")],
    min_text_bytes: Annotated[
        int,
        typer.Option(
            help="Minimum number of bytes in a files .text section")] = 2000,
):
    '''
    Export a dataset from the ripkit db
    '''

    if output != "":
        out_dir = Path(output)
        if out_dir.exists():
            print("The output directory already exists, please remove it:!")
            return

    # Get a dictionary of all the binaries that are in the ripbin db
    target_enum = get_enum_type(RustcTarget, target)
    opt_enum = get_enum_type(RustcOptimization, opt)
    bins = get_bins(target_enum, opt_enum)

    # For each optimization levels and its corresponding bin list:
    # If any binary names appears more than once drop it
    bins = list(set(bins))
    print("Finding binaries whose name occurs in opt lvls more than once...")

    # Iterate over the dictionary of opt_lvl : [bins]
    # where each list of bins has no duplicates
    cur_good_bins = []
    for bin in track(bins, description=f"Checking  bin sizes..."):

        # Parse the binary with lief
        parsed_bin = lief.parse(str(bin.resolve()))

        # Get the text section and the bytes themselse
        text_section = parsed_bin.get_section(".text")
        num_text_bytes = len(text_section.content)

        # Append a good binary to the list of current good
        # binaries
        if num_text_bytes >= min_text_bytes:
            cur_good_bins.append(bin)
    for bin in track(bins, description=f"Copying..."):
        dest_file = out_dir / bin.name
        shutil.copy(bin.resolve(), dest_file.resolve())
    return


if __name__ == "__main__":
    app()
