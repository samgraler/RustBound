import json
import math
import multiprocessing
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from multiprocessing import Pool
from pathlib import Path
from typing import List

import lief
import typer
from alive_progress import alive_bar, alive_it
from cli_utils import get_enum_type, opt_lvl_callback
from rich import print
from rich.console import Console
from rich.progress import track
from rich.table import Table
from typing_extensions import Annotated

from ripkit.cargo_picky import (CrateBuildException, LocalCratesIO,
                                RustcOptimization, RustcStripFlags,
                                RustcTarget, build_crate, gen_cargo_build_cmd,
                                gen_cross_build_cmd, get_target_productions,
                                is_executable)
from ripkit.ripbin import (CompileTimeAttacks, RustFileBundle, calculate_md5,
                           ripbin_init, stash_bin)

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)

CPU_COUNT = multiprocessing.cpu_count()
CPU_COUNT_75 = math.floor(CPU_COUNT * 0.75)


def build_helper(args):
    crate = args[0]
    opt = args[1]
    target = args[2]
    overwrite_existing = args[3]
    verbose = args[4]
    podman = args[5]

    strip = RustcStripFlags.NOSTRIP
    use_cargo = False

    # Build the crate
    try:
        build_crate(crate, opt, target, strip, use_cargo=use_cargo, force_podman=podman)
    except CrateBuildException as e:
        print(f"[bold red][FAILED][/bold red] Crate {crate} failed to build")

    print(f"[bold green][BUILT][/bold green] Crate {crate} built")

    # Need this to get the build command
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info, this is NOT used
    # to actually execute a build command
    if use_cargo:
        build_cmd = gen_cargo_build_cmd(
            crate_path, target, strip, opt
        )
    else:
        build_cmd = gen_cross_build_cmd(
            crate_path, target, strip, opt, force_podman=podman
        )
    # Get files of interest from the crate at the target <target>
    files_of_interest = [
        x for x in get_target_productions(crate, target) if is_executable(x)
    ]

    if files_of_interest == []:
        print(
            f"[bold yellow][BORING][/bold yellow] Crate {crate} had no executable production"
        )
        if verbose:
            print(
                f" [bold yellow][VERBOSE][/bold yellow] Crate {crate} cmd: {build_cmd}"
            )
        return 99

    print(f"[bold green][SUCCESS][/bold green]Crate {crate}")

    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    filetype = ""

    # Create the file info
    info = RustFileBundle(
        binary.name, binHash, target.value, opt.value, binary.name, "", build_cmd
    )

    try:
        # Save analysis
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
    """
    Build and stash create in ripbin db
    """

    # Build the crate
    build_crate(crate, opt, target, strip, use_cargo=use_cargo)

    # Need this to get the build command
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info, this is NOT used
    # to actually execute a build command
    if use_cargo:
        build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)
    else:
        build_cmd = gen_cross_build_cmd(crate_path, target, strip, opt)

    # Get files of interest from the crate at the target <target>
    files_of_interest = [
        x for x in get_target_productions(crate, target) if is_executable(x)
    ]

    if files_of_interest == []:
        print(
            f"[bold yellow][BORING][/bold yellow] Crate {crate} had no executable production"
        )
        # TODO: in the crates_io cache which cloned pkgs don't build any
        #       files of interest so they are not rebuilt
        return 99

    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    # Create the file info
    info = RustFileBundle(
        binary.name,
        binHash,
        target.value,
        opt.value,
        binary.name,
        "",
        build_cmd,
    )

    try:
        # Save analysis
        stash_bin(binary, info, overwrite_existing)
    except Exception as e:
        print(f"Exception {e} in crate {crate}")

    return


def get_bins(
    target: RustcTarget,
    optimization: RustcOptimization,
) -> List[Path]:
    """
    Get all binaries of the target
    """

    bins = []
    for parent in Path("~/.ripbin/ripped_bins/").expanduser().resolve().iterdir():
        info_file = parent / "info.json"
        try:
            with open(info_file, "r") as f:
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

        if info["optimization"] in optimization.value:
            bins.append(parent / info["binary_name"])

    return bins


@app.command()
def print_rust_targets():
    """
    Print the rust targets
    """
    cmd = shlex.split("rustc --print target-list")
    output = subprocess.run(cmd, capture_output=True, universal_newlines=True)
    res = output.stdout
    print(res)
    return


@app.command()
def init():
    '''
    Initialize the ripbin db
    '''

    ripbin_init()
    return


@app.command()
def build_stash_all(
    opt_lvl: Annotated[
        str, typer.Argument(help="The optimization level to compile for")
    ],
    target: Annotated[str, typer.Argument(help="crate target")],
    num_workers: Annotated[int, typer.Option(help="number of workers")] = CPU_COUNT_75,
    overwrite_existing: Annotated[
        bool, typer.Option(help="Overwrite existing binaries in the db")
    ] = False,
    verbose: Annotated[bool, typer.Option(help="Print verbose info")] = False,
    force_podman: Annotated[
        bool, typer.Option(help="Force the usage of podman for the Cross engine")
    ] = False,
):
    """
    Build the crates in crates io and stash into ripbin db
    """

    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return

    target_enum = get_enum_type(RustcTarget, target)

    # List of crate current installed that can be built
    crates_to_build = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
    ]

    # If we don't have to build all the crates, find the crates that
    # are already built with the specified optimization and arch
    # an dremovet that from the list of installed crates
    for parent in Path("~/.ripbin/ripped_bins/").expanduser().resolve().iterdir():
        info_file = parent / "info.json"
        info = {}
        try:
            with open(info_file, "r") as f:
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

        if (
            info["optimization"].upper() in opt_lvl
            and info["target"].upper() in target_enum.value.upper()
        ):
            # Remove this file from the installed crates list
            if (x := info["binary_name"]) in crates_to_build:
                crates_to_build.remove(x)

    # Build and analyze each crate
    args = []
    for crate in crates_to_build:
        args.append(
            (crate, opt, target_enum, overwrite_existing, verbose, force_podman)
        )
    print(f"Building {len(args)} crates!")

    with Pool(processes=num_workers) as pool:
        results = pool.map(build_helper, args)
    return


@app.command()
def seq_build_all_and_stash(
    opt_lvl: Annotated[str, typer.Argument(help="opt lvl to compile for")],
    target: Annotated[str, typer.Argument(help="crate target")],
    stop_on_fail: Annotated[
        bool, typer.Option(help="Stop all compilation when one crate fails")
    ] = False,
):
    """
    Sequentially build all the crates found in the local crates_io
    """
    # Opt lvl call back
    try:
        opt = opt_lvl_callback(opt_lvl)
    except Exception as e:
        print(e)
        return

    target_enum = get_enum_type(RustcTarget, target)

    # List of crate current installed that can be built
    crates_to_build = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
    ]

    # If we don't have to build all the crates, find the crates that
    # are already built with the specified optimization and arch
    # an dremovet that from the list of installed crates
    for parent in Path("~/.ripbin/ripped_bins/").expanduser().resolve().iterdir():
        info_file = parent / "info.json"
        info = {}
        try:
            with open(info_file, "r") as f:
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

        if (
            info["optimization"].upper() in opt_lvl
            and info["target"].upper() in target_enum.value.upper()
        ):
            # Remove this file from the installed crates list
            if (x := info["binary_name"]) in crates_to_build:
                crates_to_build.remove(x)

    success = 0
    # Build and analyze each crate
    #for crate in alive_it(crates_to_build):
    for crate in crates_to_build:
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
    output: Annotated[str, typer.Argument(help="Directory to save binaries to")],
    min_text_bytes: Annotated[
        int, typer.Option(help="Minimum number of bytes in a files .text section")
    ] = 0,
):
    """
    Export a dataset from the ripkit db
    """

    if output != "":
        out_dir = Path(output)
        if out_dir.exists():
            print("The output directory already exists, please remove it:!")
            return
        else:
            out_dir.mkdir()

    # Get a dictionary of all the binaries that are in the ripbin db
    target_enum = get_enum_type(RustcTarget, target)
    opt_enum = get_enum_type(RustcOptimization, opt)

    print(opt_enum)
    print(target_enum)

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
