"""
db_cli.py

Provide CLI to clone and interact with locally cloned crates
"""

import typer
from art import text2art
from typing_extensions import Annotated
from alive_progress import alive_bar, alive_it
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import track
import shutil
from ripkit.cargo_picky import (
    init_crates_io,
)
from . import (
    clone_crate,
    crates_io_df,
    LocalCratesIO,
    is_remote_crate_exe,
)

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)


@app.command()
def init():
    """
    Initialize ripkit with rust data base,
    and register files
    """
    init_crates_io()
    return


@app.command()
def clone(
    crate: Annotated[str, typer.Argument()],
    update: Annotated[
        bool, typer.Option(help="Update the crate if its already cloned")
    ] = False,
):
    """
    Clone a remote crate from crates.io registry to the local db
    """

    clone_crate(crate, exist_ok=update)

    return


@app.command()
def show_cratesio(
    column: Annotated[str, typer.Option(help="Column name to show")] = "",
):
    """
    Show the head of crates io dataframe
    """

    # Get the df
    crates_df = crates_io_df()

    if column == "":
        print(crates_df.head())
    else:
        print(crates_df[column])
    print(crates_df.columns)


@app.command()
def list_cloned(
    no_styling: Annotated[bool, typer.Option()] = False,
):
    """
    List the locally cloned crates
    """

    # List of crate current installed
    installed_crates = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
    ]
    if no_styling:
        for crate in installed_crates:
            print(crate)
    else:
        table = Table(border_style="black")
        table.add_column("Binary")
        for crate in installed_crates:
            table.add_row(crate, style="red")
        console.print(table)
        print(f"Thats {len(installed_crates)} crates")


@app.command()
def is_crate_exe(crate: Annotated[str, typer.Argument(help="Name of crate")]):
    """
    See if a remote crate produces an executable
    """
    print(is_remote_crate_exe(crate))
    return


@app.command()
def clone_many_exe(
    number: Annotated[int, typer.Argument(help="Number of crates to clone")],
    stash_nonexe_name: Annotated[
        bool,
        typer.Option(help="Save nonexe crate names to skip this names in the future"),
    ] = True,
    verbose: Annotated[bool, typer.Option(help="Verbose")] = False,
    try_nonexe: Annotated[bool, typer.Option(help="Attempt to clone nonexe's")] = False,
):
    """
    Clone many new executable rust crates.By default only clone crates that
    look to produce executable binaries, so not libaries.
    """

    # Get the remote crate reg
    reg = crates_io_df()

    # File containing non-exe crate names
    nonexe_names = Path("~/.crates_io/nonexe_crate_names.txt").expanduser().resolve()

    # List of crate current installed
    installed_crates = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
    ]

    if not try_nonexe:
        nonexe_files = [x for x in open(nonexe_names).readlines()]
    else:
        nonexe_files = []

    # List of crate names
    crate_names = [
        x
        for x in reg["name"].tolist()
        if x not in installed_crates and x not in nonexe_files
    ]
    print("Finding uninstalled registry...")

    # With progress bar, enumerate over the registry
    cloned_count = 0
    with alive_bar(number) as bar:
        for i, crate in enumerate(crate_names):
            if i % 100 == 0:
                print(f"Searching... {i} crates so far")
            # See if the crate is exe before cloning
            if is_remote_crate_exe(crate):
                print(f"Cloning crate {crate}")
                try:
                    if verbose:
                        clone_crate(crate, debug=True)
                    else:
                        clone_crate(crate)

                    cloned_count += 1
                    bar()
                # TODO: Make a custom exception for this
                except Exception as e:
                    print(e)
            elif stash_nonexe_name:
                with open("~/.crates_io/nonexe_crate_names.txt", "a") as f:
                    f.write(f"{crate}\n")
            if cloned_count >= number:
                break


@app.command()
def clear_cloned():
    """
    Remove all the locally cloned crates
    """

    # TODO: I will trying to define all the paths in one file.
    #       in this case LocalCratesIO. I still like the idea
    #       of having the paths defined in one file, however
    #       this line could be implemented more elegantly
    crates = list(Path(LocalCratesIO.CRATES_DIR.value).glob("*"))

    print(f"Removing {len(crates)} crates")
    for crate in alive_it(crates):
        shutil.rmtree(crate)
    return


if __name__ == "__main__":
    banner = text2art("Ripkit-DB", "random")
    console.print(banner, highlight=False)
    app()
