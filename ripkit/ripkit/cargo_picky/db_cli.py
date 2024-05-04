import typer
from art import text2art
from typing_extensions import Annotated
from alive_progress import alive_bar, alive_it
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import track
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
    '''
    Initialize ripkit with rust data base,
    and register files
    '''
    init_crates_io()
    return

@app.command()
def clone(
    crate: Annotated[str, typer.Argument()],
    update: Annotated[
        bool,
        typer.Option(help="Update the crate if its already cloned")] = False):

    clone_crate(crate, exist_ok=update)

    return

@app.command()
def show_cratesio(column: Annotated[str, typer.Option()] = '', ):
    '''
    Show the head of cratesw io dataframe
    '''

    # Get the df
    crates_df = crates_io_df()

    if column == '':
        print(crates_df.head())
    else:
        print(crates_df[column])
    print(crates_df.columns)

@app.command()
def list_cloned(
    no_styling: Annotated[bool, typer.Option()]=False,
    ):
    '''
    List the cloned crates
    '''

    # List of crate current installed
    installed_crates = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
        if x.is_dir()
    ]
    if no_styling:
        for crate in installed_crates:
            print(crate)
    else:
        table = Table(border_style='black')
        table.add_column('Binary')
        for crate in installed_crates:
            table.add_row(crate, style='red')
        console.print(table)
        print(f"Thats {len(installed_crates)} crates")


@app.command()
def is_crate_exe(crate: Annotated[str, typer.Argument()]):

    print(is_remote_crate_exe(crate))
    return




@app.command()
def clone_many_exe(number: Annotated[int, typer.Argument()],
                   verbose: Annotated[bool, typer.Option()] = False):
    '''
    Clone many new executable rust crates.
    '''

    # Get the remote crate reg
    reg = crates_io_df()

    # List of crate current installed
    installed_crates = [
        x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir()
        if x.is_dir()
    ]

    # List of crate names
    crate_names = [
        x for x in reg['name'].tolist() if x not in installed_crates
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
                except Exception as e:
                    print(e)
            if cloned_count >= number:
                break

if __name__ == "__main__":
    banner = text2art("Ripkit-DB", "random")
    console.print(banner, highlight=False)
    app()

