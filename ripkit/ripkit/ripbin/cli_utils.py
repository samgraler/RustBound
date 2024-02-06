import typer 
from pathlib import Path
from typing import List


def new_file_super_careful_callback(inp_bin: str)->Path:
    '''
    Assert that nothing exists at the new file location
    '''
    if Path(inp_bin).exists():
        raise typer.BadParameter(f"Path {inp_bin} already exists")
    return Path(inp_bin)

def new_file_callback(inp_bin: str)->Path:
    '''
    Assert that the location for the new file does not exist as a 
    directory. This WILL overwrite existing files with the same name
    '''

    if Path(inp_bin).is_dir():
        raise typer.BadParameter(f"File {inp_bin} already exists and is a directory!")
    return Path(inp_bin)

def must_be_file_callback(inp_bin: str)->Path:
    '''
    Callback to guarentee a file exists
    '''
    if Path(inp_bin).is_file():
        return Path(inp_bin)
    raise typer.BadParameter("Must must a valid file")

def iterable_path_shallow_callback(inp_dir: str)->List[Path]:
    '''
    Callback for iterable paths 

    This is useful when a parameter can be a file or a directory of files
    '''
    inp_path = Path(inp_dir)

    if inp_path.is_file():
        return [inp_path]
    elif inp_path.is_dir():
        return list(x for x in inp_path.glob('*'))
    else: 
        raise typer.BadParameter("Must pass a file or directory path")


def iterable_path_deep_callback(inp_dir: str)->List[Path]:
    '''
    Callback for iterable paths 

    This is useful when a parameter can be a file or a directory of files
    '''
    inp_path = Path(inp_dir)

    if inp_path.is_file():
        return [inp_path]
    elif inp_path.is_dir():
        return [Path(x) for x in inp_path.rglob('*')]
    raise typer.BadParameter("Must pass a file or directory path")
