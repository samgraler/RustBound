
from pathlib import Path
import subprocess
import shutil
import pandas as pd
from typing import Union
from enum import Enum


CRATES_IO_DIR = Path("~/.crates_io/").expanduser().resolve()
CLONED_CRATES_DIR = CRATES_IO_DIR / "cloned_crates/"
CRATES_IO_REG = CRATES_IO_DIR / "cratesio_reg.csv"


class LocalCratesIO(Enum):
    CRATES_DIR = str(CLONED_CRATES_DIR.resolve())

    

def init_crates_io():
    '''
    Init directories
    '''

    dirs = [CRATES_IO_DIR, CLONED_CRATES_DIR]
    files =  [CRATES_IO_REG]

    for dir in dirs:
        if not dir.exists():
            dir.mkdir()

    if not CRATES_IO_REG.exists():
        pull_registry()


def wget_reg():
    
    # Curl command that gets the official creates dump
    cmd = f"cd {CRATES_IO_DIR} && wget https://static.crates.io/db-dump.tar.gz"
    # Try to curl the index
    try: 
        output = subprocess.check_output(cmd,shell=True)
    except Exception as e:
        print(f"Error pulling the index: {e}")
        exit(1)
    return

def curl_reg():

    # file to download the tar file into
    tmp_tar_data = CRATES_IO_DIR / "db-dump.tar.gz"

    # Curl command that gets the official creates dump
    cmd = f"curl -o {tmp_tar_data.resolve()} https://static.crates.io/db-dump.tar.gz"

    print(f"COMMOND: {cmd}")
    # Try to curl the index
    try: 
        output = subprocess.check_output(cmd,shell=True)
    except Exception as e:
        print(f"Error pulling the index: {e}")
        exit(1)
    return

def pull_registry():
    '''
    Curl the crates registry and untar data
    '''

    # Temp files that are crating from pulling then extracting 
    # the tar file that holds the registry
    tmp_tar_data = CRATES_IO_DIR / "db-dump.tar.gz"
    tmp_tar_data = tmp_tar_data.resolve()
    tmp_untar_dir = CRATES_IO_DIR / "tmp_untar_dir/"
    tmp_untar_dir = tmp_untar_dir.resolve()

    # If the tar file exists already remove it 
    if tmp_tar_data.exists():
        tmp_tar_data.unlink()

    # Make and clear the directory that the tar data is going to be 
    # extracted to 
    if tmp_untar_dir.exists():
        shutil.rmtree(tmp_untar_dir)
    tmp_untar_dir.mkdir()


    # TODO: Curl reg used to work but now doesnt
    wget_reg()

    cmd = f"tar -xzf {tmp_tar_data} -C {tmp_untar_dir} --strip-components=1"

    # Try to untar the file 
    try: 
        output = subprocess.check_output(cmd,shell=True)
    except Exception as e:
        print(f"Error extracting index {e}")
        exit(1)


    # even more tempry files that are created from the untaring
    crates_path = tmp_untar_dir / "data"
    crates_path = crates_path / "crates.csv"
    cmd = f"cp {crates_path.resolve()} {CRATES_IO_REG}"

    # Try to move the csv file that contains all cargo crates
    # to the new location
    try:
        output = subprocess.check_output(cmd,shell=True)
    except Exception as e:
        print(f"Error moving index {e}")
    return



def crates_io_df()->pd.DataFrame:
    '''
    Get the df of crates
    '''
    # At this point EXTRACTED_TAR_DIR exists
    if not CRATES_IO_REG.exists():
        print(f"Error, the file {CRATES_IO_REG} should exist but doesn't")

    # Get a dataframe of the crates
    df = pd.read_csv(CRATES_IO_REG.resolve())

    # The repositories are in the 'repository' column
    return df


def del_crate(crate: Union[list[str], str],
                dir=CLONED_CRATES_DIR )-> None:

    if isinstance(crate, str):
        crate = [crate]

    for single_crate in crate:
        if (crate_path:=CLONED_CRATES_DIR.joinpath(single_crate)).exists():
            shutil.rmtree(crate_path)
    return

def clone_crate(crate: Union[list[str], str],
                exist_ok=False, dir=CLONED_CRATES_DIR, debug=False)-> None:
    """
        Function to clone cargo crates
    """


    if isinstance(crate, str):
        crate = [crate]

    for single_crate in crate:
        if (crate_path:=CLONED_CRATES_DIR.joinpath(single_crate)).exists() and not exist_ok:
            print(f"Crate {single_crate} alreadt exists at {crate_path}")
            continue
        cmd = f"cargo clone {single_crate} -- {dir.resolve()}/"

        try:
            if debug:
                output = subprocess.check_output(cmd,shell=True)
            else:
                output = subprocess.check_output(cmd,shell=True,
                                            stderr=subprocess.DEVNULL)
        except Exception as e:
            raise Exception(f"Crate pull error {e}")


def clone_crates(crate_names: pd.DataFrame, stop_on_fail=False, 
                 exist_ok:bool=False, dir=CLONED_CRATES_DIR)-> None:
    ''' Clone the passed crates '''

    finished_crates = []
    for crate in list(crate_names.name):
        try:
            clone_crate(crate,exist_ok,dir)
            finished_crates.append(crate)
        except Exception as e:
            if stop_on_fail:
                raise Exception(f"Crate {crate} failed: {e}")


# TODO: This is a hack to see if a crate is a binary 
#       there should be a better way
def is_remote_crate_exe(crate: str)-> bool:
    '''
    Attempt to install the crate, if it succedes 
    then the crate is a binary, uninstall after
    '''

    cmd = f"cargo -q install {crate}"

    try:
        output = subprocess.call(cmd,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
    except Exception as e:
        print(e)
        return False

    cmd = f"cargo uninstall {crate}"

    try:
        output = subprocess.call(cmd,
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"Error uninstall crate {crate}: {e}")
    return True




