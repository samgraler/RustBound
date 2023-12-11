"""
This file is going to be responsible for saving the 
analyzed files


Similar to cargo_picky go_picky I will make a dir at 
the home directory:

.analyzed_files
|
| PE x86
|   | go 
|   | | <compilers used>
|   | |  | 
|   | |  | <filename_optlvl_strippedOrNot.o>
|   | rust
|   | c 
|
|
| PE x86_64
| ELF x86
| ELF x86_64
|
"""

import pyarrow as pa
import pyarrow.parquet as pq
from dataclasses import fields

from pathlib import Path
from typing import Union, Generator
import pandas as pd 
import numpy as np
import inspect

from .ripbin_exceptions import RipbinRegistryError, RipbinAnalysisError, RipbinDbError, AnalysisExistsError

from .analyzer_types import Compiler, RustcOptimization, ProgLang, FileType, GoOptimization, AnalysisType


DB_PATH = Path("~/.ripbin_db/").expanduser().resolve()
DB_REGISTRY = DB_PATH.joinpath('ripbin_registry.csv')

def is_db_formated()->bool:
    """
    Im writing this after writing init because if init 
    is called and raises the Excpetion because ~/.ripbin_db
    does exist, it may be useful to check the whole structure
    """

    db = DB_PATH

    # Root dir for each lang type
    root_dirs = ["c_files", "rust_files", "go_files"]

    # Executable type
    exe_types = [str(x).lower() for x in FileType.__members__]

    # Some compilers only work for rust and c and go, 
    # and some can cross compile and some cant 
    
    # To make is easy on me, each exe_type directory 
    # will have a directory for all the compilers, 
    # and the compilers that don't make sense will have
    # empty direcotries
    compilers =  [str(x).lower() for x in Compiler.__members__]

    for root in root_dirs:
        for exe_type in exe_types:
            for comp in compilers:
                new_path = db.joinpath(f"{root}/{exe_type}/{comp}")
                if not new_path.exists():
                    return False
    return True

def init_db(force = False):

    # Rename db so I have to type less :)
    db = DB_PATH

    # If the path exists do not override it 
    if db.exists() and not force:
        raise RipbinDbError("Db may exist...")

    # Root dir for each lang type
    root_dirs = ["c_files", "rust_files", "go_files"]

    # Executable type
    exe_types = [str(x).lower() for x in FileType.__members__]

    # Some compilers only work for rust and c and go, 
    # and some can cross compile and some cant 
    
    # To make is easy on me, each exe_type directory 
    # will have a directory for all the compilers, 
    # and the compilers that don't make sense will have
    # empty direcotries
    compilers =  [str(x).lower() for x in Compiler.__members__]

    # Reminder the tree will go:
    # 
    # <bin>_file [c, go, or rust]
    # |
    # | ELFx86
    # | | rustc
    # | | | <bin_name>_optimizationlvl_[stripped,nonstripped].csv
    # | | clang
    # | | msvc
    # | | icc
    # | | gcc
    # | | go
    # |
    # | ELFx86-64
    # | | ...
    # |
    # | PEx86
    # | | ...
    # |
    # | PEx86-64
    # | | ...
    for root in root_dirs:
        for exe_type in exe_types:
            for comp in compilers:
                new_path = db.joinpath(f"{root}/{exe_type}/{comp}")
                new_path.mkdir(exist_ok=True,parents=True)
    return 

def write_generator_to_parquet(generator, output_path):
    schema = pa.schema([pa.field("data", pa.float64())])  # Adjust the schema according to your numpy array structure

    with pq.ParquetWriter(output_path, schema) as writer:
        for array in generator:
            table = pa.Table.from_arrays([pa.array(array)], schema=schema)
            writer.write_table(table)


def db_save_analysis( 
            binary_path: Path,
            data: Union[pd.DataFrame,np.ndarray, 
                        Generator[np.ndarray,None,None]], 
            progLang: ProgLang, 
            compiler: Compiler,
            fileType: FileType,
            opt_lvl: Union[RustcOptimization, 
                    GoOptimization],
            is_stripped,
            overwrite_existing=False,
            save_bin = True)->None:
    """
        Save the analyzed file to the db.
        The standard for this is saving a pandas dataframe 
        to the file

        This function also trusts the structure of the dataframe...
        something that I may change 
    """
    #TODO: Should I trust the structure of the numpy array

    
    bin_toplvl_name = binary_path.name

    descriptive_name = "_".join([bin_toplvl_name,opt_lvl.value, 
                                 "STRIPPED" if is_stripped else "NOTSTRIPPED"])

    descriptive_dir = Path(f"{progLang.value}_files/{fileType.value}/{compiler.value}")

    analysis_name = "{}_ANALYSIS.npz".format(descriptive_name)

    # Make the path to the analysis file
    analysis_file =  DB_PATH / descriptive_dir / Path(analysis_name)
    analyss_file = analysis_file.resolve()

    bin_file = DB_PATH / descriptive_dir / Path(descriptive_name)
    bin_file = bin_file.resolve()

    if analysis_file.exists() and not overwrite_existing:
        st =  "Analysis file {} exists".format(analysis_file)
        raise AnalysisExistsError(st)

    if isinstance(data, pd.DataFrame):
        # Save the numpy data from df to parquet 
        data = data.to_numpy()
    elif isinstance(data, np.ndarray):
        # Save numpy data to npz
        data = data
    elif inspect.isgenerator(data):
        # Load the lines from generator into numpy array 
        #write_generator_to_parquet(data,analysis_file)
        data = np.array(list(data))
    else:
        raise TypeError("Data is of unknown type")

    try:
        np.savez_compressed(analysis_file, data=data)
    except Exception as e:
        st = f"Np save error: {e}"
        raise Exception(st)

    if save_bin:
        with open(binary_path, 'rb') as f:
            bin_data = f.read()
        with open(bin_file, 'wb') as f:
            f.write(bin_data)
    return

def get_registry():
    '''Return dataframe of Registry'''
    if not DB_REGISTRY.exists():
        raise Exception("Error: registry already exists")
    return pd.read_csv(DB_REGISTRY, index_col = False)



    return

def register_analysis(
        opt_level: str,
        prog_lang: str,
        compiler_name: str,
        compiler_version: str,
        file_type: str,
        is_stripped: bool,
        stripped_level: str,
        os: str,
        arch: str,
        analysis_type: AnalysisType,
        path_from_db_root: Path,
    ):
    '''
        Add a file to the registry 

        NOTICE: This must be done _after_ the file has been saved
                as its path is asserted
    '''

    if not path_from_db_root.resolve().exists():
        raise Exception('Path does not exist')


    return


def init_registry():
    '''
        Init the registry
    '''
    
    # No file should be saved to db that isn't in the registry

    # Registry will be a dataframe

    # Ripbin is meant to act as a backend for binaries that have 
    # many known things aabout them.
    # 
    # As well as a backend for binaries that little is known about them 
    # 
    # For a 'known' binary not every little thing has to be know 
    # 
    # Therefore from a storage point of view I will treat both as the 
    # same entity (considered making a registry for known and unknown 
    # files, but that would've been very strict for what exectly is 
    # known about a known file). 
    # 

    # Columns will be:
    # 
    # 1. binary_name 
    # 2. opt_level 
    # 3. prog_lang 
    # 4. compiler_name 
    # 5. compiler_version 
    # 6. fileType
    # 7. is_striped
    # 8. further_strip_info [RustcStrip, ...]
    # 9. os 
    # 10. arch 
    # 12. analysisType
    # 13. path relative to db root to analysis


    columns = [
        'binary_name',
        'opt_level',
        'prog_lang',
        'compiler_name',
        'compiler_version',
        'file_type',
        'is_stripped',
        'stripped_level',
        'os',
        'arch',
        'path_from_db_root',
        'analysis_type'
    ]

    # Init the df
    registry_df = pd.DataFrame(columns=columns)

    if not DB_REGISTRY.exists():
        registry_df.to_csv(DB_REGISTRY, index=False)
    else:
        raise RipbinRegistryError("Error: registry already exists")
    return



if __name__ == "__main__":
    from analyzer.binary_analyzer import generate_minimal_labeled_features 

    if not is_db_formated():
        init_db()
        print("Init db")

    
    f = Path("exa")

    gen = generate_minimal_labeled_features(f)

    #db_save_analysis(f,gen, ProgLang.RUST, Compiler.RUSTC, FileType.ELF_X86_64, RustcOptimization.O1, False)



