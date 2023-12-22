"""
This file is going to be responsible for saving the 
analyzed files


Similar to cargo_picky go_picky I will make a dir at 
the home directory:
"""

from dataclasses import fields
import hashlib
import shutil

from alive_progress import alive_it

from pathlib import Path
from typing import Union, Generator
import pandas as pd 
import numpy as np
import inspect
from enum import Enum
from typing import Type

from .ripbin_exceptions import RipbinRegistryError, RipbinAnalysisError, RipbinDbError, AnalysisExistsError

from .analyzer_types import Compiler, RustcOptimization, ProgLang, FileType, GoOptimization, AnalysisType, Coptimization


DB_PATH = Path("~/.ripbin/").expanduser().resolve()
RIPBIN_REG = DB_PATH.joinpath('ripped_bins_registry.csv')
RIPBIN_BINS = DB_PATH.joinpath('ripped_bins')


def init()->None:
    '''
    Init the ripbin db

    Default path is '~/.ripbin/'
    '''

    # Guard for case where db exists
    if DB_PATH.exists():
        raise RipbinDbError("~/.ripbin exists")

    # Make the db
    DB_PATH.mkdir()

    # Make the ripped bins path 
    ripped_bins_store = DB_PATH.joinpath('ripped_bins')
    ripped_bins_store.mkdir()

    # Init the registry
    _init_registry()

    # Now I have
    # 
    #  ~/.ripbin
    #       | ripped_bins_registry.csv
    #       | ripped_bins
    # 
    # :D 

    return

def _init_registry()->None:
    '''
    Initialize the ripbin registry

    '''

    if RIPBIN_REG.exists():
        raise RipbinDbError("Registry path exists")


    # Goal is to catalog binaries that we know, and 
    # don't know alot about. 
    # 
    # The categories that are satisfied for a binary to 
    # be considered to be completely known, as in I compiled 
    # the binary is:
    # i.  compiler
    # ii. program language 
    # iii. file type (PE, ELF, 64bit, 32bit)
    # iv. wether or not its stripped (and to 
    #       what degree)
    # v. target arch and os 
    # 
    # Knowing these, I believe I will be able to make a model 
    # to fill in decompilation holes that current 
    # decompilation engines miss
    # 
    # Some of these are not necessarily used as features in a 
    # model input vector, but are nice for comparing models 
    # performance to different binary types 
    # (ie PE vs ELF, very self expanaltory)
    # (ie rustc vs gccc, very different looking binaries)


    # Because some of these columns are 'flexible' (that made me 
    # throw up typing, rather everything be very static and 
    # functional") meaning can hold different values like"
    # "Oz" vs "RustcDebugStrip" "RustcFillStrip" "Strip" 
    # I need the types to all be strings 
    columns = [
        'package_path',
        'binary_name',
        'opt_level',
        'prog_lang',
        'compiler_name',
        'compiler_version',
        'file_type',
        'is_stripped',    # Two flags for stripped related things
        'stripped_level', # for easier quierying
        'os',
        'arch',
        'analysis_type',
        'analysis_path',
        'bin_hash', # This is a hash that will identify 
                    # the package
    ]

    # Init the df
    registry_df = pd.DataFrame(columns=columns)

    # Save empty registry file
    registry_df.to_csv(RIPBIN_REG,index=False)
    return

def calculate_md5(file_path, buffer_size=8192):
    md5_hash = hashlib.md5()

    with open(file_path, 'rb') as file:
        buffer = file.read(buffer_size)
        while buffer:
            md5_hash.update(buffer)
            buffer = file.read(buffer_size)

    return md5_hash.hexdigest()

def get_registry():
    '''Return dataframe of Registry'''
    if not RIPBIN_REG.exists():
        raise Exception("Error: registry already exists")
    return pd.read_csv(RIPBIN_REG, index_col = False)


def _check_registry_key_values():
    '''
        This function makes sure the 'package_path' 
        in all of the ripbin_db reg has the parent 
        path as ~/.ripbin/ripped_bins
    '''

    reg = get_registry()

    for path_name in reg['package_path']:
        if Path(path_name).resolve().parent.resolve() != RIPBIN_REG.resolve():
            raise RipbinDbError("Error in registry")
    return

def save_and_register_analysis(bin_path:Path, 
                  analysis_data: Union[pd.DataFrame,np.ndarray, 
                              Generator[np.ndarray,None,None],
                               Path], 
                  analysis_type: AnalysisType,
                  progLang: ProgLang, 
                  compiler: Compiler,
                  fileType: FileType,
                  opt_lvl: Union[RustcOptimization, 
                          GoOptimization,
                            Coptimization],
                  os: str="",
                  arch: str="",
                  stripped_level = None,
                  overwrite_existing=False,
                  copy_bin: bool = True,
                  compiler_version: str = "",
                  binHash = None)->None:
    '''
    Save the passed generated or list or array to 
    analysis file and register and register anaylsis
    '''

    if binHash is None:
        binHash = calculate_md5(bin_path)
    if stripped_level == None:
        is_stripped = False 
        stripped_level = "None"
    else :
        is_stripped = True
        stripped_level = stripped_level.value


    # See if there are any existing analysis files for a binary 
    # with the same hash. If so expect the binaries to be the 
    # same
    registered_bins = get_registry()
    common_analysis = registered_bins[registered_bins['bin_hash'] == binHash]

    if common_analysis.empty:
        # Need to make a pkg_dir for this binary
        pkg_path = RIPBIN_BINS.joinpath(f"{bin_path.name}_{str(binHash)}")
    else:

        # Else there's an existing binary with the same hash 
        # - For now I am going to assume that the current binary 
        # - and the one saved are an exact match
        pkg_path = Path(list(common_analysis['package_path'])[0])

        # The following is a check that should be redunant and 
        # removed in the future 
        if pkg_path.parent.name != "ripped_bins":
            raise Exception("Poorly named package pagth")
        print("COMMON MD5 sum {} and {}:: {}".format(pkg_path, bin_path,binHash))

    if not pkg_path.exists():
        pkg_path.mkdir()

        
    analysis_file = pkg_path.joinpath(f"{bin_path.name}_{analysis_type.value}.npz")
    if not overwrite_existing and Path(analysis_file).exists():
        # Dont overwrite the existing file is it is there
        return

    reg_row_dict = {
        'package_path'      : str(pkg_path.resolve()),
        'binary_name'       : str(bin_path.name),
        'opt_level'         : str(opt_lvl.value),
        'prog_lang'         : str(progLang.value),
        'compiler_name'     : str(compiler.value),
        'compiler_version'  : str(compiler_version),
        'file_type'         : str(fileType.value),
        'is_stripped'       : str(is_stripped),
        'stripped_level'    : str(stripped_level),
        'os'                : str(os),
        'arch'              : str(arch),
        'analysis_type'     : str(analysis_type.value),
        'analysis_path'     : str(analysis_file.resolve()),
        'bin_hash'          : binHash,
    }

    reg_row_dict = {k : [v] for k,v in reg_row_dict.items()}

    row_df = pd.DataFrame.from_dict(reg_row_dict)
    # Create a new DataFrame from the dictionary and concatenate with the existing DataFrame
    new_reg = pd.concat([registered_bins, row_df], ignore_index=True)



    # Handle the different instances of analysis_data 
    if isinstance(analysis_data, pd.DataFrame):
        analysis_data = analysis_data.to_numpy()
    elif isinstance(analysis_data, np.ndarray):
        # Save numpy analysis_data to npz
        analysis_data = analysis_data
    elif inspect.isgenerator(analysis_data):
        # Load the lines from generator into numpy array 
        #write_generator_to_parquet(analysis_data,analysis_file)
        analysis_data = np.array(list(analysis_data))
    elif isinstance(analysis_data, Path):
        # Assert it's an .npz file and save 
        if ".npz" not in analysis_data.name:
            raise TypeError("Path object must be .npz file")

        # Copy the data, which in this case is another 
        # file to the destination, which is analysis file
        shutil.copy2(analysis_data, analysis_file)

    else:
        raise TypeError("Data is of unknown type")

    if not isinstance(analysis_data, Path):
        try:
            np.savez_compressed(analysis_file, data=analysis_data)
        except Exception as e:
            st = f"Np save error: {e}"
            raise Exception(st)

    # Update the reg once the file is successfully saved
    new_reg.to_csv(RIPBIN_REG,index=False)

    if copy_bin:
        bin_file = pkg_path.joinpath(bin_path.name).resolve()
        with open(bin_path, 'rb') as f:
            bin_data = f.read()
        with open(bin_file, 'wb') as f:
            f.write(bin_data)
    return

def get_enum_field(enum: Type[Enum], value):
    for field in enum.__members__.values():
        if field.value == value:
            return field

    # If no matching field is found
    return None

#def upload_existing_analysis(info: dict, existing_path: Path):
#    '''
#    Upload an existing analysis.
#    If passing info of type dict it must have keys:
#        - compiler
#        - proglang
#        - opt_lvl
#        - stripped_lvl
#        - analysis_type
#        - file_type
#    '''
#
#
#    if isinstance(info, dict):
#        compiler = get_enum_field(Compiler, info['compiler'])
#        progLang = get_enum_field(ProgLang, info['prog_lang'])
#        opt_lvl = get_enum_field(RustcOptimization, info['opt_lvl'])
#        file_type = get_enum_field(FileType, info['file_type'])
#
#    # Can pass an existing analysis for the data param
#    binHash = calculate_md5(bin_path)
#
#
#    # from file to file
#    shutil.copy2(existing_path, analysis_file)
                             

def ___re_analyze_tmp(path, comp, lang, opt):

    from analyzer.binary_analyzer import generate_minimal_labeled_features 


    analyzed_files = list(path.expanduser().resolve().rglob('*ANALYSIS.np*'))


    #bin_files = [ x.parent.joinpath(x.name.replace("_ANALYSIS.npz","")) 
    #    for x in analyzed_files if 
    #(x.parent.joinpath(x.name.replace("_ANALYSIS.npz",""))).exists()
    #and "ANALYSIS" not in x.name]

    bin_name = [ x.parent.joinpath(x.name.replace("_ANALYSIS.npz", "")) 
                for x in analyzed_files]

    bin_files = [ x for x in bin_name if x.exists()]


    # Go into rip bin and find all the files with "ANALYSIS"
    for file in alive_it(bin_files):
        # This is the analysis file, the corresponding 
        # binary file will have the same name but without 
        # the analysis part 

        # filetype/compiler/<binname>_<opt_lvl>_
        compiler = str(file.parent.name)
        f_type = str(file.parent.parent.name)

        ft = None
        for mem in FileType:
            if mem.value == f_type:
                ft = mem

        if ft is None or lang is None or comp is None:
            raise Exception("No member for type {}".format((lang,comp,ft)))

        print("Analyzing and saving {} in new db".format(file.resolve()))

        analysis_type = AnalysisType.DEC_REPR_BYTE_PLUS_FUNC_LABELS

        data_gen = generate_minimal_labeled_features(file,
                                                    use_one_hot=False)

        save_and_register_analysis(file,
                                   data_gen,
                                   analysis_type,
                                   lang,
                                   comp,
                                   ft,
                                   opt)

        analysis_type = AnalysisType.ONEHOT_PLUS_FUNC_LABELS
        data_gen = generate_minimal_labeled_features(file,
                                                    use_one_hot=True)

        save_and_register_analysis(file,
                                   data_gen,
                                   analysis_type,
                                   lang,
                                   comp,
                                   ft,
                                   opt)




    return 


def _update_pkg_in_reg(old_pkg_path, new_pkg_name):
    '''
    After _mv_package, some packages were moved on the file system 
    but not updated in the registry for what ever reason. 

    This is update the registry 
    '''

    # Get the reg
    reg = get_registry()

    # Make sure the old_pkg_path is in the registry 
    files_in_pkg = reg[
                    reg['package_path'] == f"{old_pkg_path.resolve()}"
                    ]

    # Raise error if the pkg doesn't exist
    if files_in_pkg.empty:
        raise Exception("No files with pkg path {}".format(old_pkg_path))

    # There should only exist one package, go ahead and move that now 
    old_abs =  Path(files_in_pkg.iloc[0]['package_path'])
    new_path = old_abs.parent.joinpath(new_pkg_name).resolve()

    # analysis path
    files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}", "analysis_path"]  = files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}",'analysis_path'].str.replace(f"{old_pkg_path.resolve()}", f"{new_path.resolve()}")


    # package path
    files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}", "package_path"]  = files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}","package_path"].str.replace(f"{old_pkg_path.resolve()}", f"{new_path.resolve()}")


    # Get a reg without the old package paths
    reg = reg[reg['package_path'] != f"{old_pkg_path.resolve()}"]

    # Make sure the old_pkg_path is in the registry 
    should_be_empty = reg[
                    reg['package_path'] == f"{old_pkg_path.resolve()}"
                    ]

    # Raise error if the pkg doesn't exist
    if not should_be_empty.empty:
        raise Exception("Reg was unable to remove oldpkg path{}".format(old_pkg_path))



    # Make the new reg and save
    new_reg = pd.concat([reg,files_in_pkg], ignore_index=True)

    print("This is what is going to happen")
    print("Following should be empty")
    print(should_be_empty[["package_path","analysis_path"]])
    print("This is the new package path")
    print("=============================")
    print("This is the new package rows")
    print(new_reg[new_reg['package_path'] ==  f"{new_path.resolve()}" ])
    print("=============================")


    cont = input("Continue (Y)")
    if cont not in ['Y', 'y']:
        return
 
    # Updat tne new reg
    new_reg.to_csv(RIPBIN_REG,index=False)



    return

def _mv_package(old_pkg_path, new_pkg_name):

    # Get ripbin reg 
    reg = get_registry()

    # Make sure the old_pkg_path is in the registry 
    files_in_pkg = reg[
                    reg['package_path'] == f"{old_pkg_path.resolve()}"
                    ]

    # Raise error if the pkg doesn't exist
    if files_in_pkg.empty:
        raise Exception("No files with pkg path {}".format(old_pkg_path))

    print("Found  the follow rows with pkg {old_pkg_path}")
    print(files_in_pkg[["package_path","analysis_path"]])


    # There should only exist one package, go ahead and move that now 
    old_abs =  Path(files_in_pkg.iloc[0]['package_path'])
    new_path = old_abs.parent.joinpath(new_pkg_name).resolve()


    # List of things that will change for every row in files_in_pkg
    # 1. package_path  (saved as absolute)
    # 2. analysis_path (saved as absolute)

    # analysis path
    #files_in_pkg['analysis_path'].str.replace(f"{old_pkg_path.resolve()}", 
                                                #f"{new_path.resolve()}")

    # package path
    #files_in_pkg['package_path'].str.replace(f"{old_pkg_path.resolve()}",
                                             #f"{new_path.resolve()}"})

    # analysis path
    files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}", "analysis_path"]  = files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}",'analysis_path'].str.replace(f"{old_pkg_path.resolve()}", f"{new_path.resolve()}")


    # package path
    files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}", "package_path"]  = files_in_pkg.loc[files_in_pkg['package_path'] == f"{old_pkg_path.resolve()}","package_path"].str.replace(f"{old_pkg_path.resolve()}", f"{new_path.resolve()}")


    # Get a reg without the old package paths
    reg = reg[reg['package_path'] != f"{old_pkg_path.resolve()}"]

    # Make sure the old_pkg_path is in the registry 
    should_be_empty = reg[
                    reg['package_path'] == f"{old_pkg_path.resolve()}"
                    ]

    # Raise error if the pkg doesn't exist
    if not should_be_empty.empty:
        raise Exception("Reg was unable to remove oldpkg path{}".format(old_pkg_path))



    # Make the new reg and save
    new_reg = pd.concat([reg,files_in_pkg], ignore_index=True)

    print("This is what is going to happen")
    print("Following should be empty")
    print(should_be_empty[["package_path","analysis_path"]])
    print("This is the new package path")
    print("=============================")
    print("This is the new package rows")
    print(new_reg[new_reg['package_path'] ==  f"{new_path.resolve()}" ])
    print("=============================")

    # About to move 
    print(f"Moving {old_abs} to {new_path}")

    if new_path.exists():
        raise Exception("New pkg path already exists: {}".format(new_path))

    #cont = input("Continue (Y)?")
    #if cont not in ["Y", 'y']:
    #    return

    shutil.copytree(old_abs, new_path)
    new_reg.to_csv(RIPBIN_REG,index=False)
    shutil.rmtree(old_abs)

    #new_row_ent= reg[
    #                reg['package_path'] == f"{old_pkg_path.resolve()}"
    #                ]
#df.loc[df["B"] == "HERE", "A"] = df.loc[df["B"] == "HERE", "A"].str.replace("THIS", "ANOTHERONE")




    # Ability to change file name

    # First copy the file to the new name 

    # Delete the previous name 

    # Edit the row in the registry

    # copy old row 

    # Remove old row 

    # edit copy 

    # add new row



if __name__ == "__main__":


    # Get all the rust pgks 
    reg = get_registry()

    # Get the rust files package paths
    files_list = set(reg[reg['prog_lang'] == 'rust']['package_path'].to_list())
    files_list = [x for x in files_list if "_O0_NOTSTRIPPED" in x]

    print(files_list)
    y = input(f"About to move {len(files_list)} Files... continue?(Y)")

    if y not in ['Y', 'y']:
        exit(1)

    # For each path if _O0_NOTSTRIPPED, replace it with ''
    for f in files_list:
        if "_O0_NOTSTRIPPED" in Path(f).name:
            #_mv_package( Path(f), Path(f).name.replace("_O0_NOTSTRIPPED",""))
            #_mv_package( Path(f), Path(f).name.replace("_O0_NOTSTRIPPED",""))

            _update_pkg_in_reg( Path(f), Path(f).name.replace("_O0_NOTSTRIPPED",""))



    #path = Path("/home/rest/.ripbin/ripped_bins/xsv_O0_NOTSTRIPPED_a7621f40823bab89b80ac8701ba51d6b").resolve()

    #print(path)
    #_mv_package(
    #    path
    #    ,
    #    "xsv"
    #)


