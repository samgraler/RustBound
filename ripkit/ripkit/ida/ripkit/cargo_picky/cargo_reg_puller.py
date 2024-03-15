
import shutil
import tarfile
from typing import Union
import magic
import pefile
from elftools.elf.elffile import ELFFile
import tempfile
from pathlib import Path
import subprocess
import pandas as pd
import lief
from enum import Enum
 
from .cargo_types import RustcTarget, RustcOptimization, \
                         RustcStripFlags, CargoVariables, \
                         FileType, Cargodb

from .cargo_builder import gen_cross_build_cmd


REG_DIR = Cargodb.REG_DIR.value
CLONED_DIR = Cargodb.CLONED_DIR.value
EXTRACTED_TAR_DIR = Cargodb.EXTRACTED_TAR_DIR.value
DATA_DIR = Cargodb.DATA_DIR.value




def get_file_type(file_path: Path)->FileType:
    ''' Detect the FileType of the file'''

    # Use the absoltue path
    file_path = file_path.resolve()

    # Load the info for the file 
    file_info = magic.from_file(file_path)

    # Check for PE vs ELF
    if 'PE' in file_info:
        # Load the 
        pe = pefile.PE(file_path)

        # Check the header for the machine type
        # - NOTICE: The below lines will give a type error about machine but its ok
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return FileType.PE_X86
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return FileType.PE_X86_64
        else:
            raise Exception(f"No filetype for {file_info}")

    elif 'ELF' in file_info:
        # Open the file and read the file header using ELFFile obj
        with open(file_path, 'rb') as f:
            elf_file = ELFFile(f)
            header = elf_file.header

            # 'e_machine' will indicate 32bit vs 64bit
            if header['e_machine'].lower() == 'em_386':
                return FileType.ELF_X86
            elif header['e_machine'].lower() == 'em_x86_64':
                return FileType.ELF_X86_64
            else:
                raise Exception(f"No filetype for {header['e_machine']}")
    elif 'MACH':
        #TODO: Handle MACH files 
        raise Exception("TODO: Implement MACHO files")
    else:
        raise Exception("File type unknown")






for dir in [REG_DIR,CLONED_DIR]:
    if not dir.exists():
        dir.mkdir()


def pull_registry():

    if not EXTRACTED_TAR_DIR.exists():
        EXTRACTED_TAR_DIR.mkdir(parents=True)


    # Make sure a tar file exists 
    if not DATA_DIR.exists():
        tar_file = REG_DIR.joinpath("tar_file.tar.gz").resolve()

        if not tar_file.exists():
            cmd = f"curl -o {tar_file} https://static.crates.io/db-dump.tar.gz"
            try: 
                output = subprocess.check_output(cmd,shell=True)
            except Exception as e:
                print(f"Error pulling the index: {e}")
                exit(1)

        cmd = f"tar -xzf {tar_file} -C {EXTRACTED_TAR_DIR} --strip-components=1"
        try: 
            output = subprocess.check_output(cmd,shell=True)
        except Exception as e:
            print(f"Error extracting index {e}")
            exit(1)
    return 

def get_registry_df()-> pd.DataFrame:

    # At this point EXTRACTED_TAR_DIR exists
    csv_file = DATA_DIR / "crates.csv"
    if not csv_file.exists():
        print(f"Error, the file {csv_file} should exist but doesn't")

    # Get a dataframe of the crates
    df = pd.read_csv(csv_file.resolve())

    # The repositories are in the 'repository' column
    return df

def del_crate(crate: Union[list[str], str],
                dir=CLONED_DIR )-> None:

    if isinstance(crate, str):
        crate = [crate]

    for single_crate in crate:
        if (crate_path:=CLONED_DIR.joinpath(single_crate)).exists():
            shutil.rmtree(crate_path)
    return

def clone_crate(crate: Union[list[str], str],
                exist_ok=False, dir=CLONED_DIR )-> None:
    """
        Function to clone cargo crates
    """

    if isinstance(crate, str):
        crate = [crate]

    for single_crate in crate:
        if (crate_path:=CLONED_DIR.joinpath(single_crate)).exists() and not exist_ok:
            print(f"Crate {single_crate} alreadt exists at {crate_path}")
            continue

        cmd = f"cargo clone {single_crate} -- {dir.resolve()}/"
        try:
            output = subprocess.check_output(cmd,shell=True)
        except Exception as e:
            raise Exception(f"Crate pull error {e}")


def clone_crates(crate_names: pd.DataFrame, stop_on_fail=False, 
                 exist_ok:bool=False, dir=CLONED_DIR)-> None:
    ''' Clone the passed crates '''

    finished_crates = []
    for crate in list(crate_names.name):
        try:
            clone_crate(crate,exist_ok,dir)
            finished_crates.append(crate)
        except Exception as e:
            if stop_on_fail:
                raise Exception(f"Crate {crate} failed: {e}")

# Once a packge is built, there are multiple locations that binaries 
# of interest may be 
# 
# These are the paths when using 'cross', with debug profile
# 1. <pkg_root>/target/{target_name}/debug/{exa_name}
# 2. <pkg_root>/target/{target_name}/debug/incremental
#       /{some-name}/{some_hash}/*.o 
# 
#   - For library cargo packages the intreseting files are at 
# 1. <pkg_root>/target/{target_name}/debug/{lib_pack_name}.rlib
# 5.

def is_executable(path: Path)->bool:
    try:
        if not path.is_file():
            return False


        # This will through an exeption if the file type is not 
        # elf or pe or macho
        f_type = get_file_type(path)

        # TODO: So for some reason lief.parse() prints 
        # to stdout when the file type is unknown AND 
        # throws an error
        bin = lief.parse(str(path.resolve()))#, redirect=True,
                             #stdout=devnull)

        if not hasattr(bin, "format"):
            return False
        elif bin.format in [lief.EXE_FORMATS.PE,
                        lief.EXE_FORMATS.ELF]:
            return True
        return False
    except Exception as e:
        st = f"Unexpected error seeing if file {path} if an exe: {e}"
        return False



def is_object_file(path:Path)->bool:
    # Get the file extension
    file_extension = path.suffix.lower()

    # Check if the file is a .o or .rlib file
    if file_extension == ".o" or file_extension == ".rlib":
        return True

    return False

class FileSuffixOfInterest(Enum):
    O    = "o"
    RLIB = "rlib"
    AR   = "ar"

def any_in(target_list: list[str], val:str):
    return any(sub in val for sub in target_list)

def find_built_files(target_path:Path,
                        target_suffixes: list[str] = [".rlib"],
                        exclude_suffixes: list[str] = [".rmeta"]):
    """
        This function was made to automate the finding of executable 
        files build from cargo builds

        This function will also help find .rlib files
    """

    target_subdirs = [x for x in [target_path.joinpath("debug"), 
                      target_path.joinpath("release")] if x.exists()]

    ret_files = []
    for subdir in target_subdirs:
        ret_files.extend([x for x in subdir.iterdir() if
                (is_executable(x) or any_in(target_suffixes, x.suffix.lower()))
                 and not any_in(exclude_suffixes, x.suffix.lower())])
    return ret_files


def get_target_productions(crate: str, target: RustcTarget, 
                          target_suffixes: list[str] = [".rlib"],
                          exclude_suffixes: list[str] = [".rmeta"]):
    """
    Grab a specific target produced files
    """

    # Target dir is the base target dir of the crate
    target_dir = CLONED_DIR.joinpath(crate).joinpath("target")

    # If the specific target exists as a sub dir of the general target 
    # dir, grab the files of interest from it 
    if (dir:=target_dir.joinpath(str(target.value))).exists():
        return find_built_files(dir,target_suffixes,exclude_suffixes)
    return []


def get_build_productions(crate:str, 
                          target_suffixes: list[str] = [".rlib"],
                          exclude_suffixes: list[str] = [".rmeta"])->list[Path]:
    """
        This function is for grabbing files "of interest" from a built 
        cargo package. The directories this function search for are 
        what would be typical for a typical cargo build, because of the 
        cross compiled packages. Here's an example directory to help:

        In 
        /.cargo_reg/cargo_cloned/<crate_name>/target
        it may look like:
        |
        | debug 
        | release
        | x86_64-unknown-unknown-linux-gnu
        | | release
        | | debug
        | i686-pc-windows-gnu

        cargo build will put built libs and exes in directories */target/debug, 
        */target/release . 
        However, those are not the only directories of interest, there is a 
        variable number of subdirectories that have their own 'debug' and 
        'release' sections that are also of interest. 

        Functions of interest include
            - executables 
            - .rlib files 

        Get any executables or files with the target_suffixes
        from the base of the crate

        - Search through cross generated targets as well
    """

    target_dir = CLONED_DIR.joinpath(crate).joinpath("target")

    ret_files = find_built_files(target_dir,target_suffixes,exclude_suffixes)

    for path in target_dir.iterdir():
        #print(path)

        # Ignore files
        if not path.is_dir():
            continue

        # Ignore the base debug and target directories
        if path in [target_dir.joinpath("debug"), 
                    target_dir.joinpath("target")]:
            continue

        if path.joinpath("debug").exists() or path.joinpath("target").exists():
            # If the subdir has a target dir,
            # it should be a cross target and its OWN target outpu
            # ie
            # x86_64-unknown-linux-gnu
            #   | target
            #       | debug 
            #       | realse 
            ret_files.extend(find_built_files(path,target_suffixes,exclude_suffixes))
    return ret_files


def load_rlib(path: Path)->list[lief.Binary]:
    """
        rlib files are marked as ab archive, so the file goodies in them 
        need to be extracted and then individually analyzed
    """

    if not (".rlib" in path.suffix.lower() and path.exists()):
        st = "Path does not exist or is not .rlib file"
        raise Exception(st)


    # Create a temporary directory to save the extracted files
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract files from the archive
        with tarfile.open(path, "r") as tar:
            tar.extractall(path=temp_dir)

        # Get the file names of the extracted files
        extracted_files = []
        for file_path in Path(temp_dir).iterdir():
            if file_path.is_file():
                extracted_files.append(lief.parse(file_path.name))

        return extracted_files


if __name__ == "__main__":
    #pull_registry()
    #df = get_registry_df()
    #print(df.name)
    #clone_crate("exa")

    #@build_crate("exa", 
    #@            target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU, 
    #@            strip = RustcStripFlags.SYM_TABLE, 
    #@            opt_lvl = RustcOptimization.O1)

    #build_many_crate_many_target(
    #            ["exa","ripgrep"],
    #            targets=[RustcTarget.X86_64_UNKNOWN_LINUX_GNU, 
    #            RustcTarget.I686_UNKNOWN_LINUX_GNU],
    #            strip = RustcStripFlags.SYM_TABLE, 
    #            opt_lvl = RustcOptimization.O1,
    #            stop_on_fail=False)
    clone_crate("exa")

    #print(get_build_productions("exa"))
    #print(get_build_productions("libc"))
    #print(load_rlib(CLONED_DIR.joinpath("libc/target/debug/liblibc.rlib")))
