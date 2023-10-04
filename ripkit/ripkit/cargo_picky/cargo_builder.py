"""
Cross compiling rust is not as easy as the rust book makes it sounds...
1. After following rust book instrutios to
    - rustup toolchain install <x_chain>
    - rustup target add <x_target>
    You also need the correct linker installed for rustc!!

So all this really meant was I must use cargo for building, because 
after:
    - rustup target add <x_target> 
    you can:
    - cargo build --target <x_target>

This is fine, and only using rustc was not going to get me far anyways.

This files roadmap:
    [] automate cargo building 
        [] package_dir
        [] optimizations
        [] strip or not strip 
    [] automate cross compiling 
    [] automate extracting rlib files
        [] "ar x *.rlib file" ; Which may produce alot of files
"""

import lief
import magic
import pefile
from elftools.elf.elffile import ELFFile
from enum import Enum
from pathlib import Path
import subprocess
from typing import Optional
import os
from .crates_io import LocalCratesIO
from .cargo_types import RustcTarget, CargoVariables, RustcStripFlags,\
                        RustcOptimization, Cargodb, FileType

def gen_cargo_build_cmd(proj_path: Path, target: RustcTarget, 
                        strip_cmd: Optional[RustcStripFlags] = None, 
                        opt_lvl: Optional[RustcOptimization] = None):
    # First build the environment variables,
    # the CARGO_ENCODED_RUSTC_FLAGS -otherwise called- 
    #   CargoVariables.RUSTC_FLAGS 
    # Is being used to strip or not strip
    # 
    # And CARGO_PROFILE_DEV_OPT_LEVEL -otherwise called-
    #   CargoVariables.DEV_PROF_SET_OPT_LEVEL 
    # Is being used to set the optimizaition level
    substrs = [f"cd {proj_path} && cargo clean &&"]
    if strip_cmd is not None:
        substrs.append(f"{CargoVariables.RUSTC_FLAGS.value}='{strip_cmd.value}'")
    if opt_lvl is not None:
        substrs.append(f" {CargoVariables.DEV_PROF_SET_OPT_LEVEL.value}={opt_lvl.value}")

    #substrs.append(f"cd {proj_path} && cargo clean && cargo build --target={target.value}")
    substrs.append(f"cargo build --target={target.value}")
    #substrs.append(f"cd {proj_path} && cross build --manifest-path={proj_path.resolve()}/Cargo.toml --target={target.value}")

    full_build_str = " ".join(x for x in substrs)
    return full_build_str



def gen_cross_build_cmd(proj_path: Path, target: RustcTarget, 
                        strip_cmd: Optional[RustcStripFlags] = None, 
                        opt_lvl: Optional[RustcOptimization] = None):
    # First build the environment variables,
    # the CARGO_ENCODED_RUSTC_FLAGS -otherwise called- 
    #   CargoVariables.RUSTC_FLAGS 
    # Is being used to strip or not strip
    # 
    # And CARGO_PROFILE_DEV_OPT_LEVEL -otherwise called-
    #   CargoVariables.DEV_PROF_SET_OPT_LEVEL 
    # Is being used to set the optimizaition level
    substrs = []
    if strip_cmd is not None:
        substrs.append(f"{CargoVariables.RUSTC_FLAGS.value}='{strip_cmd.value}'")
    if opt_lvl is not None:
        substrs.append(f" {CargoVariables.DEV_PROF_SET_OPT_LEVEL.value}={opt_lvl.value}")

    substrs.append(f"cd {proj_path} && cross build --target={target.value}")

    full_build_str = " ".join(x for x in substrs)
    return full_build_str


def build_crate(crate: str, 
                opt_lvl: RustcOptimization = RustcOptimization.O0,
                target: RustcTarget = RustcTarget.X86_64_UNKNOWN_LINUX_GNU, 
                strip: RustcStripFlags = RustcStripFlags.NOSTRIP,
                use_cargo=False,
                debug=False)->None:
    ''' Build the repo '''

    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    if use_cargo:
        cmd = gen_cargo_build_cmd(crate_path,target,strip, opt_lvl)
    else:
        cmd = gen_cross_build_cmd(crate_path,target,strip, opt_lvl)

    # If the crate doesn't exist dont run
    if not crate_path.exists(): 
        raise Exception(f"Crate {crate} has not been cloned")
    try: 
        subprocess.check_output(cmd, shell=True,
                                        stderr=subprocess.DEVNULL,
                                         )
    except Exception as e:
        print(f"Error: {e} Failed to rustc compile command.")
        return
    return


#def build_crate_many_target(crate: str, 
#                opt_lvl: RustcOptimization, 
#                targets: list[RustcTarget], 
#                strip: RustcStripFlags,
#                            stop_on_fail = False):
#    ''' Build the repo '''
#
#    # Log of failed builds
#    failed_builds = []
#    built_targets = []
#
#    for target in targets:
#        try:
#            build_crate(crate,opt_lvl, target, strip)
#            built_targets.append((crate,opt_lvl,target,strip))
#        except Exception as e:
#            if stop_on_fail: raise e
#            failed_builds.append((crate,opt_lvl,target,strip))
#    return (built_targets, failed_builds)

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
    #target_dir = CLONED_DIR.joinpath(crate).joinpath("target")

    target_dir = Path(LocalCratesIO.CRATES_DIR.value).joinpath(crate).joinpath("target")

    # If the specific target exists as a sub dir of the general target 
    # dir, grab the files of interest from it 
    if (dir:=target_dir.joinpath(str(target.value))).exists():
        return find_built_files(dir,target_suffixes,exclude_suffixes)
    return []




if __name__ == "__main__":

    #bul_str = gen_cross_build_cmd(Path("hello.rs"), 
    #            target = RustcTarget.X86_64_PC_WINDOWS_GNU, 
    #            strip_cmd = RustcStripFlags.SYM_TABLE, 
    #            opt_lvl = RustcOptimization.O1)
    build_crate('exa',RustcOptimization.O0, RustcTarget.X86_64_PC_WINDOWS_MSVC, RustcStripFlags.NOSTRIP)
    print("done")
