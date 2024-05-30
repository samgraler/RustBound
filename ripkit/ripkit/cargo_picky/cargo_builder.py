"""
Cargo builder provides the functions to generate cargo + cross commands to 
build creates found in the ~/.crates_io directory
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
from .picky_exceptions import CrateBuildException
from .cargo_types import (
    RustcTarget,
    CargoVariables,
    RustcStripFlags,
    RustcOptimization,
    Cargodb,
    FileType,
)

from ripkit.ripbin import (
    CompileTimeAttacks,
)


def gen_cargo_build_cmd(
    proj_path: Path,
    target: RustcTarget,
    strip_cmd: Optional[RustcStripFlags] = None,
    opt_lvl: Optional[RustcOptimization] = None,
):
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
        substrs.append(
            f" {CargoVariables.DEV_PROF_SET_OPT_LEVEL.value}={opt_lvl.value}"
        )

    # substrs.append(f"cd {proj_path} && cargo clean && cargo build --target={target.value}")
    substrs.append(f"cargo build --target={target.value}")
    # substrs.append(f"cd {proj_path} && cross build --manifest-path={proj_path.resolve()}/Cargo.toml --target={target.value}")

    full_build_str = " ".join(x for x in substrs)
    return full_build_str


def gen_cross_build_cmd(
    proj_path: Path,
    target: RustcTarget,
    strip_cmd: Optional[RustcStripFlags] = None,
    opt_lvl: Optional[RustcOptimization] = None,
    attack: Optional[CompileTimeAttacks] = None,
    force_podman: bool = False,
):
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
        substrs.append(
            f" {CargoVariables.DEV_PROF_SET_OPT_LEVEL.value}={opt_lvl.value}"
        )
    if attack is not None:
        substrs.append(f"RUSTFLAGS='-C {attack.value}'")

    if force_podman:
        substrs.append(
            f"cd {proj_path} && CROSS_CONTAINER_ENGINE=podman cross build --target={target.value}"
        )
    else:
        substrs.append(f"cd {proj_path} && cross build --target={target.value}")

    full_build_str = " ".join(x for x in substrs)
    return full_build_str


def build_crate(
    crate: str,
    opt_lvl: RustcOptimization = RustcOptimization.O0,
    target: RustcTarget = RustcTarget.X86_64_UNKNOWN_LINUX_GNU,
    strip: RustcStripFlags = RustcStripFlags.NOSTRIP,
    use_cargo=False,
    force_podman=False,
) -> None:
    """Build the repo"""

    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    if use_cargo:
        cmd = gen_cargo_build_cmd(crate_path, target, strip, opt_lvl, force_podman=force_podman)
    else:
        cmd = gen_cross_build_cmd(
            crate_path, target, strip, opt_lvl, force_podman=force_podman
        )

    # If the crate doesn't exist dont run
    if not crate_path.exists():
        raise Exception(f"Crate {crate} has not been cloned")
    try:
        subprocess.check_output(cmd, shell=True, 
                                stderr=subprocess.DEVNULL
                                )
    except Exception as e:
        print(f"ERROR In build {e}")
        raise CrateBuildException(str(e))
    return


# def build_crate_many_target(crate: str,
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


def get_file_type(file_path: Path) -> FileType:
    """Detect the FileType of the file"""

    # Use the absoltue path
    file_path = file_path.resolve()

    # Load the info for the file
    file_info = magic.from_file(file_path)

    # Check for PE vs ELF
    if "PE" in file_info:
        # Load the
        pe = pefile.PE(file_path)

        # Check the header for the machine type
        # - NOTICE: The below lines will give a type error about machine but its ok
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            return FileType.PE_X86
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            return FileType.PE_X86_64
        else:
            raise Exception(f"No filetype for {file_info}")

    elif "ELF" in file_info:
        # Open the file and read the file header using ELFFile obj
        with open(file_path, "rb") as f:
            elf_file = ELFFile(f)
            header = elf_file.header

            # 'e_machine' will indicate 32bit vs 64bit
            if header["e_machine"].lower() == "em_386":
                return FileType.ELF_X86
            elif header["e_machine"].lower() == "em_x86_64":
                return FileType.ELF_X86_64
            else:
                raise Exception(f"No filetype for {header['e_machine']}")
    elif "MACH":
        # TODO: Handle MACH files
        raise Exception("TODO: Implement MACHO files")
    else:
        raise Exception("File type unknown")


#TODO: This function could be improved if there exists a better python
#       module / way to simpily see if a file is an executable. Something
#       similar to the linux 'file' command
def is_executable(path: Path) -> bool:
    """
    See if the path is an executable. Specifically, parse the binary with
    lief and check it's format
    """

    bin = None
    try:
        if not path.is_file():
            return False

        # TODO: So for some reason lief.parse() prints
        # to stdout when the file type is unknown AND
        # throws an error
        bin = lief.parse(str(path.resolve()))
    except Exception as e:
        return False

    if bin is None:
        return False

    if not hasattr(bin, "format"):
        return False
    elif bin.format in [
        lief.EXE_FORMATS.PE,
        lief.EXE_FORMATS.ELF,
        lief.EXE_FORMATS.MACHO,
        lief.EXE_FORMATS.UNKNOWN,
    ]:
        return True
    else:
        return False


def is_object_file(path: Path) -> bool:
    """
    Explicit function to see if a crate production file is an object file.
    Specifically if the suffix is .o or .rlib then the file is considered 
    on object file
    """
    # Check if the file is a .o or .rlib file
    return path.suffix.lower() == ".o" or path.suffix.lower() == ".rlib"


class FileSuffixOfInterest(Enum):
    """"EXplicit suffix names to use when searching for crate productions"""
    O = "o"
    RLIB = "rlib"
    AR = "ar"


def any_in(target_list: list[str], val: str)->bool:
    """True if element in target list is in val"""
    return any(sub in val for sub in target_list)


def find_built_files(
    target_path: Path,
    target_suffixes: list[str] = [".rlib"],
    exclude_suffixes: list[str] = [".rmeta"],
):
    """
    This function was made to automate the finding of executable
    files build from cargo builds

    This function will also help find .rlib files
    """

    # Only search in the following two paths
    debug_path = target_path.joinpath("debug")
    release_path = target_path.joinpath("release")
    
    # glob the files from the above paths into a list, if paths exist
    files = []
    if debug_path.exists():
        files.extend([x for x in debug_path.glob('*') if x.is_file()])
    if release_path.exists():
        files.extend([x for x in release_path.glob('*') if x.is_file()])

    #TODO: Funcion name is find_built_files, not find_exes, but we only 
    #       return exes

    # Now filter out non-exectuables and any files with siffixes in 
    # exclude suffixes
    exes = [x for x in files if is_executable(x)]
    ret_files = [x for x in files if not any_in(exclude_suffixes, x.suffix.lower())]

    return ret_files


def get_target_productions(
    crate: str,
    target: RustcTarget,
    target_suffixes: list[str] = [".rlib"],
    exclude_suffixes: list[str] = [".rmeta"],
):
    """
    Grab a specific target produced files
    """

    target_dir = Path(LocalCratesIO.CRATES_DIR.value).joinpath(crate).joinpath("target")

    # If the specific target exists as a sub dir of the general target
    deep_target_dir = target_dir.joinpath(str(target.value))
    if not deep_target_dir.exists():
        return []
    else:
        return find_built_files(deep_target_dir, target_suffixes, exclude_suffixes)


if __name__ == "__main__":
    print("nop")
