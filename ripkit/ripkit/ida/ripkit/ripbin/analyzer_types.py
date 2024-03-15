"""
Provide types and dataclasses for file 'binary_analyzer.py'


Analyzing the files themselves has proven to take a longgggg time,
especially for rust and c files. So I need fast analysis.

BUT, I also want to store alot of information about a file, 
incase new info becomes useful parameters later. 

"""

from enum import Enum
from dataclasses import dataclass
import pandas as pd
from pathlib import Path



class AnalysisType(Enum):
    ONEHOT_PLUS_FUNC_LABELS = "onehot_plus_func_labels"
    DEC_REPR_BYTE_PLUS_FUNC_LABELS = 'dec_repr_byte_plus_func_labels'

class Coptimization(Enum):
    O0 = "0"
    O1 = "1"
    O2 = "2"
    O3 = "3"

class GoOptimization(Enum):
    DEFAULT = "default"

class RustcOptimization(Enum):
    O0 = "0"
    O1 = "1"
    O2 = "2"
    O3 = "3"
    OS = "s"
    OZ = "z"

@dataclass 
class FunctionInfo():
    name: str
    addr: int
    addrHex: str
    size: int

@dataclass
class binaryFileExecSectionOnly():
    ''' Represents a  file '''
    name: str
    stripped: bool
    compile_cmd: str
    bytes: pd.DataFrame

class FileType(Enum):
    ''' File type enums '''
    # @TODO: Add MACH-0 support
    # @TODO: NOTICE: lief has its own file types but doesn't differenciate
    #         64bit and 32bit
    PE_X86 = "pe_x86"
    PE_X86_64 = "pe_x86_64"
    ELF_X86 = "elf_x86"
    ELF_X86_64 = "elf_x86_64"

class Compiler(Enum):
    ICC = "icc"
    GCC = "gcc"
    RUSTC = "rustc"
    GO = "go"
    CLANG = "clang"
    MSVC = "msvc"

class ProgLang(Enum):
    C = "c"
    RUST = "rust"
    GO = "go"

@dataclass 
class ByteInfo():
    byte: int
    hexByte: str
    #oneHotEncodedByte: list[int]
    address: int
    hexStrAddress: str
    functionStart: bool
    functionEnd: bool
    functionMiddle: bool
    #fileName: Path
    fileName: str

@dataclass
class KnownByteInfo_verbose_sql():
    # Byte things
    byte: int
    hexStrByte: str
    #oneHotEncodedByte: list[int]
    address: int
    hexStrAddress: str
    funcStart: bool
    funcEnd: bool
    funcMiddle: bool
    # File thins 
    fileName: str #Path
    fileType: str #FileType
    # File generation things
    compiler: str #Compiler
    progLan: str #ProgLang
    optimization: str #Optimization
    is_stripped: bool
    os_arch : str    #TODO Probably be good to make an enum for this 
    compile_cmd : str
 
@dataclass
class KnownByteInfo_verbose():
    # Byte things
    byte: int
    hexStrByte: str
    oneHotEncodedByte: list[int]
    address: int
    hexStrAddress: str
    funcStart: bool
    funcEnd: bool
    funcMiddle: bool
    # File thins 
    fileName: Path
    fileType: FileType
    # File generation things
    compiler: Compiler
    progLan: ProgLang
    optimization:  RustcOptimization
    is_stripped: bool
    os_arch : str    #TODO Probably be good to make an enum for this 
    compile_cmd : str
                    #      too

class RustcStripFlags(Enum):
    """ 
    This is a flag meant to be passed to 
    CargoVariables.RUSTC_FLAGS
    """
    # NOTICE: Only one flag can be passed to 
    # CARGO_ENCODED_RUSTFLAGS...
    # They remove the RUSTFLAGS environment variable 
    # in favor of this one that encodes the flags...
    # however I could not find a way to change multiple 
    # flags together
    NOSTRIP = "-Cstrip=none"
    DEBUG_INFO = "-Cstrip=debug"
    SYM_TABLE = "-Cstrip=symbols"


class CargoVariables(Enum):
    ''' 
    These are the means to provided the build flags, via env vars
    '''
    RUSTC_FLAGS = "CARGO_ENCODED_RUSTFLAGS"
    DEV_PROF_SET_OPT_LEVEL = "CARGO_PROFILE_DEV_OPT_LEVEL"
    RELEASE_PROF_SET_OPT_LEVEL = "CARGO_PROFILE_RELEASE_OPT_LEVEL"



class RustcTarget(Enum):
    """Supported rustc targets"""

    AARCH64_APPLE_DARWIN = "aarch64-apple-darwin"
    AARCH64_APPLE_IOS = "aarch64-apple-ios"
    AARCH64_APPLE_IOS_MACABI = "aarch64-apple-ios-macabi"
    AARCH64_APPLE_IOS_SIM = "aarch64-apple-ios-sim"
    AARCH64_APPLE_TVOS = "aarch64-apple-tvos"
    AARCH64_APPLE_WATCHOS_SIM = "aarch64-apple-watchos-sim"
    AARCH64_FUCHSIA = "aarch64-fuchsia"
    AARCH64_KMC_SOLID_ASP3 = "aarch64-kmc-solid_asp3"
    AARCH64_LINUX_ANDROID = "aarch64-linux-android"
    AARCH64_NINTENDO_SWITCH_FREESTANDING = "aarch64-nintendo-switch-freestanding"
    AARCH64_PC_WINDOWS_GNULLVM = "aarch64-pc-windows-gnullvm"
    AARCH64_PC_WINDOWS_MSVC = "aarch64-pc-windows-msvc"
    AARCH64_UNKNOWN_FREEBSD = "aarch64-unknown-freebsd"
    AARCH64_UNKNOWN_FUCHSIA = "aarch64-unknown-fuchsia"
    AARCH64_UNKNOWN_HERMIT = "aarch64-unknown-hermit"
    AARCH64_UNKNOWN_LINUX_GNU = "aarch64-unknown-linux-gnu"
    AARCH64_UNKNOWN_LINUX_GNU_ILP32 = "aarch64-unknown-linux-gnu_ilp32"
    AARCH64_UNKNOWN_LINUX_MUSL = "aarch64-unknown-linux-musl"
    AARCH64_UNKNOWN_NETBSD = "aarch64-unknown-netbsd"
    AARCH64_UNKNOWN_NONE = "aarch64-unknown-none"
    AARCH64_UNKNOWN_NONE_SOFTFLOAT = "aarch64-unknown-none-softfloat"
    AARCH64_UNKNOWN_NTO_QNX710 = "aarch64-unknown-nto-qnx710"
    AARCH64_UNKNOWN_OPENBSD = "aarch64-unknown-openbsd"
    AARCH64_UNKNOWN_REDOX = "aarch64-unknown-redox"
    AARCH64_UNKNOWN_UEFI = "aarch64-unknown-uefi"
    AARCH64_UWP_WINDOWS_MSVC = "aarch64-uwp-windows-msvc"
    AARCH64_WRS_VXWORKS = "aarch64-wrs-vxworks"
    AARCH64_BE_UNKNOWN_LINUX_GNU = "aarch64_be-unknown-linux-gnu"
    AARCH64_BE_UNKNOWN_LINUX_GNU_ILP32 = "aarch64_be-unknown-linux-gnu_ilp32"
    ARM_LINUX_ANDROIDEABI = "arm-linux-androideabi"
    ARM_UNKNOWN_LINUX_GNUEABI = "arm-unknown-linux-gnueabi"
    ARM_UNKNOWN_LINUX_GNUEABIHF = "arm-unknown-linux-gnueabihf"
    ARM_UNKNOWN_LINUX_MUSLEABI = "arm-unknown-linux-musleabi"
    ARM_UNKNOWN_LINUX_MUSLEABIHF = "arm-unknown-linux-musleabihf"
    ARM64_32_APPLE_WATCHOS = "arm64_32-apple-watchos"
    ARMEB_UNKNOWN_LINUX_GNUEABI = "armeb-unknown-linux-gnueabi"
    ARMEBV7R_NONE_EABI = "armebv7r-none-eabi"
    ARMEBV7R_NONE_EABIHF = "armebv7r-none-eabihf"
    ARMV4T_NONE_EABI = "armv4t-none-eabi"
    ARMV4T_UNKNOWN_LINUX_GNUEABI = "armv4t-unknown-linux-gnueabi"
    ARMV5TE_NONE_EABI = "armv5te-none-eabi"
    ARMV5TE_UNKNOWN_LINUX_GNUEABI = "armv5te-unknown-linux-gnueabi"
    ARMV5TE_UNKNOWN_LINUX_MUSLEABI = "armv5te-unknown-linux-musleabi"
    ARMV5TE_UNKNOWN_LINUX_UCLIBCEABI = "armv5te-unknown-linux-uclibceabi"
    ARMV6_UNKNOWN_FREEBSD = "armv6-unknown-freebsd"
    ARMV6_UNKNOWN_NETBSD_EABIHF = "armv6-unknown-netbsd-eabihf"
    ARMV6K_NINTENDO_3DS = "armv6k-nintendo-3ds"
    ARMV7_APPLE_IOS = "armv7-apple-ios"
    ARMV7_LINUX_ANDROIDEABI = "armv7-linux-androideabi"
    ARMV7_SONY_VITA_NEWLIBEABIHF = "armv7-sony-vita-newlibeabihf"
    ARMV7_UNKNOWN_FREEBSD = "armv7-unknown-freebsd"
    ARMV7_UNKNOWN_LINUX_GNUEABI = "armv7-unknown-linux-gnueabi"
    ARMV7_UNKNOWN_LINUX_GNUEABIHF = "armv7-unknown-linux-gnueabihf"
    ARMV7_UNKNOWN_LINUX_MUSLEABI = "armv7-unknown-linux-musleabi"
    ARMV7_UNKNOWN_LINUX_MUSLEABIHF = "armv7-unknown-linux-musleabihf"
    ARMV7_UNKNOWN_LINUX_UCLIBCEABI = "armv7-unknown-linux-uclibceabi"
    ARMV7_UNKNOWN_LINUX_UCLIBCEABIHF = "armv7-unknown-linux-uclibceabihf"
    ARMV7_UNKNOWN_NETBSD_EABIHF = "armv7-unknown-netbsd-eabihf"
    ARMV7_WRS_VXWORKS_EABIHF = "armv7-wrs-vxworks-eabihf"
    ARMV7A_KMC_SOLID_ASP3_EABI = "armv7a-kmc-solid_asp3-eabi"
    ARMV7A_KMC_SOLID_ASP3_EABIHF = "armv7a-kmc-solid_asp3-eabihf"
    ARMV7A_NONE_EABI = "armv7a-none-eabi"
    ARMV7A_NONE_EABIHF = "armv7a-none-eabihf"
    ARMV7K_APPLE_WATCHOS = "armv7k-apple-watchos"
    ARMV7R_NONE_EABI = "armv7r-none-eabi"
    ARMV7R_NONE_EABIHF = "armv7r-none-eabihf"
    ARMV7S_APPLE_IOS = "armv7s-apple-ios"
    ASMJS_UNKNOWN_EMSCRIPTEN = "asmjs-unknown-emscripten"
    AVR_UNKNOWN_GNU_ATMEGA328 = "avr-unknown-gnu-atmega328"
    BPFEB_UNKNOWN_NONE = "bpfeb-unknown-none"
    BPFEL_UNKNOWN_NONE = "bpfel-unknown-none"
    HEXAGON_UNKNOWN_LINUX_MUSL = "hexagon-unknown-linux-musl"
    I386_APPLE_IOS = "i386-apple-ios"
    I586_PC_WINDOWS_MSVC = "i586-pc-windows-msvc"
    I586_UNKNOWN_LINUX_GNU = "i586-unknown-linux-gnu"
    I586_UNKNOWN_LINUX_MUSL = "i586-unknown-linux-musl"
    I686_APPLE_DARWIN = "i686-apple-darwin"
    I686_LINUX_ANDROID = "i686-linux-android"
    I686_PC_WINDOWS_GNU = "i686-pc-windows-gnu"
    I686_PC_WINDOWS_MSVC = "i686-pc-windows-msvc"
    I686_UNKNOWN_FREEBSD = "i686-unknown-freebsd"
    I686_UNKNOWN_HAIKU = "i686-unknown-haiku"
    I686_UNKNOWN_LINUX_GNU = "i686-unknown-linux-gnu"
    I686_UNKNOWN_LINUX_MUSL = "i686-unknown-linux-musl"
    I686_UNKNOWN_NETBSD = "i686-unknown-netbsd"
    I686_UNKNOWN_OPENBSD = "i686-unknown-openbsd"
    I686_UNKNOWN_UEFI = "i686-unknown-uefi"
    I686_UWP_WINDOWS_GNU = "i686-uwp-windows-gnu"
    I686_UWP_WINDOWS_MSVC = "i686-uwp-windows-msvc"
    I686_WRS_VXWORKS = "i686-wrs-vxworks"
    M68K_UNKNOWN_LINUX_GNU = "m68k-unknown-linux-gnu"
    MIPS_UNKNOWN_LINUX_GNU = "mips-unknown-linux-gnu"
    MIPS_UNKNOWN_LINUX_MUSL = "mips-unknown-linux-musl"
    MIPS_UNKNOWN_LINUX_UCLIBC = "mips-unknown-linux-uclibc"
    MIPS64_OPENWRT_LINUX_MUSL = "mips64-openwrt-linux-musl"
    MIPS64_UNKNOWN_LINUX_GNUABI64 = "mips64-unknown-linux-gnuabi64"
    MIPS64_UNKNOWN_LINUX_MUSLABI64 = "mips64-unknown-linux-muslabi64"
    MIPS64EL_UNKNOWN_LINUX_GNUABI64 = "mips64el-unknown-linux-gnuabi64"
    MIPS64EL_UNKNOWN_LINUX_MUSLABI64 = "mips64el-unknown-linux-muslabi64"
    MIPSEL_SONY_PSP = "mipsel-sony-psp"
    MIPSEL_SONY_PSX = "mipsel-sony-psx"
    MIPSEL_UNKNOWN_LINUX_GNU = "mipsel-unknown-linux-gnu"
    MIPSEL_UNKNOWN_LINUX_MUSL = "mipsel-unknown-linux-musl"
    MIPSEL_UNKNOWN_LINUX_UCLIBC = "mipsel-unknown-linux-uclibc"
    MIPSEL_UNKNOWN_NONE = "mipsel-unknown-none"
    MIPSISA32R6_UNKNOWN_LINUX_GNU = "mipsisa32r6-unknown-linux-gnu"
    MIPSISA32R6EL_UNKNOWN_LINUX_GNU = "mipsisa32r6el-unknown-linux-gnu"
    MIPSISA64R6_UNKNOWN_LINUX_GNUABI64 = "mipsisa64r6-unknown-linux-gnuabi64"
    MIPSISA64R6EL_UNKNOWN_LINUX_GNUABI64 = "mipsisa64r6el-unknown-linux-gnuabi64"
    MSP430_NONE_ELF = "msp430-none-elf"
    NVPTX64_NVIDIA_CUDA = "nvptx64-nvidia-cuda"
    POWERPC_UNKNOWN_FREEBSD = "powerpc-unknown-freebsd"
    POWERPC_UNKNOWN_LINUX_GNU = "powerpc-unknown-linux-gnu"
    POWERPC_UNKNOWN_LINUX_GNUSPE = "powerpc-unknown-linux-gnuspe"
    POWERPC_UNKNOWN_LINUX_MUSL = "powerpc-unknown-linux-musl"
    POWERPC_UNKNOWN_NETBSD = "powerpc-unknown-netbsd"
    POWERPC_UNKNOWN_OPENBSD = "powerpc-unknown-openbsd"
    POWERPC_WRS_VXWORKS = "powerpc-wrs-vxworks"
    POWERPC_WRS_VXWORKS_SPE = "powerpc-wrs-vxworks-spe"
    POWERPC64_IBM_AIX = "powerpc64-ibm-aix"
    POWERPC64_UNKNOWN_FREEBSD = "powerpc64-unknown-freebsd"
    POWERPC64_UNKNOWN_LINUX_GNU = "powerpc64-unknown-linux-gnu"
    POWERPC64_UNKNOWN_LINUX_MUSL = "powerpc64-unknown-linux-musl"
    POWERPC64_UNKNOWN_OPENBSD = "powerpc64-unknown-openbsd"
    POWERPC64_WRS_VXWORKS = "powerpc64-wrs-vxworks"
    POWERPC64LE_UNKNOWN_FREEBSD = "powerpc64le-unknown-freebsd"
    POWERPC64LE_UNKNOWN_LINUX_GNU = "powerpc64le-unknown-linux-gnu"
    POWERPC64LE_UNKNOWN_LINUX_MUSL = "powerpc64le-unknown-linux-musl"
    RISCV32GC_UNKNOWN_LINUX_GNU = "riscv32gc-unknown-linux-gnu"
    RISCV32GC_UNKNOWN_LINUX_MUSL = "riscv32gc-unknown-linux-musl"
    RISCV32I_UNKNOWN_NONE_ELF = "riscv32i-unknown-none-elf"
    RISCV32IM_UNKNOWN_NONE_ELF = "riscv32im-unknown-none-elf"
    RISCV32IMAC_UNKNOWN_NONE_ELF = "riscv32imac-unknown-none-elf"
    RISCV32IMAC_UNKNOWN_XOUS_ELF = "riscv32imac-unknown-xous-elf"
    RISCV32IMC_ESP_ESPIDF = "riscv32imc-esp-espidf"
    RISCV32IMC_UNKNOWN_NONE_ELF = "riscv32imc-unknown-none-elf"
    RISCV64GC_UNKNOWN_FREEBSD = "riscv64gc-unknown-freebsd"
    RISCV64GC_UNKNOWN_LINUX_GNU = "riscv64gc-unknown-linux-gnu"
    RISCV64GC_UNKNOWN_LINUX_MUSL = "riscv64gc-unknown-linux-musl"
    RISCV64GC_UNKNOWN_NONE_ELF = "riscv64gc-unknown-none-elf"
    RISCV64GC_UNKNOWN_OPENBSD = "riscv64gc-unknown-openbsd"
    RISCV64IMAC_UNKNOWN_NONE_ELF = "riscv64imac-unknown-none-elf"
    S390X_UNKNOWN_LINUX_GNU = "s390x-unknown-linux-gnu"
    S390X_UNKNOWN_LINUX_MUSL = "s390x-unknown-linux-musl"
    SPARC_UNKNOWN_LINUX_GNU = "sparc-unknown-linux-gnu"
    SPARC64_UNKNOWN_LINUX_GNU = "sparc64-unknown-linux-gnu"
    SPARC64_UNKNOWN_NETBSD = "sparc64-unknown-netbsd"
    SPARC64_UNKNOWN_OPENBSD = "sparc64-unknown-openbsd"
    SPARCV9_SUN_SOLARIS = "sparcv9-sun-solaris"
    THUMBV4T_NONE_EABI = "thumbv4t-none-eabi"
    THUMBV5TE_NONE_EABI = "thumbv5te-none-eabi"
    THUMBV6M_NONE_EABI = "thumbv6m-none-eabi"
    THUMBV7A_PC_WINDOWS_MSVC = "thumbv7a-pc-windows-msvc"
    THUMBV7A_UWP_WINDOWS_MSVC = "thumbv7a-uwp-windows-msvc"
    THUMBV7EM_NONE_EABI = "thumbv7em-none-eabi"
    THUMBV7EM_NONE_EABIHF = "thumbv7em-none-eabihf"
    THUMBV7M_NONE_EABI = "thumbv7m-none-eabi"
    THUMBV7NEON_LINUX_ANDROIDEABI = "thumbv7neon-linux-androideabi"
    THUMBV7NEON_UNKNOWN_LINUX_GNUEABIHF = "thumbv7neon-unknown-linux-gnueabihf"
    THUMBV7NEON_UNKNOWN_LINUX_MUSLEABIHF = "thumbv7neon-unknown-linux-musleabihf"
    THUMBV8M_BASE_NONE_EABI = "thumbv8m.base-none-eabi"
    THUMBV8M_MAIN_NONE_EABI = "thumbv8m.main-none-eabi"
    THUMBV8M_MAIN_NONE_EABIHF = "thumbv8m.main-none-eabihf"
    WASM32_UNKNOWN_EMSCRIPTEN = "wasm32-unknown-emscripten"
    WASM32_UNKNOWN_UNKNOWN = "wasm32-unknown-unknown"
    WASM32_WASI = "wasm32-wasi"
    WASM64_UNKNOWN_UNKNOWN = "wasm64-unknown-unknown"
    X86_64_APPLE_DARWIN = "x86_64-apple-darwin"
    X86_64_APPLE_IOS = "x86_64-apple-ios"
    X86_64_APPLE_IOS_MACABI = "x86_64-apple-ios-macabi"
    X86_64_APPLE_TVOS = "x86_64-apple-tvos"
    X86_64_APPLE_WATCHOS_SIM = "x86_64-apple-watchos-sim"
    X86_64_FORTANIX_UNKNOWN_SGX = "x86_64-fortanix-unknown-sgx"
    X86_64_FUCHSIA = "x86_64-fuchsia"
    X86_64_LINUX_ANDROID = "x86_64-linux-android"
    X86_64_PC_NTO_QNX710 = "x86_64-pc-nto-qnx710"
    X86_64_PC_SOLARIS = "x86_64-pc-solaris"
    X86_64_PC_WINDOWS_GNU = "x86_64-pc-windows-gnu"
    X86_64_PC_WINDOWS_GNULLVM = "x86_64-pc-windows-gnullvm"
    X86_64_PC_WINDOWS_MSVC = "x86_64-pc-windows-msvc"
    X86_64_SUN_SOLARIS = "x86_64-sun-solaris"
    X86_64_UNKNOWN_DRAGONFLY = "x86_64-unknown-dragonfly"
    X86_64_UNKNOWN_FREEBSD = "x86_64-unknown-freebsd"
    X86_64_UNKNOWN_FUCHSIA = "x86_64-unknown-fuchsia"
    X86_64_UNKNOWN_HAIKU = "x86_64-unknown-haiku"
    X86_64_UNKNOWN_HERMIT = "x86_64-unknown-hermit"
    X86_64_UNKNOWN_ILLUMOS = "x86_64-unknown-illumos"
    X86_64_UNKNOWN_L4RE_UCLIBC = "x86_64-unknown-l4re-uclibc"
    X86_64_UNKNOWN_LINUX_GNU = "x86_64-unknown-linux-gnu"
    X86_64_UNKNOWN_LINUX_GNUX32 = "x86_64-unknown-linux-gnux32"
    X86_64_UNKNOWN_LINUX_MUSL = "x86_64-unknown-linux-musl"
    X86_64_UNKNOWN_NETBSD = "x86_64-unknown-netbsd"
    X86_64_UNKNOWN_NONE = "x86_64-unknown-none"
    X86_64_UNKNOWN_OPENBSD = "x86_64-unknown-openbsd"
    X86_64_UNKNOWN_REDOX = "x86_64-unknown-redox"
    X86_64_UNKNOWN_UEFI = "x86_64-unknown-uefi"
    X86_64_UWP_WINDOWS_GNU = "x86_64-uwp-windows-gnu"
    X86_64_UWP_WINDOWS_MSVC = "x86_64-uwp-windows-msvc"
    X86_64_WRS_VXWORKS = "x86_64-wrs-vxworks"


