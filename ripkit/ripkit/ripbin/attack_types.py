from enum import Enum

class CompileTimeAttacks(Enum):
    '''
    Compile time attack names and there flags
    '''
    fpath4 = "-C -fpatchable-function-entry=4"
    link_time_opts = "-C lto -C embed-bitcode=yes"

