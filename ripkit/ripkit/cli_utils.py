from enum import Enum
from ripkit.cargo_picky import RustcOptimization


class CallBackException(Exception):
    def __init__(self, message="Exception building crate"):
        self.message = message
        super().__init__(self.message)


def opt_lvl_callback(opt_lvl):
    opt_lvl = opt_lvl.lower()
    if opt_lvl in ["o0", "0"]:
        opt = RustcOptimization.O0
    elif opt_lvl in ["o1", "1"]:
        opt = RustcOptimization.O1
    elif opt_lvl in ["o2", "3"]:
        opt = RustcOptimization.O2
    elif opt_lvl in ["o3", "3"]:
        opt = RustcOptimization.O3
    elif opt_lvl in ["oz", "z"]:
        opt = RustcOptimization.OZ
    elif opt_lvl in ["os", "s"]:
        opt = RustcOptimization.OS
    else:
        raise CallBackException("{} is an invalid optimization lvl".format(opt_lvl))
    return opt


def get_enum_type(enum, input_string) -> Enum:
    try:
        return enum(input_string)
    except Exception:
        raise ValueError(f"No matching enum type for the string '{input_string}'")
