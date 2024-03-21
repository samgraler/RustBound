'''
Moving the functionality of scoring Ghidra and IDA to here so that I 
never again have two implementations for the same thing... that end up 
not being the same :)) 

Later will see about scoring NN here too 
'''


import numpy as np
import sys
from pathlib import Path
from ripkit.ripbin import (
    lief_gnd_truth,
    ConfusionMatrix,
)
ripkit_dir = Path("../ripkit").resolve()
sys.path.append (
    str(ripkit_dir)
)

def get_address_len_gnd(bin:Path):
    '''
    Given an unstripped input binary, generate the 
    gnd truth matrix with addresses and lengths as column
    '''
    # 1  - Ground truth for bin file, func addr, len
    gnd_truth = lief_gnd_truth(bin.resolve())

    gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                                    gnd_truth.func_lens.T.reshape(-1,1)), axis=1)

    return gnd_truth, gnd_matrix

def gnd_truth_start_plus_len(bin:Path):
    '''
    Generate the ground truth for the givne binary file
    '''

    # Load the groud truth from lief 
    gnd_truth = lief_gnd_truth(bin.resolve())

    # Reshape the ground truth so that we have a matrix with 2 columns:
    #   | start_addr | func_len |
    #     .. ...     | .. ...
    gnd = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                            gnd_truth.func_lens.T.reshape(-1,1)), axis=1)
    return gnd_truth, gnd



def find_offset(lief_addrs, ghidra_addrs):
    '''
    Ghidra adds an offset to it's addrs, this function 
    finds that offset
    '''

    # The idea here is to...
    # 1. Find the space (in bytes) between all the functions 
    # 2. Make a list of tuples of:
    #       (function_start_address, bytes_til_next_function)

    # Once we have this we can try to "slide" the function 
    #  addresses until the two lists of bytes_til_next match

    ghid_addr_bnext =  append_bnext(ghidra_addrs)
    lief_addrs =  append_bnext(lief_addrs)

    offset = 0
    found_offset = False
    for _, (addr, btnext) in enumerate(lief_addrs):
        if found_offset:
            break
        for _, (ghid_addr, ghid_btnext) in enumerate(ghid_addr_bnext):
            if found_offset:
                break
            if ghid_btnext == btnext:
                offset = ghid_addr - addr
                return offset
    return offset

def append_bnext(inp_list):
    """
    given a list integers, calculate the distane 
    until the next integer. 

    Make a tuple of (integer, till_next_int)
    """

    new_list = []

    # Generate a list of addrs and the # bytes till the next addr
    for i, fun in enumerate(inp_list):
        if i < len(inp_list) - 1:
            to_next = int(inp_list[i+1]) - int(inp_list[i])
        else:
            to_next = 0
        new_list.append((fun, to_next))

    return new_list


def load_ida_prediction(prediction_file: Path)->np.ndarray:
    '''
    Load the IDA npz file
    '''
    return load_npz(prediction_file)

# TODO: Is an npz really less size than npy is there's 
#       only one array?
def load_npz(inp: Path)->np.ndarray:
    '''
    Read the npz, expected to have a single file
    '''
    npz_file = np.load(inp)
    return npz_file[list(npz_file.keys())[0]].astype(int)


def load_ghidra_prediction(prediction_file: Path, gnd: np.ndarray)->np.ndarray:
    '''
    Load the Ghidra npz file
    '''

    # 1 - Load the file
    prediction = load_npz(prediction_file)

    # 3 - Apply the offset to the ghidra funcs
    offset = find_offset(sorted(gnd[:,0].tolist()), 
                             sorted((prediction[:,0].tolist())))

    # Apply the offset to all of the addresses
    prediction[:,0] += offset
    return prediction


def score_start_plus_len(gnd: np.ndarray, prediction: np.ndarray, 
                         min_addr: int, 
                         max_addr: int)-> tuple[ConfusionMatrix,ConfusionMatrix,ConfusionMatrix]:
    '''
    Score prediction NPY and NPZ of the given file
    '''

    start_conf = ConfusionMatrix(0,0,0,0)
    end_conf = ConfusionMatrix(0,0,0,0)
    bound_conf = ConfusionMatrix(0,0,0,0)

    # 1. Mask the prediction array so that we only consider functions in the 
    #       .text section
    # TODO: The below line using the min and max addr of the text section.
    #       Using the below line:
    #           - tp decrease 
    #           - fp increase
    #           - fn increase
    #       FN should not have increased
    #       TP should not have decreased
    #       FP increasing makes sense
    #       With TP inc and TP decreaing I suspect that the min and max addrs
    #       are slighlty incorrect -- I will stick with np.max and min for now
    #       There is a marginal difference in the final values for a testset
    #       of roughly 200 files (0.0001 difference of F1) 
    #
    #mask = ((prediction[:,0]  < max_addr) & (prediction[:,0] >  min_addr))
    #
    # Create the mask
    mask = ((prediction[:,0]  <= np.max(gnd[:,0])) & 
            (prediction[:,0] >=  np.min(gnd[:,0])))
    #print(f"Mask uses min {np.min(gnd[:,0])} and max {np.max(gnd[:,0])}")

    # Apply the mask
    filt_prediction = prediction[mask]

    # 3 - Compare the two lists

    # 3.1 - Function start stats
    start_conf.tp=len(np.intersect1d(gnd[:,0], filt_prediction[:,0]))
    start_conf.fp = filt_prediction.shape[0] - start_conf.tp
    start_conf.fn = gnd.shape[0] - start_conf.tp

    # 3.2 - Function end stats
    # -- For ghidra and IDA, we do not predict ends. Rather lengths.
    # -- Therefore, see if start+len is in ends
    pred_end_addresses = filt_prediction[:,0]  + filt_prediction[:,1]
    gnd_end_addresses = gnd[:,0]  + gnd[:,1]

    end_conf.tp = len(np.intersect1d(gnd_end_addresses, pred_end_addresses))
    end_conf.fp = pred_end_addresses.shape[0] - end_conf.tp
    end_conf.fn = gnd_end_addresses.shape[0] - end_conf.tp

    # 3.3 - Function bounds stats
    # Check the predicted bounds for correctness
    # FP = Total number of functions in pred - tp
    # FN = Total number of functions in ground - tp
    for row in filt_prediction:
        if np.any(np.all(row == gnd, axis=1)): 
            bound_conf.tp+=1
    bound_conf.fp = filt_prediction.shape[0] - bound_conf.tp
    bound_conf.fn = gnd.shape[0] - bound_conf.tp

    return start_conf, end_conf, bound_conf
