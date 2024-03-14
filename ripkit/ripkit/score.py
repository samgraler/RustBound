sys.path.append (
    str(ripkit_dir)
)
import numpy as np
from pathlib import Path
from ripkit.ripbin import (
    lief_gnd_truth,
    FoundFunctions,
    ConfusionMatrix,
    calc_metrics,
    save_raw_experiment,
    #get_functions,
    #new_file_super_careful_callback,
    new_file_callback,
    #must_be_file_callback,
    iterable_path_shallow_callback,
    iterable_path_deep_callback,
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

    return gnd_matrix



def score_file(gnd_truth, prediction):
    '''
    Given Gnd turth and prediction, score the prediction
    '''

    total_start_conf = ConfusionMatrix(0,0,0,0)
    total_bound_conf = ConfusionMatrix(0,0,0,0)
    total_bytes = 0

    # Init the confusion matrix for this bin
    start_conf = ConfusionMatrix(0,0,0,0)
    bound_conf = ConfusionMatrix(0,0,0,0)

    # 4 - Mask the array so we only include bytes in .text
    mask_max = (ida_funcs[:,0] <= np.max(gnd_truth.func_addrs))
    ida_funcs = ida_funcs[mask_max]

    mask_min = (ida_funcs[:,0] >= np.min(gnd_truth.func_addrs))
    filt_ida_funcs = ida_funcs[mask_min]


    # 3 - Compare the two lists
    # Get all the start addrs that are in both, in ida only, in gnd_trush only
    start_conf.tp=len(np.intersect1d(gnd_matrix[:,0], filt_ida_funcs[:,0]))
    start_conf.fp=len(np.setdiff1d( filt_ida_funcs[:,0], gnd_matrix[:,0] ))
    start_conf.fn=len(np.setdiff1d(gnd_matrix[:,0], filt_ida_funcs[:,0]))


    # tp + fp = Total predicted
    if not start_conf.tp + start_conf.fp == filt_ida_funcs.shape[0]:
        print(f"{start_conf.tp}")
        print(f"{start_conf.fp}")
        print(f"{filt_ida_funcs.shape[0]}")
        raise Exception

    # tp + fn = total pos
    if not start_conf.tp + start_conf.fn == gnd_matrix.shape[0]:
        print(f"{start_conf.fp}")
        print(f"{start_conf.fn}")
        print(f"{filt_ida_funcs.shape[0]}")
        raise Exception


    bound_conf.tp = np.count_nonzero(np.all(np.isin(filt_ida_funcs, gnd_matrix),axis=1))
    bound_conf.fp = filt_ida_funcs.shape[0] - bound_conf.tp
    bound_conf.fn = gnd_matrix.shape[0] - bound_conf.tp


    ## The below is the test of an old code implementation 

    # Check the predicted bounds for correctness
    #for row in filt_offset_funcs:
    #    if np.any(np.all(row == gnd_matrix, axis=1)): 
    #        bound_conf.tp+=1
    #    else:
    #        bound_conf.fp+=1

    ## Check to see how many false negative there were 
    #for row in gnd_matrix:
    #    if not np.any(np.all(row == filt_offset_funcs, axis=1)):
    #        bound_conf.fn+=1



    ## The above is a test of an old code implementation ^^



    #TODO: Is the below equivalent to the top?
    # Check the predicted bounds for correctness
    #for row in filt_ida_funcs:
    #    if np.any(np.all(row == gnd_matrix, axis=1)): 
    #        bound_conf.tp+=1
    #    else:
    #        bound_conf.fp+=1

    ## Check to see how many false negative there were 
    #for row in gnd_matrix:
    #    if not np.any(np.all(row == filt_ida_funcs, axis=1)):
    #        bound_conf.fn+=1

    total_bytes += gnd_truth.num_bytes

    total_start_conf.tp += start_conf.tp
    total_start_conf.fp += start_conf.fp
    total_start_conf.fn += start_conf.fn

    total_bound_conf.tp += bound_conf.tp
    total_bound_conf.fp += bound_conf.fp
    total_bound_conf.fn += bound_conf.fn

    if verbose:
        print(f"binary: {bin.name}")
        print(f"Starts: {start_conf}")
        print(f"Starts Metrics: {calc_metrics(start_conf)}")
        print(f"Bounds Metrics: {calc_metrics(bound_conf)}")

    print(f"Start conf: {total_start_conf}")
    print(f"Starts Metrics: {calc_metrics(total_start_conf)}")
    print(f"Bound conf: {total_bound_conf}")
    print(f"Bounds Metrics: {calc_metrics(total_bound_conf)}")
    return 


