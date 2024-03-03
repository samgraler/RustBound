from pathlib import Path 
import itertools
import shutil
import subprocess
import time
import random
import json
from typing import List, Generator
from typing_extensions import Annotated
from fairseq.models.roberta import RobertaModel
import torch
import sys
import lief 
from elftools.elf.elffile import ELFFile
from dataclasses import dataclass
from colorama import Fore, Back, Style
import numpy as np
from alive_progress import alive_it
from ripkit.ripbin import ( 
    ConfusionMatrix,
    calc_metrics,
    save_raw_experiment_three_prob,
    lief_gnd_truth,
)
import time
import typer 
import rich
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)

@dataclass 
class FunctionInfo():
    name: str
    addr: int
    addrHex: str
    size: int



def get_elf_functions(path:Path, warn_if_stripped: bool = False)->List[FunctionInfo]:
    """
        Get the functions in an ELF file. 
        NOTICE: elffile seems to ignore functions injected by gcc such as 
        "register_tm...", "deregister_tm...", 
        Therefore those names will be included in the list, but will have 
        a size of 0 
    """

    with open(path, 'rb') as f:
        elf = ELFFile(f)

        # Get the symbol table
        symbol_table = elf.get_section_by_name('.symtab')

        # Get the .text section
        text_section = elf.get_section_by_name('.text')

        if symbol_table is None:
            raise Exception(f"No symbol table in file {path}")
        elif text_section is None:
            raise Exception(f"No .text section in file {path}")

        # Create a list of functionInfo objects... symbol_table will give a 
        # list of symbols, grab the function sybols and get there name, 
        # their 'st_value' which is start addr and size 
        functionInfo = [FunctionInfo(x.name, x['st_value'], f"0x{x['st_value']:x}",x['st_size']) 
            for x in symbol_table.iter_symbols() if x['st_info']['type'] == 'STT_FUNC']

        if functionInfo == [] and warn_if_stripped:
            # TODO: This warning wont make sense when someone is analyzing an 
            #   file without knowing if its stripped or not, maybe take out?
            warnings.warn("There is no function info, and expect stripped is off")

    return functionInfo


def get_hex_str(inp):
    hex_str = f"{str(hex(inp))[2:]}"
    if len(hex_str) == 1:
        hex_str= "0" + hex_str
    return hex_str


# Load the binary and 
def gen_data_raw_func_bound(path: Path, output: Path):
    #TODO: Use lief to get the .text section of the binary and but here 
    #      (... or is it use lief to get every byte from the file and put here?...)

    functions = get_elf_functions(path)

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    func_end_addrs = {} 
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start+info[1]] = info[0]


    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    with open(output, 'w') as out:
        for i, byte in enumerate(text_bytes):

            # Starting at the text section, the address of each byte is 
            # the base_address + the text_section's virtual address 
            # plus the number of bytes we've gone over 
            address = base_address + text_section.virtual_address + i
            func_start = True if address in func_start_addrs.keys() else False
            func_end = True if address in func_end_addrs.keys() else False
            func_middle = True if not func_start and not func_end else False

            if func_start:
                lbl = 'F'
            elif func_end:
                lbl= 'R'
            else:
                lbl = '-'

            hex_str = get_hex_str(address)
            #line = f"{hex_str} {lbl}"
            line = f"{byte} {lbl}"

            #print(line)
            out.write(line+'\n')

    print("WARNING THIS ONLY HAS THE .TEXT section")
    return

def get_start_and_end_addrs(bin):

    functions = get_elf_functions(bin)

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    func_end_addrs = {} 
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start+info[1]] = info[0]

    return func_start_addrs, func_end_addrs



def load_bin_for_xda_inp(path: Path):
    '''
    Generate npy matrix with vectors:
        <isStart, isMiddle, isEnd, byte>
    '''
    functions = get_elf_functions(path)

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    func_end_addrs = {} 
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start+info[1]] = info[0]


    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    for i, byte in enumerate(text_bytes):
        address = base_address + text_section.virtual_address + i
        if address in func_start_addrs.keys():
            lbl = 'S'
        elif address in func_end_addrs.keys():
            lbl = 'E'
        else:
            lbl = 'N'
        yield [str(byte), lbl]

def xda_predict_raw(bin: Path, model): #-> Generator[tuple[np.ndarray,float], None, None]:
    '''
    Predict all the bytes in the .text section of the binary model
    '''
    # Parse the bin 
    parsed_bin = lief.parse(str(bin.resolve()))

    #TODO: Get the text section contents
    text_bytes = parsed_bin.get_section(".text").content

    #TODO: Make sure contents are bytes wihtout 0x
    text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

    STEP = 512
    total_time = 0
    total_res = np.zeros((int(len(text_bytes)/STEP)+1 , 512,3))
    loop_counter = 0

    #for i in alive_it(range(0, len(text_bytes)-STEP-1, STEP)):
    for i in range(0, len(text_bytes)-STEP-1, STEP):
        loop_counter+=1

        # Get the total chunnk, and the labeled chunk 
        token_chunk = text_bytes[i:i+STEP]

        # Make a sting of 512 tokens
        encoded_tokens = model.encode(' '.join(token_chunk))

        # Get the prediction
        start = time.time()
        logprobs = model.predict('funcbound', encoded_tokens)
        total_time += time.time() - start

        total_res[loop_counter] = logprobs.detach().cpu().numpy()
        #cur_res = logprobs.detach().cpu().numpy()
        #yield cur_res, total_time
    return total_res,total_time

        # The following line will decide what classification the byte is
        #predictions = logprobs.argmax(dim=2).view(-1).data
    #return total_res, total_time

def xda_predict(inp_file: Path, model, out_file:Path = None):

    token_gen = load_bin_for_xda_inp(inp_file)
    token_list = list(token_gen)


    # inp and lbl
    token_raw = [x[0] for x in token_list]
    token_inp = []
    for x in token_raw:
        repr =  str(hex(int(x))[2:])
        if len(repr) == 1:
            repr = '0' + repr
        token_inp.append(repr)
    token_lbl = [x[1] for x in token_list]

    STEP = 512
    START = 1 
    END = 2 
    NEITHER = 0
    true_pos = 0
    true_neg = 0
    false_pos = 0
    false_neg = 0

    total_time = 0

    # Open the log file so that we can freely write to it
    with open(out_file, 'w') as out_f:
        for i in alive_it(range(0, len(token_inp)-STEP-1, STEP)):

            # Get the total chunnk, and the labeled chunk 
            token_chunk = token_inp[i:i+STEP]
            lbl_chunk = token_lbl[i:i+STEP]

            # Make a sting of 512 tokens
            encoded_tokens = model.encode(' '.join(token_chunk))

            # Get the prediction
            start = time.time()
            logprobs = model.predict('funcbound', encoded_tokens)
            total_time += time.time() - start
            predictions = logprobs.argmax(dim=2).view(-1).data


            # TODO: numpy should be used evenutally for this comparison
            # Iterate over the bytes and the predicted label see if 
            # labels are correct
            for i, (raw_byte, prediction, lbl) in enumerate(
                zip(token_chunk, predictions, lbl_chunk)):

                #TODO: right now I only care about its ability to 
                # label function starts

                # Check for true and false positives
                if prediction == START:
                    if lbl == 'S':
                        true_pos +=1 
                    else:
                        false_pos +=1 
                if prediction == END or prediction == NEITHER:
                    if lbl != 'S' :
                        true_neg +=1 
                    else:
                        false_neg +=1 
                out_f.write(f"{raw_byte} {prediction} {lbl}\n")


    return true_pos, false_pos, true_neg, false_neg, total_time


@app.command()
def unified_gen_training(
    num_pretrain: Annotated[int, typer.Argument()],
    num_finetune: Annotated[int, typer.Argument()],
    num_valid: Annotated[int, typer.Argument()],
    base_path: Annotated[str, typer.Argument()],
    ):
    '''
    For each pretraining dataset used in other experiemnts, pick x binaries.
    For each finetuning dataset used in other expriments, pick y binaries 

    Pretraining requires a minimum of 4 bins for pre training 
    '''

    # TODO warnings

    #dataset_bins = Path("../datasets/20_file_subset/")
    #if not dataset_bins.exists():
    #    print("Dataset does not exist")
    #    return 
    #
    #pretrain_tot = []
    #valid_tot = []
    #finetune_tot = []

    #for subset in dataset_bins.iterdir():
    #    # 9 files in the subset goes to pretrain
    #    # 1 file goes to validation 
    #    # 10 files go to fintune 
    #    subset_files = list(subset.glob('*'))
    #    pretrain_tot.extend(subset_files[:9])
    #    valid_tot.append(subset_files[9])
    #    finetune_tot.extend(subset_files[10:])

    #generate_data_src_pretrain_all(pretrain_tot, valid_tot)
    #generate_data_src_finetune_for_funcbound(finetune_tot)
    #print("Ready to train new model...")

    # TODO: Hardcoded
    # Go to each of the previously used dataset, and pick bins

    # Store the bins
    pretrain_dict = {}
    finetune_dict = {}

    # All pretrain, valid,finetune
    pretrain_tot = []
    finetune_tot = []
    valid_tot = []

    base_path = Path(base_path)

    base_saved = Path("unified_sampled_bins")
    base_saved.mkdir()

    for dir in base_path.iterdir():
        pretrain = dir / Path("dataset_pretrain")
        finetune = dir / Path("dataset_finetune")

        pretrain_and_valid = random.sample(list(pretrain.glob('*')), num_pretrain+num_valid)

        pretrain_bins = pretrain_and_valid[0:num_pretrain]
        valid_bins = pretrain_and_valid[-num_valid:]

        for bin in pretrain_bins:
            pretrain_tot.append(bin)
        pretrain_dict[dir] = pretrain_bins

        finetune_bins = random.sample(list(finetune.glob('*')), num_finetune)
        for bin in finetune_bins:
            finetune_tot.append(bin)
        finetune_dict[dir] = finetune_bins

        #bins_for_valid = [ x for x in list(pretrain.glob('*')) if x not in pretrain_bins]
        #valid_bins = random.sample(bins_for_valid, num_valid)

        for bin in valid_bins:
            valid_tot.append(bin)
        finetune_dict[f"VALID_{dir}"] = valid_bins

        # Copy the bins for pretrain, finetune, and pretrain_valid all to one ouputdir
        opt_dir = base_saved / dir.name
        opt_dir.mkdir()

    # so that BiRNN can be trained on the same sample


    print(f"Pretain: {pretrain_tot}")
    print(f"Finetuen: {finetune_tot}")
    generate_data_src_pretrain_all(pretrain_tot, valid_tot)
    generate_data_src_finetune_for_funcbound(finetune_tot)

    return

@app.command()
def gen_pretrain_data(
        bin_dir: Annotated[str, typer.Argument()],
        num_validation_bins: Annotated[int, typer.Argument()],
    ):

    bins_path = Path(bin_dir)
    if not bins_path.exists():
        print(f"Bin path {bins_path} does not exist")
        return

    bins_list = list(bins_path.rglob('*'))

    # Get random valudation bins, default to 4 of them 
    valid = random.sample(bins_list, num_validation_bins)
    bins_path = [x for x in bins_list if x not in valid]

    generate_data_src_pretrain_all(bins_list, valid)

    return

def generate_data_src_pretrain_all(train_bins, validation_bins):
    '''
    For pretraining on our own data, concatenate all bytes from 
    all binaries and delimit by a newline so that each line does 
    not exceed what the model expects.

    What the model expects by default seems to be 512 so Im going to 
    follow that convention

    and 4 binaries were used for validation in valid.in

    No label, just bytes

    data-src/pretrain-all/train.in
    data-src/pretrain-all/valid.in
    '''

    train_path = Path("data-src/pretrain_all/train.in")
    valid_path = Path("data-src/pretrain_all/valid.in")
    train_files = train_bins
    valid_files = validation_bins

    with open(train_path, 'w') as f:
        for file in train_files:
            # Parse the bin 
            parsed_bin = lief.parse(str(file.resolve()))

            #TODO: Get the text section contents
            text_bytes = parsed_bin.get_section(".text").content

            #TODO: Make sure contents are bytes wihtout 0x
            text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

            #TODO: Write chunks of 512 to the file 
            for i in range(0,len(text_bytes)-512-1, 512):
                f.write(" ".join(text_bytes[i:i+512]) + "\n")

    with open(valid_path, 'w') as f:
        for file in valid_files:
            # Parse the bin 
            parsed_bin = lief.parse(str(file.resolve()))

            #TODO: Get the text section contents
            text_bytes = parsed_bin.get_section(".text").content

            #TODO: Make sure contents are bytes wihtout 0x
            text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

            #TODO: Write chunks of 512 to the file 
            for i in range(0,len(text_bytes)-512-1, 512):
                f.write(" ".join(text_bytes[i:i+512]) + "\n")
    
    print("Run ./scripts/pretrain/preprocess-pretrain-all.sh to put data in the data-bin/pretrain_all [REQUIRED]")
    return

def generate_data_src_finetune_for_funcbound(list_of_paths):
    '''
    S = Start
    E = End
    N = Neither

    train.data  : bytes from files concatenated
    train.label : labels for each bytes in data 
    '''

    train_data = Path("data-src/funcbound/train.data")
    train_lbl = Path("data-src/funcbound/train.label")

    valid_data = Path("data-src/funcbound/valid.data")
    valid_lbl = Path("data-src/funcbound/valid.label")

    train_files = list_of_paths[:-4]
    valid_files = list_of_paths[-4:]

    with open(train_data, 'w') as f:
        with open(train_lbl, 'w') as lbl_f:
            for file in train_files:


                functions = get_elf_functions(file)

                func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

                func_end_addrs = {} 
                for start, info in func_start_addrs.items():
                    # NOTE: THIS IS IMPORTANT
                    # Ignoring functions that are of zero length
                    if info[1] > 0:
                        func_end_addrs[start+info[1]] = info[0]


                # Parse the bin 
                parsed_bin = lief.parse(str(file.resolve()))

                text_section = parsed_bin.get_section(".text")

                #TODO: Get the text section contents
                text_bytes = text_section.content

                #TODO: Make sure contents are bytes wihtout 0x
                text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

                # Get the base address of the loaded binary
                base_address = parsed_bin.imagebase

                #TODO: Write chunks of 512 to the file 
                for i in range(0,len(text_bytes)-512-1, 512):
                    chunk_base_address = base_address + text_section.virtual_address + i
                    #func_start = True if address in func_start_addrs.keys() else False
                    #func_end = True if address in func_end_addrs.keys() else False
                    #func_middle = True if not func_start and not func_end else False

                    lbls = []
                    for lbl_offset in range(512):
                        if chunk_base_address + lbl_offset in func_start_addrs.keys():
                            lbls.append("S")
                        elif chunk_base_address + lbl_offset in func_end_addrs.keys():
                            lbls.append("E")
                        else:
                            lbls.append("N")


                    f.write(" ".join(text_bytes[i:i+512]) + "\n")
                    lbl_f.write(" ".join(lbls) + "\n")


    with open(valid_data, 'w') as f:
        with open(valid_lbl, 'w') as lbl_f:
            for file in valid_files:


                functions = get_elf_functions(file)

                func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

                func_end_addrs = {} 
                for start, info in func_start_addrs.items():
                    # NOTE: THIS IS IMPORTANT
                    # Ignoring functions that are of zero length
                    if info[1] > 0:
                        func_end_addrs[start+info[1]] = info[0]


                # Parse the bin 
                parsed_bin = lief.parse(str(file.resolve()))

                text_section = parsed_bin.get_section(".text")

                #TODO: Get the text section contents
                text_bytes = text_section.content

                #TODO: Make sure contents are bytes wihtout 0x
                text_bytes = [f"{get_hex_str(x)}" for x in text_bytes] 

                # Get the base address of the loaded binary
                base_address = parsed_bin.imagebase

                #TODO: Write chunks of 512 to the file 
                for i in range(0,len(text_bytes)-512-1, 512):
                    chunk_base_address = base_address + text_section.virtual_address + i
                    #func_start = True if address in func_start_addrs.keys() else False
                    #func_end = True if address in func_end_addrs.keys() else False
                    #func_middle = True if not func_start and not func_end else False

                    lbls = []
                    for lbl_offset in range(512):
                        if chunk_base_address + lbl_offset in func_start_addrs.keys():
                            lbls.append("S")
                        elif chunk_base_address + lbl_offset in func_end_addrs.keys():
                            lbls.append("E")
                        else:
                            lbls.append("N")


                    f.write(" ".join(text_bytes[i:i+512]) + "\n")
                    lbl_f.write(" ".join(lbls) + "\n")


    print("Run ./scripts/finetune/preprocess.sh to put data in the data-bin/funcbound [REQUIRED]")
    return 


def xda_experiment(pretrain_bins, finetune_bins, test_bins):


    # In the paper they used whole dataset for pretraining (b/c they had 3)
    #   and 4 binaries were used for validation
    #pretrain_files = []

    # Used 10% of a whole dataset for finetuning 
    #finetune_files = []

    # Used the whole third dataset for testing
    #test_files = []


    # For each binary in pretrain_bins, the contents need to all be concatenated and 
    # put into "data-src/pretain/train.in  generate_data_src_pretrain_all
    generate_data_src_pretrain_all(pretrain_bins)

    # Need to run ./scripts/pretrain/preprocess-pretrain-all.sh to put data in data-bin/pretrain_all
    # Popen.call([ " ./scripts/pretrain/preprocess-pretrain-all.sh])
    # TODO: When does the above process terminate 

    # For each file in finetune_files need to concatenate all bytes, and genarete a train and label file
    generate_data_src_finetune_for_funcbound(finetune_bins)

    # Need to run "Run ./scripts/finetune/preprocess.sh to put data in the data-bin/funcbound [REQUIRED]")
    # Popen.call(["./scripts/finetune/preprocess.sh" ])
    # TODO: When does the above process terminate 

    # For each file in the test file I need to run a test experiemnt

    




    return

def read_saved(path_in):

    # tp, tn, fp, fn
    res = []

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    with open(path_in, 'r') as f:
        for line in f:
            _, prediction, lbl = line.split(" ")
            lbl = lbl.strip()
            prediction = int(prediction.strip())

            if prediction == 1 :
                if lbl == 'S':
                    tp+=1
                else:
                    fp+=1

            elif prediction != 0:
                if lbl != 'S':
                    tn+=1
                else:
                    fn +=1

    return [tp,fp,tn,fn]



#def save_raw_results(binary:Path, out_dir:Path, predictions: np.ndarray, runtime:float)->None:
#    '''
#    Save the results to a npz file and save the time to runtime.txt
#
#    Save path structure
#    out_dir
#    |
#    | binary.name
#    |     |
#    |     | {binary.name_result}.npz
#    |     | runtime.txt
#    '''
#
#    if not out_dir.exists():
#        out_dir.mkdir()
#    elif out_dir.exists() and out_dir.is_file():
#        raise Exception
#
#    # Make the new binary dir
#    result_path = out_dir.joinpath(f"{binary.name}")
#    if result_path.exists():
#        raise Exception
#    result_path.mkdir()
#
#    # Save the data 
#    npz_file = result_path / f"{binary.name}_result.npz"
#    np.savez_compressed(npz_file, predictions)
#
#    # save the runtime
#    runtime_path = result_path / "runtime.txt"
#    with open(runtime_path, 'w') as f:
#        f.write(f"{runtime}")
#
#    return

# TODO: Save results on a per file basis 
def save_results_timed(res, out_file:Path):
    '''
    Save the .text file and a corresponding file with 
    the count(tp), count(tn), count(fp), count(fn), runtime
    '''
        # print(f"TP: {res[0]}")
        # print(f"FP: {res[1]}")
        # print(f"TN: {res[2]}")
        # print(f"FN: {res[3]}")
        # print(f"Runtime {res[4]")

    data = {
        'tp' : res[0],
        'fp' : res[1],
        'tn' : res[2],
        'fn' : res[3], 
        'runtime' : res[4],
    }

    with open(out_file, 'w') as f:
        json.dump(data, f)

    return

@dataclass
class ConfMatrix:
    tp: int
    fp: int
    tn: int
    fn: int

def xda_predict_many(inp_files, model, out_dir, save_results=False, use_saved=True):
    tot_tp = 0
    tot_tn = 0
    tot_fp = 0
    tot_fn = 0

    confusion_matrix = ConfMatrix(0,0,0,0)

    for i, file_to_predict in enumerate(inp_files):
        print(f"File {i} of {len(inp_files)}")
        if not file_to_predict.exists():
            print(f"Bad file {file_to_predict}")
            continue

        # See if the cached result exists 
        saved = out_dir / f"{file_to_predict.name}"
        time_dir = Path(f"{out_dir}_TIMES")

        if not time_dir.exists():
            time_dir.mkdir()
        time_file = time_dir.resolve() / f"{file_to_predict.name}_time"

        not_good_res = False
        if saved.exists():
            res = read_saved(saved)
            if len(res) < 5:
                not_good_res = True

        if not saved.exists() or not_good_res:
            if save_results:
                res = xda_predict(file_to_predict, model, 
                                  saved)
                save_results_timed(res, time_file)
            else:
                res = xda_predict(file_to_predict, model)

        print(f"File {file_to_predict.name} results...")
        print(f"TP: {res[0]}")
        print(f"FP: {res[1]}")
        print(f"TN: {res[2]}")
        print(f"FN: {res[3]}")
        print(f"Runtime: {res[4]}")
        

        confusion_matrix.tp += res[0]
        confusion_matrix.tn += res[1]
        confusion_matrix.fp += res[2]
        confusion_matrix.fn += res[3]

        #tot_tp += res[0]
        #tot_tn += res[2]
        #tot_fp += res[1]
        #tot_fn += res[3]
        print("Running totals:")
        print(f"TP: {confusion_matrix.tp}")
        print(f"TN: {confusion_matrix.tn}")
        print(f"FP: {confusion_matrix.fp}")
        print(f"FN: {confusion_matrix.fn}")


    return tot_tp, tot_tn, tot_fp, tot_fn


def gen_strip_file(bin_path:Path):
    '''
    Strip the passed file and return the path of the 
    stripped file
    '''

    # Copy the bin and strip it 
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        _ = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return Path("")

    return strip_bin





@app.command()
def read_log(
    bin_dir: Annotated[str, typer.Argument()],
    res_dir: Annotated[str, typer.Argument()],
    ):
    '''
    Read the timed XDA logs 
    '''
    res = {
        'tp' : 0,
        'fp' : 0,
        'tn' : 0,
        'fn' : 0,
        'stripped_size':0,
        'size':0,
    }


    files = []
    for file in Path(res_dir).rglob('*'):
        for bin in Path(bin_dir).rglob('*'):
            if bin.name.lower() in file.name.lower():
                files.append((file,bin))
                continue
        #if file.name.lower() in x.name.lower() for x in Path(bin_dir).rglob('*')):
            #files.append(file)


    tot_runtime = 0
    for (file,bin) in files:
        # read as json, get runtime key
        key = 'runtime'
        with open(file, 'r') as f:
            data = json.load(f)
        tot_runtime += data[key]
        res['tp'] += data['tp']
        res['fp'] += data['fp']
        res['tn'] += data['tn']
        res['fp'] += data['fp']

        # Stip the bin, then record the size
        stripped_bin = gen_strip_file(bin)
        res['size'] += bin.stat().st_size
        res['stripped_size'] += stripped_bin.stat().st_size
        stripped_bin.unlink()

    print(res)
    print(f" The total runtime: {tot_runtime} seconds")
    print(f"The BPS: {res['stripped_size'] / tot_runtime}")
    #print(f"


    # Recall = # Correct Pos lbls /  # Ground Trurth Pos lbls
    # Recall = tp / (tp+fn) 
    recall = res['tp'] / (res['tp']+res['fn'])

    # Prec = #pos_lbl / #
    # Prec = tp / (tp+fp)
    prec = res['tp'] / ( res['tp'] + res['fp'])

    # F1 
    f1 = (2*prec*recall)/(prec+recall)

    print(f"Prec: {prec}")
    print(f"Recall: {recall}")
    print(f"F1: {f1}")
    return



@app.command()
def raw_test(
    bins: Annotated[str, typer.Argument()],
    checkpoint_dir: Annotated[str, typer.Argument()],
    checkpoint: Annotated[str, typer.Argument()],
    result_path: Annotated[str, typer.Argument()],
    check_for_existing_results: Annotated[bool, typer.Option()]=True,
    ):
    '''
    Temp test to see how to save raw predictions in pbnz file
    '''


    res_path = Path(result_path)
    if not res_path.exists():
        res_path.mkdir()
    elif res_path.is_file():
        raise Exception

    input_path = Path(bins)
    if not input_path.exists():
        print(f"Path {input_path} doesn't exist")
        return
    elif input_path.is_dir():
        inp_bins =  list(input_path.rglob('*'))
    else:
        inp_bins = [input_path]

    # Load our model
    roberta = RobertaModel.from_pretrained(checkpoint_dir, 
                                            checkpoint,
                                            'data-bin/funcbound', 
                                            user_dir='finetune_tasks')
    roberta.cuda()
    roberta.eval()

    for bin_path in alive_it(inp_bins):
        print(f"On bin: {bin_path.name}")

        single_res_path = res_path.joinpath(f"{bin_path.name}")
        if single_res_path.exists() and check_for_existing_results:
            if all( x in [z.name for z in single_res_path.rglob('*')] for x in ["runtime.txt", f"{bin_path.name}_result.npz"]):
                print(f"Skipping {bin_path.name}... already done")
                continue
            else:
                #single_res_path.unlink()
                shutil.rmtree(single_res_path)
        elif single_res_path.exists():
            raise Exception("result file already exists, pass arguments to chose to delete the existing path or skip over this experiemtn")

        # Get the xda res  and save
        #res_generator = xda_predict_raw(bin_path, roberta)
        tot_res, runtime = xda_predict_raw(bin_path, roberta)


        # Check that the dir exists, and is not a file 
        if single_res_path.exists():
            if single_res_path.is_file():
                raise Exception
        elif not single_res_path.exists():
            single_res_path.mkdir()

        # Make the sub directory
        sub_dir = single_res_path.joinpath(bin_path.name)
        if not sub_dir.exists():
            sub_dir.mkdir()
        elif sub_dir.is_file():
            raise Exception("Subdir is a file")

        # Save the compressed matrix
        matrix_saved = sub_dir.joinpath(f"{bin_path.name}_result.npz")
        if matrix_saved.exists():
            raise Exception("MAtix has been saved")
        
        #cur_results = []
        #for i in range(10000):
        #    step, runtime = next(res_generator)
        #    cur_results.append(step)

        #total_res = [x[0] for x in list(res_generator)]

        # Save the first numpy chunk
        #np.savez(matrix_saved, np.array([x[0] for x in list(res_generator)]))
        np.savez(matrix_saved, tot_res)
        # For every 10,000 bytes saze it into its own array 
        print("saved")

        #TODO: This was an attempt to fix the processing crashing for too many arrays

        #runtime = 0 
        ##for (data, cur_runtime) in res_generator:
        #chunks_per_numpy_array = 1000
        #current_sub_chunk = []
        #array_indexing = 0
        #total_numpy_arrays = []
        #for chunk in iter(lambda: list(itertools.islice((x[0] for x in res_generator), 512)), []):
        #    #safe_nump_save(data, matrix_saved)
        #    current_sub_chunk.append(chunk)
        #    if len(current_sub_chunk) == chunks_per_numpy_array:
        #        total_numpy_array.append(numpy.array(current_sub_chunk))



        # Save the runtime
        runtime_file = sub_dir.joinpath("runtime.txt")
        with open(runtime_file, 'w') as f:
            f.write(f"{runtime}")

        #save_raw_experiment_three_prob( bin_path, runtime, res, single_res_path)
    return

def safe_nump_save(data: np.ndarray, npz_file: Path):
    '''
    Read the memory mapped npz file to append the data to it 
    '''
    #npz_open_file= np.load(npz_file, mmap_mode="r")
    #npz_data = npz_open_file[list(npz_open_file.keys())[0]]
    matrix_mmap = np.memmap(npz_file, mode="r+" ),#dtype=npz_data.dtype, shape=npz_data.shape)

    matrix_mmap.resize((matrix_mmap.shape[0] + data.shape[0], matrix_mmap.shape[1]))
    npz_open_file.close()
    return



@app.command()
def read_bounds_raw(
    input_dir : Annotated[str,typer.Argument()],
    bin_dir: Annotated[str, typer.Argument()],
    verbose: Annotated[bool, typer.Option()] = False,
    supress_warn: Annotated[bool, typer.Option()] = False,
    ):
    '''
    Read the input dir and compute results using the lief module
    '''

    input_path = Path(input_dir)
    if not input_path.exists(): 
        print(f"Inp dir {input_dir} is not a dir")
        return

    bin_path = Path(bin_dir)
    if not bin_path.exists():
        print(f"Bin dir {bin_dir} is not a dir")
        return

    if bin_path.is_file():
        bins = [bin_path]
    else:
        bins = list(bin_path.glob('*'))

    matching_files = {}
    for bin in bins:
        matching = False
        for res_file in input_path.rglob('*'):
            if ".npz" not in res_file.name:
                continue
            if res_file.name.replace("_result.npz","") == bin.name:
                matching_files[bin] = res_file
                matching = True
        if not matching:
            print(f"Never found {bin.name}")


    if len(matching_files.keys()) != len(bins):
        msg = f"Found {len(matching_files.keys())}: {matching_files.keys()}"
        print(f"{matching_files.keys()}")
        print(f"Some bins don't have matching result file")
        raise Exception(msg)


    total_start_conf = ConfusionMatrix(0,0,0,0)
    total_bound_conf = ConfusionMatrix(0,0,0,0)
    total_end_conf = ConfusionMatrix(0,0,0,0)
    total_bytes = 0

    START = 1 
    END = 2 

    for bin in alive_it(list(matching_files.keys())):
        # Init the confusion matrix for this bin
        start_conf = ConfusionMatrix(0,0,0,0)
        bound_conf = ConfusionMatrix(0,0,0,0)
        end_conf = ConfusionMatrix(0,0,0,0)


        # 1  - Ground truth for bin file, this time the matrix will be...
        #           | start addr | end addr | 
        #   where end addr is the address of the final byte that is in the function
        #   end_addr = start_addr + length - 1

        #  0x01  mov 
        #  0x02  pop
        #  0x03  ret
        # start = 1 
        # len = 3
        # end = 3

        gnd_truth = lief_gnd_truth(bin.resolve())
        # NOTICE: IMPORTANT... xda seems to the first byte outside of the function 
        #               as the end of the function 
        lengths_adjusted = gnd_truth.func_lens
        ends = gnd_truth.func_addrs + lengths_adjusted
        gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
                                    ends.T.reshape(-1,1)), axis=1)
        #gnd_matrix = np.concatenate((gnd_truth.func_addrs.T.reshape(-1,1), 
        #                            gnd_truth.func_lens.T.reshape(-1,1)), axis=1)

        # 2 - Find the npz with the xda funcs and addrs, chop of functions that 
        #     are out-of-bounds of the lief functions (these are functions that are
        #       likely outside of the .text section)
        xda_funcs = read_xda_npz(matching_files[bin])
        predictions = torch.Tensor(xda_funcs).argmax(dim=2).view(-1).data #.numpy()
        start_indices = np.where(predictions == START)[0]
        end_indices = np.where(predictions == END)[0]

        # 3 - Get the address of the first byte in the .text section and add this
        #     to all the function bound indices
        parsed_bin = lief.parse(str(bin.resolve()))
        text_section_virt_addr = parsed_bin.get_section(".text").virtual_address
        text_section_start = parsed_bin.imagebase + text_section_virt_addr

        xda_starts = start_indices + text_section_start - 512
        xda_ends = end_indices + text_section_start - 512

        # 4 - Compare the two lists
        # Get all the start addrs that are in both, in ida only, in gnd_trush only
        start_conf.tp=len(np.intersect1d(gnd_matrix[:,0], xda_starts))
        start_conf.fp=len(np.setdiff1d( xda_starts, gnd_matrix[:,0] ))
        start_conf.fn=len(np.setdiff1d(gnd_matrix[:,0], xda_starts))

        # 5 - Compare the ends
        end_conf.tp=len(np.intersect1d(gnd_matrix[:,1], xda_ends))
        end_conf.fp=len(np.setdiff1d( xda_ends, gnd_matrix[:,1] ))
        end_conf.fn=len(np.setdiff1d(gnd_matrix[:,1], xda_ends))


        # Create tuple of the starts to the ends 
        #if len(xda_starts) == len(xda_ends):
        #    xda_bounds = np.concatenate((xda_starts.T.reshape(-1,1), xda_ends.T.reshape(-1,1)),axis=1)
        #else:
        # When we don't have the same number of start predictions as we do end predictions, 
        # We have the cases:

        # Case 1: Two or more starts in a row 
        # Case 2: Two or more ends in a row

        # In either case, always take the first predictions
        
        # To achieve this, take the two lists of starts and ends,
        #   | start | end | 
        #   |  ..   | ..  | 
        # 
        # Any convert to a style:
        # 
        #  | Addresses | label | 
        #  |  ..       | start | 
        #  | ..        | end   | 

        # There, I can iterate through the list, and whenever a second start is read 
        # or a second end it read, pop it. 

        # 1. Add a column of all 1s for the start addrs, and a column of all 2s for the end addrs
        all_ones = np.ones((1,len(xda_starts)))
        #tmp_starts = np.vstack((xda_starts, np.ones((1,len(xda_starts))))).T
        tmp_starts = np.vstack((xda_starts, all_ones)).T

        all_twos = np.full((1,len(xda_ends)),2)
        #tmp_ends = np.vstack((xda_ends, np.full((1,len(xda_ends)),2))).T
        tmp_ends = np.vstack((xda_ends, all_twos)).T

        # 2. Vertically stack the start and end columns and sort by adddress
        comb =  np.vstack((tmp_starts, tmp_ends))
        sorted_indices = np.argsort(comb[:, 0])
        bounds = comb[sorted_indices]

        # 3. Filter any occurancce where theres more than 1 start, or end in a row
        # Specifically, the following line..
        #   a. bounds[1:,1] gets the second column excluding the first row
        #   b. bounds[:,1] gets the second column excluding the last row
        #   c. Compare these two 
        #    
        #  1                                     1
        #  2   ->   2  !=   1  ->  True    ->    2
        #  1        1       2      True          1
        #  1        1       1      False

        if bounds.shape[0] == 0:
            xda_bounds = np.array([[]])
        else:
            indices_to_keep = np.append(True, bounds[1:, 1] != bounds[:-1, 1])
            filt_sorted_bounds = bounds[indices_to_keep]

            # If the first label is a function end, remove it,
            # If the last label is a function start, remove it 

            # Check to see if theres no rows,
            # This would be the case is the first 
            # prediction is an end and there is only 1 prediction
            try:
                if filt_sorted_bounds.shape[0] == 0:
                    xda_bounds = np.array([[]])
                else:
                    if filt_sorted_bounds[0,1] == 2:
                        filt_sorted_bounds = filt_sorted_bounds[1:,:]

                    if filt_sorted_bounds.shape[0] == 0:
                        xda_bounds = np.array([[]])
                    elif filt_sorted_bounds[-1,1] == 1:
                        filt_sorted_bounds = filt_sorted_bounds[:-1,:]
                    # Lastly, combine the start and ends array to make matrix:   | start | end |
                        starts = filt_sorted_bounds[filt_sorted_bounds[:,1] == 1]
                        ends = filt_sorted_bounds[filt_sorted_bounds[:,1] == 2]
                        xda_bounds = np.hstack(( starts[:,0].reshape(-1,1), ends[:,0].reshape(-1,1)))
            except Exception as e:
                print(filt_sorted_bounds.shape)
                raise(e)
                

        if total_start_conf.tp == 0:
            np.save("TMP_XDA_BOUINDS", xda_bounds)
            np.save("TMP_GND_M", gnd_matrix)

        # 6 - Compare the ends
        #bound_conf.tp=len(np.intersect1d(gnd_matrix, xda_bounds))
        #bound_conf.fp=len(np.setdiff1d( xda_bounds, gnd_matrix ))
        #bound_conf.fn=len(np.setdiff1d(gnd_matrix, xda_bounds))
        bound_conf.tp = np.count_nonzero(np.all(np.isin(xda_bounds, gnd_matrix),axis=1))
        bound_conf.fp = xda_bounds.shape[0] - bound_conf.tp
        bound_conf.fn = gnd_matrix.shape[0] - bound_conf.tp


        debug = True
        if debug:
            with open("XDA_FUNCS_BOUND",'w') as f:
                for row in xda_bounds:
                    f.write(f"{row}\n")
            with open("GND_MATRIX",'w') as f:
                for row in gnd_matrix:
                    f.write(f"{row}\n")

        # tp + fp = Total predicted
        if not start_conf.tp + start_conf.fp == xda_starts.shape[0]:
            print(f"start TP: {start_conf.tp}")
            print(f"start FP: {start_conf.fp}")
            print(f"Xda starts: {xda_starts.shape}")
            print(f"gnd matrix {gnd_matrix.shape[0]}")
            return

        # tp + fn = total pos
        if not start_conf.tp + start_conf.fn == gnd_matrix.shape[0]:
            print(f"{start_conf.fp}")
            print(f"{start_conf.fn}")
            print(f"{gnd_matrix.shape[0]}")
            print(f"start total: {xda_starts.shape}")
            print(f"gnd matrix {gnd_matrix.shape[0]}")
            return

        total_bytes += gnd_truth.num_bytes

        total_start_conf.tp += start_conf.tp
        total_start_conf.fp += start_conf.fp
        total_start_conf.fn += start_conf.fn

        total_bound_conf.tp += bound_conf.tp
        total_bound_conf.fp += bound_conf.fp
        total_bound_conf.fn += bound_conf.fn

        total_end_conf.tp += end_conf.tp
        total_end_conf.fp += end_conf.fp
        total_end_conf.fn += end_conf.fn

        if verbose:
            print(f"binary: {bin.name}")
            print(f"Starts: {start_conf}")
            print(f"Starts Metrics: {calc_metrics(start_conf)}")

            print(f"Ends : {end_conf}")
            print(f"Ends Metrics: {calc_metrics(end_conf)}")

            print(f"Bounds: {bound_conf}")
            print(f"Bounds Metrics: {calc_metrics(bound_conf)}")

    print(f"Starts Metrics: {calc_metrics(total_start_conf)}")
    print(f"Ends Metrics: {calc_metrics(total_end_conf)}")
    print(f"Bounds Metrics: {calc_metrics(total_bound_conf)}")
    return 




def read_xda_npz(inp: Path)->np.ndarray:
    '''
    Read the ida npz
    '''
    npz_file = np.load(inp)
    return npz_file[list(npz_file.keys())[0]]



#@app.command()
#def test(
#        inp_dir: Annotated[str, typer.Argument()],
#        out_dir: Annotated[str, typer.Argument()],
#        checkpoint_dir: Annotated[str, typer.Argument()],
#        checkpoint: Annotated[str, typer.Argument()],
#        ):
#    '''
#    Test XDA on a set of binaries.
#    '''
#
#
#    # Make a list of the input file 
#    test_files = [x.resolve() for x in Path(inp_dir).resolve().rglob('*')]
#
#    out_path = Path(out_dir)
#    if not out_path.exists():
#        out_path.mkdir()
#
#    # Load our model
#    roberta = RobertaModel.from_pretrained(checkpoint_dir, 
#                                        checkpoint,
#                                        'data-bin/funcbound', 
#                                        user_dir='finetune_tasks')
#    roberta.eval()
#    results = xda_predict_many(test_files, roberta, out_path.resolve(), save_results=True)
#
#    return

if __name__ == '__main__':
    app()
    exit()

    OPTIMIZATION = 'Oz'

    ##TODO: This is best used when I have large similar datasets for O0-Oz
    ##       until I have all of those compiled I will manually split
    ##with open("TEST_BIN_NAME_SET.json", 'r') as f:
    ##    bin_names = json.load(f)['names']

    ## 
    #rust_files = []

    #for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
    #    info_file = parent / 'info.json'
    #    info = {}
    #    try:
    #        with open(info_file, 'r') as f:
    #            info = json.load(f)
    #    except FileNotFoundError:
    #        print(f"File not found: {info_file}")
    #        continue
    #    except json.JSONDecodeError as e:
    #        print(f"JSON decoding error: {e}")
    #        continue
    #    except Exception as e:
    #        print(f"An error occurred: {e}")
    #        continue


    #    if info['optimization'].upper() in OPTIMIZATION.upper():

    #        bin_file  =  parent / info['binary_name']
    #        if bin_file.exists():
    #            rust_files.append(bin_file)


    #pretrain_files = rust_files[:50]
    #finetune_files = rust_files[50:100]
    #test_files = rust_files[300:]

    #with open("XDA_DATASET_SPLITS", 'w') as f:
    #    f.write("Pretrain_names\n")
    #    f.write(", ".join(x.name for x in pretrain_files) + "\n")
    #    f.write("finetune_names\n")
    #    f.write(", ".join(x.name for x in finetune_files) + "\n")
    #    f.write("test_names\n")
    #    f.write(", ".join(x.name for x in test_files) + "\n")

    test_files = [x for x in Path("ghid_xda_subset_res_O0_20_raw_bin").rglob('*')]

    #checkpoint_dir = "ryans_saved_checkpoints/funcbound/"
    checkpoint_dir = "checkpoints/funcbound/"
    checkpoint = "checkpoint_best.pt"

    #TODO: For some reason the scipt is checking for a dict.txt in the 
    # checkpoints directory

    # Load our model
    roberta = RobertaModel.from_pretrained(checkpoint_dir, 
                                        checkpoint,
                                        'data-bin/funcbound', 
                                        user_dir='finetune_tasks')
    roberta.eval()

    results = xda_predict_many(test_files, roberta, str(OPTIMIZATION), save_results=True)

    print("Total results...")
    print(f"TP:{results[0]}")
    print(f"TN:{results[1]}")
    print(f"FP:{results[2]}")
