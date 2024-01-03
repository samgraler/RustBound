from pathlib import Path 
import time
import random
import json
from typing_extensions import Annotated
from fairseq.models.roberta import RobertaModel
import sys
import lief 
from elftools.elf.elffile import ELFFile
from dataclasses import dataclass
from colorama import Fore, Back, Style
import numpy as np
from alive_progress import alive_it

#from ../ripkit.ripkit.ripbin import (
#    get_functions,
#)


import time
import typer 
import rich

from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()
app = typer.Typer()

@dataclass 
class FunctionInfo():
    name: str
    addr: int
    addrHex: str
    size: int



def get_elf_functions(path:Path, warn_if_stripped: bool = False)->list[FunctionInfo]:
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


def generate_data_src_pretrain_all(list_of_paths):
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
    train_files = list_of_paths[:-4]
    valid_files = list_of_paths[-4:]

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

def xda_predict_many(inp_files, model, out_dir, save_results=False, use_saved=True):
    tot_tp = 0
    tot_tn = 0
    tot_fp = 0
    tot_fn = 0
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
        
        tot_tp += res[0]
        tot_tn += res[2]
        tot_fp += res[1]
        tot_fn += res[3]
        print("Running totals:")
        print(f"TP: {tot_tp}")
        print(f"TN: {tot_tn}")
        print(f"FP: {tot_fp}")
        print(f"FN: {tot_fn}")


    return tot_tp, tot_tn, tot_fp, tot_fn




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
        'fsize':0,
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
        key = 'runetime'
        with open(file, 'r') as f:
            data = json.load(f)
        tot_runtime += data[key]
        res['tp'] += data['tp']
        res['fp'] += data['fp']
        res['tn'] += data['tn']
        res['fp'] += data['fp']
        res['fsize'] += bin.stat().st_size

    print(res)
    print(tot_runtime)
    print(res['fsize'] / tot_runtime)
    return




    return

@app.command()
def timed_test(
        inp_dir: Annotated[str, typer.Argument()],
        out_dir: Annotated[str, typer.Argument()],
        checkpoint_dir: Annotated[str, typer.Argument()],
        checkpoint: Annotated[str, typer.Argument()],
        ):


    # Make a list of the input file 
    test_files = [x.resolve() for x in Path(inp_dir).resolve().rglob('*')]

    out_path = Path(out_dir)
    if not out_path.exists():
        out_path.mkdir()

    # Load our model
    roberta = RobertaModel.from_pretrained(checkpoint_dir, 
                                        checkpoint,
                                        'data-bin/funcbound', 
                                        user_dir='finetune_tasks')
    roberta.eval()
    results = xda_predict_many(test_files, roberta, out_path.resolve(), save_results=True)

    return

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
