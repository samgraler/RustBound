'''
    New model using sliding window size of bytes, and labeling 
    that window of bytes as a function start or not
'''
import lief
import shutil
import subprocess
import os
import json
import time
from lightning.pytorch.cli import LightningCLI

from lightning.pytorch.utilities.types import STEP_OUTPUT

from torchmetrics.classification import (
    BinaryF1Score, BinaryPrecision, BinaryRecall,
)
import sys
#import matplotlib.pyplot as plt

#from model_runner import log_model, save_json_receipt

import random
#import polars as pl

from typing import Optional, Tuple

import torch 
import numpy as np
#import logging
import torch.nn as nn
import torch.optim as optim
from pathlib import Path
from torch.utils.data import Dataset, DataLoader
from alive_progress import alive_bar, alive_it
from torchinfo import summary
#from torchviz import make_dot
import typer
from rich.console import Console
from typing_extensions import Annotated

from models import recreatedModel

from pytorch_lightning.callbacks import ModelCheckpoint

import multiprocessing 
CPU_COUNT = multiprocessing.cpu_count()

from ripkit.ripbin import (
    get_functions,
    generate_minimal_labeled_features,
)
#from ripbin import (
#    get_registry, AnalysisType, ProgLang,
#    generate_minimal_unlabeled_features,
#    POLARS_generate_minimal_unlabeled_features,
#    )

import lightning.pytorch as pylight


# This is not the bi-directional RNN itself,
# But rather a wrapper to train it 
class lit(pylight.LightningModule):
    def __init__(self, classifier:nn.Module, 
                 loss_func: nn.modules.loss._Loss, 
                 learning_rate: int,
                 hidden_size: int,
                 input_size: int,
                 num_layers:int,
                 threshold: float =.9)->None:
        super().__init__()
        self.classifier = classifier
        self.loss_func = loss_func
        self.lr = learning_rate
        self.threshold = threshold
        self.save_hyperparameters()

        self.metrics = [
            BinaryF1Score(threshold=threshold),
            BinaryPrecision(threshold=threshold),
            BinaryRecall(threshold=threshold),
        ]
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.rnn = nn.RNN(input_size, hidden_size, num_layers, 
                          batch_first=True, bidirectional=True,
                          nonlinearity='relu')
                          #nonlinearity='gru')
        #self.rnn = nn.GRU(input_size, hidden_size, num_layers, 
        #                  batch_first=True, bidirectional=True)
        self.fc = nn.Linear(hidden_size*2, 1)
        self.sigmoid = nn.Sigmoid()
        self.softmax = nn.Softmax()
        self.relu = nn.ReLU()

    #def forward(self, x)->torch.Tensor:
    #    '''
    #        Forward method
    #    '''
    #    print(x)
    #    param1 = self.num_layers * 2 
    #    param2 = x.size(0)
    #    param3 = self.hidden_size
    #    #h0 = torch.zeros(self.num_layers * 2, x.size(0), 
    #    #                 self.hidden_size).to(x.device)
    #    h0 = torch.zeros(param1, param2, 
    #                     param3).to(x.device)
    #    out, _ = self.rnn(x, h0)
    #    out = self.fc(out)
    #    out = out.squeeze(dim=2)
    #    out = torch.nan_to_num(self.sigmoid(out))
    #    return out



    def reset_metrics(self)->None:
        self.metrics = [
            BinaryF1Score(threshold=self.threshold),
            BinaryPrecision(threshold=self.threshold),
            BinaryRecall(threshold=self.threshold),
        ]

    
    def training_step(self, batch, batch_idx)->torch.Tensor:
        # Trianing loop
        inp_batch, target = batch

        out_tensor = self.classifier(inp_batch)

        # Calc loss
        loss = self.loss_func(out_tensor, target)
        self.log("Train_Loss", loss, prog_bar=True)
        return loss

    def validation_step(self,batch, batch_idx)->STEP_OUTPUT:
        # Trianing loop
        inp_batch, target = batch

        out_tensor = self.classifier(inp_batch)

        # Calc loss
        loss = self.loss_func(out_tensor, target)
        self.log("Valid_Loss", loss)

    def configure_optimizers(self)->optim.Optimizer:
        optimizer = optim.RMSprop(self.parameters(), lr=self.lr)
        return optimizer

    def test_step(self, batch, batch_idx)->STEP_OUTPUT:
        # Trianing loop
        inp_batch, target = batch

        out_tensor = self.classifier(inp_batch)

        # Calc loss
        loss = self.loss_func(out_tensor, target)

        self.log("Test_Loss", loss)

        for func in self.metrics:
            # BUG: There is an error in this function, a claim that 
            #       target has values that are non [0 or 1]
            func.update(out_tensor.to('cpu'),
                          target.to('cpu'))



app = typer.Typer()
console = Console()




# Custom dataset class
class MyDataset(Dataset):
    def __init__(self, data, target):
        self.data = data
        self.target = target

    def __len__(self):
        return len(self.data)

    def __getitem__(self, index):
        inp = self.data[index]
        target = self.target[index]
        return inp, target



#logging.basicConfig(level=logging.INFO)
#BAR_LOGGER = logging.getLogger('alive_progress')

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


app = typer.Typer()
console = Console()

def test_model( model, dataloader, metrics = 
               [BinaryF1Score, BinaryPrecision, BinaryRecall]):
    '''
    test the model

    Returns
    -------

    list :
        List of the passed metrics
    '''

    model.eval()
    with torch.no_grad():
        bar = alive_it(dataloader, theme='scuba', 
                        title = "Evaluationg")

        for inp_batch, target in bar:
            output_tensor = model(inp_batch)

            for func in metrics:
                func.update(output_tensor.squeeze().to('cpu'),
                          target.squeeze().to('cpu'))

    return metrics 

def vsplit_dataset(inpAr, split: tuple[int,int,int]):
    '''
    Split passed matrix for train validate test 

    Parameteres 
    -----------

    inpAr: np.ndarray
        the dataset

    split: tuple[int,int,int]
        the split, must add to 100
    '''

    if sum(split) != 100:
        raise Exception("Split error, must add to 100")

    
    # Get the total rows so I know what 100 percent is 
    tot_rows = inpAr.shape[0]

    # The test index is 0% - splot[0]%
    test_index = tot_rows // 100 * split[0]

    # The validate index is split[0]% to split[1]%
    validate_index = test_index + tot_rows // 100 * split[1]

    # The test index is the rest
    return (inpAr[:test_index,:], 
            inpAr[test_index: validate_index,:], 
            inpAr[validate_index:, :]
            )


def gen_one_hot_dataset_ENDS(files: list[Path], num_chunks):

    # TODO: Bools instead?
    # BUG: Maybe - when I switch to np.bool_ the performance 
    #       drops DRASTICALLY
    inp_array = np.empty((num_chunks,1000,255), dtype=np.float64)
    label_arr = np.empty((num_chunks,1000, 1), dtype=np.float64)

    #inp_array = np.empty((num_chunks,1000,255), dtype=np.bool_)
    #label_arr = np.empty((num_chunks,1000, 1), dtype=np.bool_)


    data_info = []

    with alive_bar(num_chunks, title="Generating dataset") as bar:
    #for i in alive_it(range(num_chunks), title="Generating dataset"):
        for _ in range(num_chunks):

            # Randomly select a file from the glob
            selected_file = np.random.choice(files)

            # Load the selected .npz file
            with np.load(selected_file, mmap_mode='r', 
                         allow_pickle=True) as npz_file:
                # Get the first (and only) file array that is in the 
                # npz file
                data = npz_file[npz_file.files[0]]
    
                # Randomly select a 1000-row chunk from the 'data' array

                # Randomly select an index for data start
            
                if data.shape[0] < 1001:
                    continue

                index =np.random.randint(0, data.shape[0]-1000-1)
                chunk = data[index: index+1000, :]

                # the chunks is forward
                # start, mid, end, *byte
                inp_array[i,:,:] = chunk[:,3:]
                label_arr[i,:,:] = chunk[:,2].reshape((1000,1))
                data_info.append((selected_file, index))
                bar()

    return inp_array, label_arr

def gen_one_hot_dataset(files: list[Path], num_chunks):

    # TODO: Is bool more effecient?
    # BUG: Maybe - when I switch to np.bool_ the performance 
    #       drops DRASTICALLY
    inp_array = np.empty((num_chunks,1000,255), dtype=np.float64)
    label_arr = np.empty((num_chunks,1000, 1), dtype=np.float64)

    # 3d numpy array. Each chunk is 1000x255 and I have <num_chunks> chunks
    #inp_array = np.empty((num_chunks,1000,255), dtype=np.bool_)
    #label_arr = np.empty((num_chunks,1000, 1), dtype=np.bool_)

    data_info = []

    # Sanity check that all files exist TODO: This should be redundant and ultimately removed
    files = [x for x in files if x.exists()]

    # This is how many chunks per file to get, notice if a file is not 
    # long enough for this number of chunks, other files will just be 
    # revisited
    about_chunks_per_file = num_chunks / len(files)


    # This loop will iterate num_chunks time over index
    # 0 : num_chunks-1 
    # It will select 1 chunk from one file then move on to the next
    data_index = 0
    #for i in alive_it(range(num_chunks), title="Generating dataset"):

    with alive_bar(num_chunks, title="Generating dataset") as bar:
        for _ in range(num_chunks):
    #for i in alive_it(range(num_chunks), title="Generating dataset"):
            good_file = False

            # Randomly select a file from the glob
            selected_file = np.random.choice(files)

            # Load files until a file atleast 1000 bytes long 
            npz_file_data = np.array([])
            while not good_file:
                selected_file = np.random.choice(files)
                # Load the selected .npz file
                with np.load(selected_file, mmap_mode='r', 
                             allow_pickle=True) as npz_file:

                    # Get the first (and only) file array that is in the npz file
                    npz_file_data = npz_file[npz_file.files[0]]
    
                    # If the npz_file_data array is not large enough to be a chunk, go to 
                    # the next loop iteration
                    if npz_file_data.shape[0] >= 1001:
                        good_file = True
                        print(f"File {selected_file} too short")
                        break

            # TODO: Remove for loop to return to old, and unindent lines by 1
            for _ in range(int(about_chunks_per_file)):

                # Select an index
                # The greatest_index is matrix.shape - 1 - 1000
                rand_index =np.random.randint(0, npz_file_data.shape[0]-1000-1)

                # The chunk is a 2d matrix 
                # where the columns are [start,middle,end,*byte]
                chunk = npz_file_data[rand_index: rand_index+1000, :]

                # The input array, or the onehot array is the one-hot bytes, which is 
                # every thing after the first 3 columns
                inp_array[data_index,:,:] = chunk[:,3:]

                # The lbl array is the first column which is TRUE or FALSE, denoting 
                # whether or not the the bytes is a function start
                label_arr[data_index,:,:] = chunk[:,0].reshape((1000,1))
                #inp_array[i,:,:] = chunk[:,3:]
                #label_arr[i,:,:] = chunk[:,0].reshape((1000,1))

                data_index += 1
                bar()

                data_info.append((selected_file, data_index))
                if data_index >= 1000:
                    # We're done break 
                    return inp_array, label_arr
                


    return inp_array, label_arr



def create_dataloaders(
        input_files,
        cache_file = Path(".DEFAULT_CACHE"),
        num_chunks = 1000,
        ends=False,
    ):
    '''
    Generate dataloaders 
    '''

    #print(f"Cache file {cache_file} does not exist")
    if cache_file.exists():
        data = np.empty((0,0))
        lbl = np.empty((0,0))
        with np.load(cache_file, mmap_mode='r') as f:
            data = f['data']
            lbl = f['lbl']
    else:
        # Get the data set
        if ends:

            data, lbl= gen_one_hot_dataset_ENDS(input_files,num_chunks=num_chunks)
        else:
            data, lbl= gen_one_hot_dataset(input_files,num_chunks=num_chunks)
        np.savez(cache_file, data=data, lbl=lbl)

    # Get split the dataset
    train_data, valid_data, test_data = vsplit_dataset(data,
                                                    (80,10,10)) 
    train_lbl, valid_lbl, test_lbl = vsplit_dataset(lbl,
                                                    (80,10,10)) 

    # Get the training dataset
    train_dataset = MyDataset(torch.Tensor(train_data).to(DEVICE), 
                     torch.Tensor(train_lbl).squeeze().to(DEVICE))
    valid_dataset = MyDataset(torch.Tensor(valid_data).to(DEVICE), 
                     torch.Tensor(valid_lbl).squeeze().to(DEVICE))
    test_dataset = MyDataset(torch.Tensor(test_data).to(DEVICE), 
                     torch.Tensor(test_lbl).squeeze().to(DEVICE))


    # Get the dataloader
    # BUG: Using num workers (maybe) introduced more CUDA init errors
    train_dataloader = DataLoader(train_dataset, batch_size=32, 
                                shuffle=False,
                                drop_last=True)#, num_workers=CPU_COUNT)
    valid_dataloader = DataLoader(valid_dataset, batch_size=32, 
                                shuffle=False,
                                drop_last=True) #,num_workers=CPU_COUNT)
    test_dataloader = DataLoader(test_dataset, batch_size=32, 
                                shuffle=False,
                                drop_last=True) #, num_workers=CPU_COUNT)

    return train_dataloader, valid_dataloader, test_dataloader

@app.command()
def rust_train_model(
        opt_lvl: Annotated[str, typer.Argument(
                    help="Opt level to train model on")] = 'O0',
        lr: Annotated[str, typer.Option(
                    help="learning rate to use")] = '0.0005',
        ends: Annotated[bool, typer.Option(
                    help="learning rate to use")] = False,
    
        starts: Annotated[bool, typer.Option(
                    help="learning rate to use")] = False,
        ):

    if opt_lvl not in ['all', 'O0', 'O1', 'O2', 'O3']:
        print(f"Opt lvl {opt_lvl} is unknown")
        return

    # Get the opt levels
    opt_lvls = [opt_lvl] if opt_lvl != 'all' else ['O0', 'O1', 'O2', 'O3']

    # Get the results
    if (not starts) and (not ends):
        total_results = [(opt, rust_train_model_helper(opt,float(lr),
                                ends=True),'ends') for opt in opt_lvls]
        total_results.extend([(opt, 
                            rust_train_model_helper(opt,float(lr),
                            ends=False),'starts') for opt in opt_lvls])
    elif ends:
        total_results = [(opt, rust_train_model_helper(opt,float(lr),
                                ends=True),'ends') for opt in opt_lvls]
    else:
        total_results = [(opt, rust_train_model_helper(opt,float(lr),
                                ends=False),'ends') for opt in opt_lvls]


    for opt, res, detect_type in total_results:
        print(f"TRAINING SUMMARY with {opt} {detect_type}")
        print("======================================")
        print(f"  Had {len(res[0])} rust files to use")
        print(f"  Learn Rate: {lr}")
        print(f"  TrainLoader {len(res[-2][0])}")
        print(f"  ValidLoader {len(res[-2][1])}")
        print(f"  TestLoader {len(res[-2][2])}")
        for metric in res[2]:
            print(f"    {type(metric).__name__} : {metric.compute()}")
    return 


def onehot_to_byte(onehot_list: list):


    # THe index of the byte is one less than its decimal value 
    if 1 not in onehot_list:
        return 0

    return onehot_list.index(1) + 1


@app.command()
def new_detect(
        file: Annotated[str, typer.Argument(help='Input binay')],
        opt_lvl: Annotated[str, typer.Argument(help='Opt lvl')],
        start: Annotated[bool, typer.Option(
                    help="Detect Start Bounds")] = True,
        use_cache_model: Annotated[bool, typer.Option(
                    help="Used the chached mode")] = True,
    ):


    if opt_lvl not in ['O0', 'O1', 'O2', 'O3']:
        print(f"Opt lvl {opt_lvl} is unknown")
        return


    if start:
        MODEL_F_NAME = Path(f"MODEL_{opt_lvl}_start")
    else:
        MODEL_F_NAME = Path(f"MODEL_{opt_lvl}_end")

    print(f"Generating model and dataset")
    if (not use_cache_model and not start) or not MODEL_F_NAME.exists():
        rust_files, losses, results, loaders, \
            model  = rust_train_model_helper(opt_lvl,'0.0005', ends=True)
        torch.save(model,MODEL_F_NAME)
    elif (not use_cache_model and start) or not MODEL_F_NAME.exists():
        rust_files, losses, results, loaders, \
            model  = rust_train_model_helper(opt_lvl,'0.0005', ends=False)
        torch.save(model,MODEL_F_NAME)
    elif MODEL_F_NAME.exists():
        model = torch.load(MODEL_F_NAME)
    else:
        print("Error")
        return

    summary(model)

    cached_file= Path(f".cache_for_{file}.npz").resolve()

    if not cached_file.exists():
        print("Generating npz data")
        data = generate_minimal_unlabeled_features(Path(file), use_one_hot=True)
        np.savez(cached_file,np.array(list(data)))
    else:
        print("Loading npz data")
        data = np.load(cached_file,mmap_mode='r', allow_pickle=True)
        data = data[data.files[0]]

    # Now data is a generator, 

    threshold = .9

    print("Labeling addrs...")
    for i in alive_it(range(0,data.shape[0]-1000, 1000), title="LabelingFunctions"):
        # Get 1000 chunks from the generator 

        # The yielded array has address, *byte
        # Ignore the address
        addrs = data[i:i+1000,0].transpose().reshape(-1,1)

        # Get the chunk
        chunk = data[i:i+1000,1:]
        #print(f"Chunk shape {chunk.shape}")

        # Pass the chunk to the model 
        inp = torch.Tensor(chunk).unsqueeze(0).to(DEVICE)
        pred_label = model(inp)
        lbls = torch.where(pred_label >= threshold, 
                    torch.tensor(1), torch.tensor(0)).cpu().numpy().transpose()


        byte_lbl_addrs = np.hstack((addrs,lbls,chunk))
        #print(f"lbl addrs shape {byte_lbl_addrs.shape}")

        starts = byte_lbl_addrs[byte_lbl_addrs[:,1]==1]

        #print(addrs[lbls==1])
        if np.count_nonzero(lbls == 1) >= 1:
            for start in starts:
                #print(f"Shape of start {start.shape}")
                #exit(1)
                print(f"0x{hex(start[0])}|, 0x{hex(onehot_to_byte(list(start[3:])))}")


def lit_model_train(input_files, 
                    cache_file = Path(".DEFAULT_CACHE"),
                    print_summary=False,
                    learning_rate = 0.0005,
                    input_size=255,
                    hidden_size=16,
                    layers=1,
                    epochs=100,
                    threshold=.9,
                    ends=False):
    
    '''
    Train RNN model
    '''

    cache_file = Path(".lit_cache_dataset.npz")

    # Init the model
    model = recreatedModel(input_size, hidden_size, layers)

    # Binary cross entrophy loss
    loss_func = nn.BCELoss()

    classifier = lit(model,
                     loss_func=loss_func,
                     learning_rate=learning_rate,
                     input_size=input_size,
                     hidden_size=hidden_size,
                     num_layers=layers)

    train_loader, valid_loader, test_loader = create_dataloaders(
            input_files, cache_file=cache_file,ends=False)

    # Summary of the model 
    if print_summary:
        summary(model, (32,1000,255))

    trainer = pylight.Trainer(max_epochs=100)
    
    trainer.fit(classifier, train_loader, valid_loader)

    # TODO: Get metrics out of the test
    trainer.test(classifier, dataloaders=test_loader)

    return classifier.metrics, classifier

def cli_main():


    print("cli main")
    learning_rate =  0.0005

    input_size=255
    hidden_size=16
    layers=1

    opt_lvl = 'O0'
    # Get the registry of available analyzed files
    reg = get_registry()

    print("Got the registry")

    files = reg[reg['analysis_type'] == AnalysisType.ONEHOT_PLUS_FUNC_LABELS.value]
    files = files[files['prog_lang'] == ProgLang.RUST.value]
    files = files[files['opt_level'] == opt_lvl]

    # List of analysis file paths 
    input_files = files['analysis_path'].to_list()

    cache_file = Path(".lit_cache_dataset.npz")

    # Init the model
    model = recreatedModel(input_size, hidden_size, layers)

    # Binary cross entrophy loss
    loss_func = nn.BCELoss()

    classifier = lit(model, loss_func, learning_rate)

    train_loader, valid_loader, test_loader = create_dataloaders(
            input_files, cache_file=cache_file,ends=False)


    trainer = pylight.Trainer(max_epochs=100)

    cli = LightningCLI(classifier)




#TODO: Way to test on a large dataset without having to load it all into
# memory before running the test
def large_test():
    '''
    '''

    # The trainer takes a dataloader as a parameter
    # So loop over all the files, create the dataloader 
    # and run the test 

    # Theory 1: 
    #   - Use small dataloader 


    return


def rnn_predict(model, unstripped_bin):
    # the rnn can predict chunks of 1000 bytes 

    threshold = .9

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    data_gen = generate_minimal_labeled_features(unstripped_bin)
    inp_chunk = []
    lbl_chunk = []

    # Recored start time
    start = time.time()

    for row in data_gen:
        # Index | meaning
        # 0     | is_start
        # 1     | is_middle
        # 2     | is_end 
        # 3:    | one_hot_encoded value
        lbl_chunk.append(row[0])
        inp_chunk.append(row[3:])
        
        # NOTICE: Feed the model with 1000 bytes

        if len(lbl_chunk) == 1000:
            # make numpy matrix for this chunk
            lbl = np.array(np.array(lbl_chunk))
            inp = np.array([inp_chunk])

            # Get the prediction from the model 
            with torch.no_grad():
                prediction = model(torch.Tensor(inp).to(DEVICE))

            # Reset the chunk
            lbl_chunk = []
            inp_chunk = []

            # Score the prediction
            prediction = prediction.squeeze().to('cpu').numpy()
            prediction[prediction >= 0.9] = 1
            prediction[prediction < 0.9] = 0
            target = lbl.squeeze()

            # Some each of the cases. The .item() changed the type from
            # np.int64 to int
            tp += np.sum((prediction == 1) & (target == 1)).item()
            tn += np.sum((prediction == 0) & (target == 0)).item()
            fp += np.sum((prediction == 1) & (target == 0)).item()
            fn += np.sum((prediction == 0) & (target == 1)).item()

    runtime = time.time() - start

    return tp, tn, fp, fn, runtime 

@app.command()
def train_on(
        inp_dir: Annotated[str, typer.Argument(
                                    help='Directory of bings to train on')],
    ):

    # Get the files from the input path
    train_files = list(Path(inp_dir).rglob('*')) 


    # Train on these files
    metrics, classifier = lit_model_train(train_files)
    print([x.compute() for x in metrics])

    return


@app.command()
def train_on_first(
        opt_lvl: Annotated[str, typer.Argument(
                        help='Directory of bins to test on')],

        num_bins: Annotated[int, typer.Argument(
                        help='Num bins to test on')],
    ):

    opts = ['O0','O1','O2','O3','Z','S']

    # TODO: verify this is how Oz and Os are lbls
    if opt_lvl not in opts:
        print(f"opt lbl must be in {opts}")
        return

    ##TODO: This is best used when I have large similar datasets for O0-Oz
    ##       until I have all of those compiled I will manually split
    ##with open("TEST_BIN_NAME_SET.json", 'r') as f:
    ##    bin_names = json.load(f)['names']

    ## 
    rust_files = []

    for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
        info_file = parent / 'info.json'
        info = {}
        try:
            with open(info_file, 'r') as f:
                info = json.load(f)
        except FileNotFoundError:
            print(f"File not found: {info_file}")
            continue
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue


        if info['optimization'].upper() in opt_lvl.upper():

            bin_file  =  parent / info['binary_name']
            if bin_file.exists():
                rust_files.append(bin_file)

    # Get the first x files
    if len(rust_files) < num_bins:
        print(f"Num bins too low {rust_files}")
        return

    # Get the first x files
    first_x_files = rust_files[0:num_bins]

    with open(f"TRAINED_FILESET_{opt_lvl}.txt", 'w') as f:
        f.write("\n".join(x.name for x in first_x_files))
        

    # Train on these files
    metrics, classifier = lit_model_train(first_x_files)
    print([x.compute() for x in metrics])

    return


@app.command()
def train_without(
        opt_lvl: Annotated[str, typer.Argument(
                        help='Directory of bins to test on')],
        testset: Annotated[str, typer.Argument(
                        help='Directory of bins to test on')],
    ):
    opts = ['O0','O1','O2','O3','Z','S']

    # TODO: verify this is how Oz and Os are lbls
    if opt_lvl not in opts:
        print(f"opt lbl must be in {opts}")
        return

    test_path = Path(testset).resolve()
    if not test_path.exists():
        print(f"PAth {test_path} does not exist")

    # Get the test files 
    rust_test_files = [ x.name for x in test_path.glob('*')]

    for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
        info_file = parent / 'info.json'
        info = {}
        try:
            with open(info_file, 'r') as f:
                info = json.load(f)
        except FileNotFoundError:
            print(f"File not found: {info_file}")
            continue
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue


        if info['optimization'].upper() in opt_lvl:
            npz_file = parent / "onehot_plus_func_labels.npz"

            if info['binary_name'] not in rust_test_files:
                rust_train_files.append(npz_file)

    # Get the classifier and the metrics from training 
    metrics, classifier = lit_model_train(rust_train_files)
    print([x.compute() for x in metrics])

    # Create the pytorch tainer, will call the .test method on this 
    # object to test the model 
    trainer = pylight.Trainer(max_epochs=100)

    classifier.reset_metrics()

    # Get the run time of the module
    start = time.time()
    res = trainer.test(classifier,dataloaders=test_dataloader)
    runtime = time.time() - start

    # TODO: This is old code but I want to make sure its completely 
    #        useless before I delete it 
    #print(f"Test on {len(rust_test_files)}")
    #metrics = [x.compute() for x in classifier.metrics]
    #print(metrics)
    #print(f"Run time for 1000 chunks on optimization {opt_lvl}: {runtime}")
    #print(f"The len of train files was {len(rust_train_files)}")
    #print(f"The len of test files was {len(rust_test_files)}")
    return

@app.command()
def read_results(
        file: Annotated[str, typer.Argument(
                        help='json file of results')],
    ):

    # Create a path object for the file
    file_path = Path(file)

    # If the file doesn't exist return error
    if not file_path.exists():
        print(f"File {file} does not exist")
        return

    # Load the json file
    with open(file, 'r') as f:
        data = json.load(f)
        # Data is made of 
        #{
        #    '<bin_name>' : {'tp' : ,
        #                     'fp' : ,
        #                     'tn' : ,
        #                     'fn' : ,
        #                    }
        #}

    # Sum all the confusion matrix values 
    tp = sum(x['tp'] for x in data.values())
    fp = sum(x['fp'] for x in data.values())
    tn = sum(x['tn'] for x in data.values())
    fn = sum(x['fn'] for x in data.values())
    runtime = sum(x['runtime'] for x in data.values())
    tot_file_size = sum(x['filesize'] for x in data.values())

    # Recall 
    recall = tp/ (tp + fn)

    # Precision 
    precision = tp / (tp + fp)

    # F1
    f1 = 2 * precision * recall / (precision+recall)

    # File avg runtime
    file_avg = runtime / len(data.values())

    # Byte per second 
    # TODO: This bps is per .text byte ...
    #       talking with boyand this should change
    bps = (tp+tn+fn+fp) / runtime

    print(f"For {len(data.keys())} bins...")
    print(f"TP : {tp}")
    print(f"TN : {tn}")
    print(f"FP : {fp}")
    print(f"FN : {fn}")
    print(f"F1 : {f1}")
    print(f"Precision : {precision}")
    print(f"Recall : {recall}")
    print(f"Avg file time: {file_avg}")
    print(f"BPS .text: {bps}")
    print(f"BPS whole file: {tot_file_size/runtime}")
    print(f"total file size: {tot_file_size}")


    return


def strip_file(bin_path:Path)->Path:

    # Copy the bin and strip it 
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    strip_bin = strip_bin.resolve()
    shutil.copy(bin_path, Path(strip_bin))
    print(f"The new bin is at {strip_bin}")

    try:
        _ = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        # TODO: Handle better
        raise Exception("Could not strip bin")

    return strip_bin 

@app.command()
def test_on(
        testset_dir: Annotated[str, typer.Argument(
                        help='Directory of bins to test on')],
        weights: Annotated[str, typer.Argument(
                    help='File of bins')],
        results: Annotated[str, typer.Argument(
                    help="Path to save results to")]):

    # Make sure checkpoint exists
    if not Path(weights).exists():
        print(f"Path {weights} doesn't exist")
        return

    # Load the pytorch lightning model from the checkpoints
    lit_pylit = lit.load_from_checkpoint(weights)#,loss_func=loss_func,
    #                                 learning_rate=learning_rate,
    #                                 classifier=model)
    model = lit_pylit.classifier
    model.eval()

    # make sure testdir exists 
    testset_path = Path(testset_dir)
    if not testset_path.exists():
        print(f"Testset {testset_path} doesn't exist")
        return

    # Load the files from the test set 
    testfiles = list(testset_path.glob('*'))

    tp = 0
    tn = 0
    fp = 0
    fn = 0
    log_file = Path(results)
    for file in alive_it(testfiles):
        cur_tp, cur_tn, cur_fp, cur_fn, runtime = rnn_predict(model, file)
        tp+=cur_tp
        tn+=cur_tn
        fp+=cur_fp
        fn+=cur_fn
        print(f"tp {tp} | tn {tn} | fp {fp} | fn {fn}")

        # Get the total file size
        stripped_file = strip_file(file)
        file_size = os.path.getsize(stripped_file)
        stripped_file.unlink()


        # Read the log file
        if log_file.exists():
            with open(log_file, 'r') as f:
                cur_data = json.load(f)
        else:
            cur_data = {}

        # update the log file
        cur_data[file.name] = {
            'tp' : tp,
            'tn' : tn,
            'fp' : fp,
            'fn' : fn,
            'runtime' : runtime,
            'filesize': file_size
        }

        # Update the log
        if log_file.exists():
            log_file.unlink()

        # Dump the new log file
        with open(log_file, 'w') as f:
            json.dump(cur_data, f)

    return


if __name__ == "__main__":
    app()
    exit(1)

    OPTIMIZATION = 'O1'

    #TODO: This is best used when I have large similar datasets for O0-Oz
    #       until I have all of those compiled I will manually split
    #with open("TEST_BIN_NAME_SET.json", 'r') as f:
    #    bin_names = json.load(f)['names']

    # 
    rust_train_files = []
    rust_test_files = []

    rust_o0_files = []

    xda_testset= []
    with open('OUT.json', 'r') as f:
        xda_testset= json.load(f)['names']

    for parent in Path("/home/ryan/.ripbin/ripped_bins/").iterdir():
        info_file = parent / 'info.json'
        info = {}
        try:
            with open(info_file, 'r') as f:
                info = json.load(f)
        except FileNotFoundError:
            print(f"File not found: {info_file}")
            continue
        except json.JSONDecodeError as e:
            print(f"JSON decoding error: {e}")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue


        if info['optimization'].upper() in OPTIMIZATION:
            npz_file = parent / "onehot_plus_func_labels.npz"

            if info['binary_name'] in xda_testset:
                rust_test_files.append(npz_file)
            else:
                rust_train_files.append(npz_file)

            #rust_o0_files.append(npz_file)
            #if info['binary_name'] not in bin_names:
            #    rust_train_files.append(npz_file)
            #else:
            #    rust_test_files.append(npz_file)




    # TODO: TEMP: 
    #rust_train_files.extend(rust_test_files)
    #rust_test_files.extend(rust_o0_files[250:])
    #rust_train_files.extend(rust_o0_files[:250])



    metrics, classifier = lit_model_train(rust_train_files)
    print([x.compute() for x in metrics])


    # Create the dataloader for the test files now 
    test_data, test_lbl= gen_one_hot_dataset(rust_test_files ,
                                            num_chunks=1000)

    # TODO: Hardcoded a chache here 
    # BUG: This doesn't have to do with the target tensor error 
    #       beacuse it happens with and without it 
    #_, _, test_data = vsplit_dataset(test_data, (0,0,100)) 
    #_, _, test_lbl = vsplit_dataset(test_lbl,(0,0,100)) 

    #print(test_lbl)

    test_dataset = MyDataset(torch.Tensor(test_data).to(DEVICE), 
                     torch.Tensor(test_lbl).squeeze().to(DEVICE))

    # BUG: Num workers introduced more CUDA Initialization errors
    test_dataloader = DataLoader(test_dataset, batch_size=32, 
                                shuffle=False,
                                drop_last=True)#, num_workers=CPU_COUNT)

    trainer = pylight.Trainer(max_epochs=100)

    classifier.reset_metrics()

    # Get the run time of the module
    start = time.time()
    res = trainer.test(classifier,dataloaders=test_dataloader)
    runtime = time.time() - start

    print(f"Test on {len(rust_test_files)}")
    metrics = [x.compute() for x in classifier.metrics]
    print(metrics)
    print(f"Run time for 1000 chunks on optimization {OPTIMIZATION}: {runtime}")
    print(f"The len of train files was {len(rust_train_files)}")
    print(f"The len of test files was {len(rust_test_files)}")

    test_files = Path("RUST_TEST_FILES.txt")
    with open(test_files, 'w') as f:
        for file in rust_test_files:
            f.write(f"{file.parent}\n")

    #run_info = {
    #    'metrics' : metrics,
    #    'optimization' : OPTIMIZATION,
    #    'train_file_pool' : rust_train_files,
    #    'test_file_pool' : rust_test_files,
    #}

    ## Save the summary
    #with open(f"RNN_SUMMARY_{OPTIMIZATION}.json", 'w') as f:
    #    json.dump(run_info, f)

