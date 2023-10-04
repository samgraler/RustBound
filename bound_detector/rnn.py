'''
    New model using sliding window size of bytes, and labeling 
    that window of bytes as a function start or not
'''
from torchmetrics.classification import (
    BinaryF1Score, BinaryPrecision, BinaryRecall,
)
import sys
#import matplotlib.pyplot as plt

#from model_runner import log_model, save_json_receipt

import random
import polars as pl

from typing import Optional, Tuple

import torch 
import numpy as np
import logging
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

sys.path.append('../util_dev/ripbin')
#from ripbin import (
#    get_registry, AnalysisType, ProgLang,
#    generate_minimal_unlabeled_features,
#    POLARS_generate_minimal_unlabeled_features,
#    )


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



logging.basicConfig(level=logging.INFO)
BAR_LOGGER = logging.getLogger('alive_progress')

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


app = typer.Typer()
console = Console()


def train_model( model, epochs, train_dataloader, loss_func, optimizer,
                valid_loader):
    '''
    train the model

    Returns
    -------

    list 
    '''

    loss_per_batch = []

    
    bar = alive_it(range(epochs), title='Training')
    for _ in bar:
        loss = None

        # Make sure the model is set to training
        model.train()
        for inp_batch, target in train_dataloader:
            # Get the predication
            out_tensor = model(inp_batch)

            # TODO: temp print the max prob
            #max_prob = torch.max(out_tensor)

            #print("===================")
            #print(inp_batch)
            #print(out_tensor)
            #print(max_prob)
            #print("===================")

            # Calc loss
            loss = loss_func(out_tensor, target)

            # zero grad 
            optimizer.zero_grad()

            # Backward step
            loss.backward()

            # new weights
            optimizer.step()

        model.eval()  # Set the model to evaluation mode
        val_loss = 0.0
        with torch.no_grad():
            for batch_data, target in valid_loader:
                out_tensor = model(batch_data)  # Forward pass
                val_loss += loss_func(out_tensor, target).item()
            avg_loss = val_loss/len(valid_loader)
            print(f"Validation loss {avg_loss}")
            loss_per_batch.append(avg_loss)

    return loss_per_batch

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

    
    tot_rows = inpAr.shape[0]

    test_index = tot_rows // 100 * split[0]
    validate_index = test_index + tot_rows // 100 * split[1]

    return (inpAr[:test_index,:], 
            inpAr[test_index: validate_index,:], 
            inpAr[validate_index:, :]
            )


def gen_one_hot_dataset_ENDS(files: list[Path], num_chunks):

    inp_array = np.empty((num_chunks,1000,255), dtype=np.float64)
    label_arr = np.empty((num_chunks,1000, 1), dtype=np.float64)

    data_info = []

    for i in alive_it(range(num_chunks), title="Generating dataset"):

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

    return inp_array, label_arr

def gen_one_hot_dataset(files: list[Path], num_chunks):

    inp_array = np.empty((num_chunks,1000,255), dtype=np.float64)
    label_arr = np.empty((num_chunks,1000, 1), dtype=np.float64)

    data_info = []

    for i in alive_it(range(num_chunks), title="Generating dataset"):

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

            #chunk = data[index:][:1000]

            inp_array[i,:,:] = chunk[:,3:]
            label_arr[i,:,:] = chunk[:,0].reshape((1000,1))
            data_info.append((selected_file, index))

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
    train_dataloader = DataLoader(train_dataset, batch_size=32, 
                                shuffle=False,
                                drop_last=True)
    valid_dataloader = DataLoader(valid_dataset, batch_size=32, 
                                shuffle=False,
                                drop_last=True)
    test_dataloader = DataLoader(test_dataset, batch_size=32, 
                                shuffle=False,
                                drop_last=True)

    return train_dataloader, valid_dataloader, test_dataloader

def rnn_model_train(input_files, 
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

    # Init the model
    model = recreatedModel(input_size, hidden_size, layers)
    model.to(DEVICE)


    train_loader, valid_loader, test_loader = create_dataloaders(
            input_files, cache_file=cache_file,ends=ends)

    # Summary of the model 
    if print_summary:
        summary(model, (32,1000,255))

    # Binary cross entrophy loss
    loss_func = nn.BCELoss()

    # Adam optimizer
    #optimizer = optim.Adam(model.parameters(), lr=0.005)
    optimizer = optim.RMSprop(model.parameters(), lr=learning_rate)

    # Train the model
    losses = train_model(model, epochs, train_loader, 
                         loss_func, optimizer, valid_loader)


    # Metrics to use on the model
    metrics = [
        BinaryF1Score(threshold=threshold),
        BinaryPrecision(threshold=threshold),
        BinaryRecall(threshold=threshold),
    ]

    # Test the model and get metric results
    results = test_model( model, test_loader,  metrics)

    return losses, results, [train_loader, valid_loader, test_loader], model


def test_model_on_bin(model, file,threshold=0.9):

    data = []
    # Load the selected .npz file
    with np.load(file, mmap_mode='r', 
                 allow_pickle=True) as npz_file:
        # Get the first (and only) file array that is in the 
        # npz file
        data = npz_file[npz_file.files[0]]

    # go over 1000 byte increments in the file and see what I 
    # get 
    chunk_labels = []
    for i in range(0,data.shape[0]-1000, 1000):

        chunk = data[i:i+1000,:]
        unlbl_chunk = chunk[:,3:]


            #label_arr[i,:,:] = chunk[:,0].reshape((1000,1))
            #data_info.append((selected_file, index))

            #chunk = data[index:][:1000]

        inp = torch.Tensor(unlbl_chunk).unsqueeze(0).to(DEVICE)
        pred_label = model(inp)
        pred_label = torch.where(pred_label >= threshold, 
                                 torch.tensor(1), torch.tensor(0))

        #res = np.concatenate(( unlbl_chunk,
                              # pred_label.cpu().numpy().transpose()
                              #), axis=1)
        chunk_labels.append((i,i+1000, 
                             pred_label.cpu().numpy().transpose()))

    return chunk_labels



def _train_test_real_test():

    reg = get_registry()

    files = reg[reg['analysis_type'] == AnalysisType.ONEHOT_PLUS_FUNC_LABELS.value]
    files = files[files['prog_lang'] == ProgLang.RUST.value]

    # List of analysis file paths 
    rust_files = files['analysis_path'].to_list()

    # Get a single file for real testing
    random_file = random.choice(rust_files)

    rust_files.remove(random_file)

    # Train and test a model
    losses, results = rnn_model_train(rust_files)

    print(f"Chosen file is {random_file}")
    # Get labels for a file
    labels = test_model_on_bin(model, random_file)

    for index_start, index_end, lbl in labels:
        func_starts = lbl[lbl[:, 0] == 1]
        func_nonstarts = lbl[lbl[:, 0] == 0]
        print(f"Index {index_start} | Number of starts {len(func_starts)}")
        print(f"Index {index_start} | Number of nonstarts{len(func_nonstarts)}")
        for i, row in enumerate(lbl):
            # Will be 1000 in lbl
            if row == 1:
                print(f"Start at {index_start+i}")

    print(f"Chosen file is {random_file}")

    return


def label_with_model(model, data, threshold=.9):

    # List of 1000xdata.shape[1]+1 np chunks

    tot_data = np.empty((data.shape[0],data.shape[1]+1))
    for i in alive_it(range(0,data.shape[0]-1000, 1000), title="LabelingFunctions"):

        chunk = data[i:i+1000,:]

        inp = torch.Tensor(chunk).unsqueeze(0).to(DEVICE)
        pred_label = model(inp)

        lbls = torch.where(pred_label >= threshold, 
                                 torch.tensor(1), torch.tensor(0)).cpu().numpy()

        labeled_chunk = np.concatenate((chunk, lbls.transpose()),axis=1)
        tot_data[i:i+1000, : ] = labeled_chunk
        #tot_data = np.vstack((tot_data,labeled_chunk))

    return tot_data


def get_function_start_addrs(model, data):
    '''
    Use the model to return a list of the function start addresses
    '''

    addrs = data[:,0].transpose().reshape(-1,1)
    data = data[:,1:]

    # Iterate over data in chunks off 1000 and pass to model 
    labeled_data =  label_with_model(model, data)
    #addrs_labeled = np.concatenate((addrs,labeled_data), axis=1)
    addrs_labeled = np.hstack((addrs, labeled_data))

    # Return a list of address where the function start occurs
    # addr, byte, lbl
    #starts = addrs_labeled[addrs_labeled[:,2] == 1]

    #print(starts)

    return addrs_labeled


def rust_train_model_helper(opt_lvl, learning_rate,ends=False):

    # Get the registry of available analyzed files
    reg = get_registry()




    files = reg[reg['analysis_type'] == AnalysisType.ONEHOT_PLUS_FUNC_LABELS.value]
    files = files[files['prog_lang'] == ProgLang.RUST.value]
    files = files[files['opt_level'] == opt_lvl]

    # List of analysis file paths 
    rust_files = files['analysis_path'].to_list()

    cache_file = Path(f".CACHE_OPT{opt_lvl}.npz")

    losses, results, loaders, model = rnn_model_train(rust_files,cache_file,
                                               ends=ends)

    return rust_files, losses, results, loaders, model

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


#def np_generator(file: Path):
#    print(file)
#    with np.load(file, mmap_mode='r', allow_pickle=True) as f:
#        for row in f[f.files[0]]:
#            yield row


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
                #print(f"{start[0]}, ")

#result = A[B == 1]

    #for i in alive_it(range(0,df.shape[0]-1000, 1000), title="LabelingFunctions"):
    #        break

    #    chunk = data[i:i+1000,:]

    #    inp = torch.Tensor(chunk).unsqueeze(0).to(DEVICE)
    #    pred_label = model(inp)

    #    lbls = torch.where(pred_label >= threshold, 
    #                             torch.tensor(1), torch.tensor(0)).cpu().numpy()

    #    tot_data[i:i+1000, :] = np.concatenate((chunk, lbls.transpose()),axis=1)

    #    #tot_data[i:i+1000, : ] = labeled_chunk
    #    #tot_data = np.vstack((tot_data,labeled_chunk))


    ##addrs_labeled = np.concatenate((addrs,labeled_data), axis=1)
    ##tot_data = np.hstack((addrs, tot_data))


    #print(tot_data)


    #print("DONE!")







@app.command()
def detect_boundaries(
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


    cached_file= Path(f".cache_for_{file}.csv").resolve()

    if not cached_file.exists():
        df = None
        print("Generating polars dataframe")
        for i, sub_df in enumerate(POLARS_generate_minimal_unlabeled_features(Path(file), 
                                               use_one_hot=True)):
            if i % 100 == 0:
                print(i)
            if df is None:
                df = pl.DataFrame({'address':[],
                                   'byte':[],
                                   })
                continue
            one_hot = pl.Series(sub_df[1:], dtype=pl.Boolean)

            print(sub_df[0])
            print(one_hot)
            new_data =  {'address':sub_df[0], 
                         'byte' : one_hot}

            df = df.vstack(pl.DataFrame(new_data))

        if df is None:
            raise Exception("Empty df from file {}".format(file))

        print("Writing dataframe to csv")
        df.write_csv(cached_file)
    else:
        print("Loading cached file")
        df = pl.read_csv(cached_file)
    print("Labeling....!")

    #for i in alive_it(range(0,df.shape[0]-1000, 1000), title="LabelingFunctions"):
    #        break

    #    chunk = data[i:i+1000,:]

    #    inp = torch.Tensor(chunk).unsqueeze(0).to(DEVICE)
    #    pred_label = model(inp)

    #    lbls = torch.where(pred_label >= threshold, 
    #                             torch.tensor(1), torch.tensor(0)).cpu().numpy()

    #    tot_data[i:i+1000, :] = np.concatenate((chunk, lbls.transpose()),axis=1)

    #    #tot_data[i:i+1000, : ] = labeled_chunk
    #    #tot_data = np.vstack((tot_data,labeled_chunk))


    ##addrs_labeled = np.concatenate((addrs,labeled_data), axis=1)
    ##tot_data = np.hstack((addrs, tot_data))


    #print(tot_data)


    #print("DONE!")


if __name__ == "__main__":

    app()
