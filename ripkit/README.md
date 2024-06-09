
# Welcome! 

BoundDetector started a simple scripts to make research easier, but now has a full fledged CLI to make tasks easier! 

### Research Overview
The main idea of this research was to see if Neural Networks could identify 
function boundaries in Rust Binaries. Then compare the performance to that 
of tools like Ghidra and IDA! 


### Cli Overview (Subject to a lot of change)
1. Automated cloning and compiling of Rust Crates
2. Profiling of dataset based on patterns 
3. Modification of binaries in dataset
4. Ghidra and IDA integrations for script running

Adjacent CLI's have also been made separate from Ripkit...
1. BiRNN training and testing
2. XDA training and testing


### Research in depth
Bound Detector is a comparison of 4 different tools ability to detect
function boundaries in stripped binary files generated from Rust. 

- BiRNN
- XDA
- Ghidra 
- IDA Pro 

Additionally we contribute Ripkit, and cargo_picky. 

*Ripkit* was originally made to parse binary files, and generate 
feature vectors form the binaries. The initial intent was to make it 
easy to pre-process binaries into various different styles of feature 
vectors, and to save the vectors so we have to do less future preprocessing.

*cargo_picky* is a tool to make it easy to generate a large dataset of 
rust generated binary files. Therefore the tool....
1. Pulls crates from crates.io (Ex. cargo_picky pull 100 (pull 100 crates))
2. Compiles the crates with user specified optimization level and arch
3. *For this research we care about the executables* so cargo picky will also
pull the executable files generated from compilation and save them 
Using the tools combined means we quickly generated 1000+ different Rust binary
files, and generated their corresponding feature vectors quickly.


# Future 

Cross optimization training and testing 
New languages 
Cross language training and testing 
New platforms 
Cross platform training and testing 

Improve the flexibility of Ripkit. Ripkit was very convenient *before a good 
feature vector representation was chosen* because it made it easy to 
experiment with different feature vectors. However, it becomes obsolete once
the feature vector is selected. In some cases it was faster to pre-process on 
the fly than it was to load already preprocessed data. 

Ultimately provide bindings and cli to pull analyze crates

# Installation

The following installation steps detail the process of installing all dependencies necessary to use Ripkit on a fresh Ubuntu VM. Ripkit is currently only supported on linux.

This tutorial assumes that the `RustBound` repository has been cloned to the VM. If this in not the case, see the steps below:

```sh
# Step 1: install git
sudo apt install git

# Step 2: clone RustBound from github (the command below uses HTTPS, but you can modify for your preferred cloning method)
git clone https://github.com/UCdasec/RustBound.git
```

## Dependencies

The Ripkit tool depends on the following non-python packages:
1. rustup
2. cargo-clone
3. openssl-devel
4. pkg-config
5. cross
6. docker -or- podman

The steps to install these dependencies are below:
```sh
sudo apt update

# Step 1: install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Step 2: restart shell, or update PATH environment variable (see instructions post rust install)

# Step 3: retrieve any necessary updates
rustup update

# Step 4: install compiler toolchain (necessary for cargo-clone)
sudo apt install build-essential

# Step 5: install cargo-clone 
cargo install cargo-clone

# Step 6: install openssl-devel and pkg-config
sudo apt install pkg-config && sudo apt install libssl-dev

# Step 7: install The cross compiler package 'cross'
cargo install cross --git https://github.com/cross-rs/cross

# Step 8: install a container engine (docker or podman)

# podman is recommended due to its simpler setup process:
sudo apt install podman

# docker is another option, but due to its more elaborate setup, the following website should be used as a reference: https://docs.docker.com/engine/install/ubuntu/
```

## Poetry

Poetry is a tool for dependency management and packaging in Python. It is used to install the necessary python dependencies for Ripkit, and isolates them from the rest of your environment through the use of a python virtual environment. 

Here are the installation steps:
```sh
# Step 1: Install pipx package (used to install poetry)
sudo apt install pipx

# Step 2: install poetry
pipx install poetry

# Step 3: update PATH env var
pipx ensurepath

# Step 4: update poetry
pipx upgrade poetry

# Step 5: cd into the `ripkit` directory (varies depending on where RustBound repository was cloned into)
cd ~/RustBound/ripkit

# Step 6: Activate the virtual environment by creating a nested shell
poetry shell

# Step 7: Install ripkit dependencies 
poetry install
```

## Ghidra

Ghidra is an open source reverse engineering framework, and one of the tools used to demonstrate the performance of the models in this project 

An installation script is provided, and should be run using the following command (from the RustBound/ripkit directory): `python ripkit/main.py ghidra install-ghidra`

Internet connection is required to download and install the necessary dependencies, and this script may take a minute to complete.

## IDA

IDA Pro is a professional reverse engineering framework that requires a license to use. Because of this fact, there is currently no installation process established, and the IDA Pro paths are hard coded in ripkit. In the future, we plan to write a script that installs a free version of IDA if it exists.

# Usage 

Since the dependencies were installed in a virtual environment managed by poetry, before using the Ripkit tool, it is necessary to cd into the project directory (RustBound/ripkit) and run the command `poetry shell` to start the virtual environment.

When you are finished using the tools, the nested shell created by poetry can be exited using the `exit` command

Ripkit commands can be run as follows: `python ripkit/main.py [command] [arguments]`

For a list of commands, use `python ripkit/main.py --help`

Additionally, individual commands will also accept the --help flag for usage information

## Docs

mkdocs is used for documentation. Currently you must serve them youself:
```
mkdocs serve -a 0.0.0.0:8000
```
Docs will then be at http://0.0.0.0:8000
## Roadmap...


- [ ] Overhaul to the database system. Current system is slow and probably would be better implemented with sqlite to support storage of modiffied binaries
