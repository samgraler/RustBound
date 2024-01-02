
# Welcome 

Bound Detector is a comparison of 4 different tools ability to detect
function boundaries in stripped binary files generated from Rust. 

- BiRNN
- XDA
- Ghidra 
- IDA Pro 

Additionally we contribute ripkit, and cargo_picky. 

*ripkit* was originally made to parse binary files, and generate 
feature vectors form the binaries. The initial intent was to make it 
easy to preprocess binaries into various different styles of feature 
vectors, and to save the vectors so we have to do less future preprocessing.

*cargo_picky* is a tool to make it easy to generate a large dataset of 
rust generated binary files. Therefore the tool....
1. Pulls crates from crates.io (Ex. cargo_picky pull 100 (pull 100 crates))
2. Compiles the crates with user specified optimization level and arch
3. *For this research we care about the executables* so cargo picky will also
pull the exectuable files generated from compilation and save them 

Using the tools combined means we quickly generated 1000+ different Rust binary
files, and generated their corresponding feature vectors quickly.


# Future 

Cross optimization training and testing 
New languages 
Corss langauge trainign and testing 
New platforms 
Cross platform training and testing 

Improve the flexability of ripkit. Ripkit was very convient *before a good 
feature vector representation was chosen* because it made it easy to 
experiment with different feature vectors. However, it becomes obsolete once
the feature vector is selected. In some cases it was faster to preprocess on 
the fly than it was to load already preprocessed data. 



Ultimately provide bindings and cli to pull analyze crates


# Acouple dependencies 

Command:
rustup
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

cargo
```
rustup update
```

cargo-clone
openssl-devel
pkg-config

```
sudo apt install pkg-config
sudo apt install libssl-dev
cargo install cargo-clone
```

The cross compiler package cross
```
cargo install cross --git https://github.com/cross-rs/cross
```

Container engine... I use podman because it doesn't need root
```
sudo apt install podman
```
