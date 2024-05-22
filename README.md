# RustBound !! 

Analysis of current methods of Function Boundary Detection in Stripped Binary Files on executable files generated from Rust source code

The main components of this repository are:
1. Ripkit : tool for cloning and compiling rust binaries
2. XDA : Implementation from "XDA: Accurate, Robust Disassembly with Transfer Learning" of a function boundary detector
3. ghidra_bench: tool for benchmarking ghidra




# Ripkit dependencies 

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


# Training BiRNN...

*Input:* The BiRNN requires ".npy" files for training. These can be generated using the command:
```bash
cli.py gen-npzs
```
This will extract the .text section of the provided binaires and generate feature vectors for the model.


*Training:* Use the command:
```bash
cli.py train-on
```

*Testing:* Use the command:
```bash
cli.py test-on-nongpu
```

# Training XDA... 
There are some preprocesing steps that are best exapline dby XDA's
github repo. 

Once those are done, the cli tool ryan_cli.py is what I used to 
help me train test and log expirements


# Running IDA / Ghidra

Ripkit has just one function to support extracting function bounds from a file uploaded to IDA. Look at the command for ripkit 'ida':
```bash
python ripkit/main.py ida
```
Similarly ghidra is supported as well:
```bash
python ripkit/main ghidra
```

