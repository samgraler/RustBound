# Bound Detector !! 

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


