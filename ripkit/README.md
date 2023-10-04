

Going to use cargo binding and ripbin to automate everything 
with data... including feature vector generation


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
