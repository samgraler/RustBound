
This page will serve as the main reference guide to the CLI usage. This page 
will not provide environment setup or install.

### Overview 

***Running ripkit***
Currenlty ripkit does not have a true release yet. Therefore to run ripkit 
run the command:
```bash
python ripkit/main.py [COMMAND] [OPTIONS]
```

Ripkit is divided logically into subcommands. Each subcommand may have a few 
or many of it's own commands. Currently the main subcommands are:

1. cargo
2. ripbin
3. ghidra
4. ida
5. profile
6. modify

### Cargo

***Overview:*** 

The cargo subcommand provides actions that pertain to pulling cargo crates. 
Really for now thats about it.

***Commands:***

1. clear-cloned
    - Delete all the locally cloned crates
2. clone
    - Clone a specific crate name to the local db
3. clone-many-exe
    - Clone many crates that have executables 
4. init 
    - Init the local crates_io
5. is-crate-exe
    - See if a remote crate produces an executable
6. list-cloned 
    - Lis the locally cloned crates
7. show-cratesio 
    - TODO

***Important Paths***
```python
# Structure:
# $HOME/.crates_io
# |- cloned_crates
#    |- crate1
#    |- crate2
#    |- crate3
Path("~/.crates_io/").expanduser()
```


### Ripbin

***Overview:***
The ripbin subcommand is not intuative initially. This subcommand is provides
actions to:
1. Build crates found in the local crates io


***Commands:***


### Ghidra 

***Overview:***
***Commands:***

### IDA 

***Overview:***
***Commands:***
