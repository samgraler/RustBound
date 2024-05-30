### Cargo

The cargo subcommand provides actions that pertain to pulling 
cargo crates to the local db and db management. 

### Commands:

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

### Important Paths

```python
# Structure:
# $HOME/.crates_io
# |- cloned_crates
#    |- crate1
#    |- crate2
#    |- crate3
Path("~/.crates_io/").expanduser()
```


