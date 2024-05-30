
This page will serve as the main reference guide to the CLI usage. 
This page will not provide environment setup or install.

### Overview 

***Running ripkit***
Currenlty ripkit does not have a true release yet. Therefore to run ripkit 
run the command:
```bash
python ripkit/main.py [COMMAND] [OPTIONS]
```

Ripkit is divided logically into subcommands. Each subcommand may 
have a few or many of it's own commands. Currently the main 
subcommands are:

1. cargo
    - Interact with a local Rust Crate database
    - [cargo_cli](cargo_cli.md)
2. ripbin
    - Complile Rust crates and save to / interact with db 
    - [ripbin_cli](ripbin_cli.md)
3. ghidra
    - Use ghidra to recover function boundaries
    - [ghidra_cli](ghidra_cli.md)
4. ida
    - Use IDA Pro to recover function boudnaries
    - [ida_cli](ida_cli.md)
5. profile
    - Profile datasets for patterns in prologues and epilogues
    - [profile_cli](profile_cli.md)
6. modify
    - Modify sets of binaries to 'trick' models
    - [modify_cli](modify_cli.md)

*And the main command will have some of it's own runnable command*
