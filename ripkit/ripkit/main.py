import typer
import shutil
from itertools import chain
import lief
import math
import json
import pandas as pd
from typing_extensions import Annotated
from alive_progress import alive_bar, alive_it
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()
app = typer.Typer()


from ripkit.cargo_picky import (
    gen_cargo_build_cmd,
    get_target_productions,
    is_executable,
    init_crates_io,
    crates_io_df,
    clone_crate,
    is_remote_crate_exe,
    LocalCratesIO,
    build_crate,
    RustcStripFlags,
    RustcOptimization,
    RustcTarget
)

from ripkit.ripbin import (
    save_lief_ground_truth,
    get_functions,
    save_analysis,
    calculate_md5,
    RustFileBundle,
    generate_minimal_labeled_features,
    DB_PATH,
    AnalysisType,
    FileType,
    Compiler,
    ProgLang,
    RustcOptimization,
)


def build_analyze_crate(crate, opt, target, filetype,
                        strip = RustcStripFlags.NOSTRIP,
                        use_cargo=True):
    '''
    Helper function to build then analyze the crate
    '''


    # Build the crate 
    build_crate(crate, opt, target, strip,
                        use_cargo=use_cargo)

    # Need this to get the build command 
    crate_path = Path(LocalCratesIO.CRATES_DIR.value).resolve().joinpath(crate)

    # Need the build command for the bundle info 
    build_cmd = gen_cargo_build_cmd(crate_path, target, strip, opt)


    # Get files of interest from the crate at the target <target>
    files_of_interest = [x for x in get_target_productions(crate, target) 
                            if is_executable(x)]

    if files_of_interest == []:
        print(f"Crate {crate} had no build executable productions")
        # TODO: in the crates_io cache which cloned pkgs don't build any 
        #       files of interest so they are not rebuilt
        return 99

    # The only file in the list should be the binary
    binary = files_of_interest[0]

    # Create the file info
    binHash = calculate_md5(binary)

    # Create the file info
    info = RustFileBundle(binary.name,
                          binHash,
                          target.value,
                          filetype,
                          opt.value,
                          binary.name,
                          "",
                          build_cmd)


    # Generate analysis
    data = generate_minimal_labeled_features(binary)

    # TODO: Anlysis not being saved with target or ELF vs PE?

    try:
        # Save analyiss
        save_analysis(binary,
                        data,
                        AnalysisType.ONEHOT_PLUS_FUNC_LABELS,
                        info,
                        overwrite_existing=False)
    except Exception as e:
        print(f"Exception {e} in crate {crate}")

    return 0


# Load the binary and 
def gen_data_raw_func_bound(path: Path, output: Path):
    #TODO: Use lief to get the .text section of the binary and but here 
    #      (... or is it use lief to get every byte from the file and put here?...)

    functions = get_functions(path)

    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    func_end_addrs = {} 
    for start, info in func_start_addrs.items():
        # NOTE: THIS IS IMPORTANT
        # Ignoring functions that are of zero length
        if info[1] > 0:
            func_end_addrs[start+info[1]] = info[0]


    parsed_bin = lief.parse(str(path.resolve()))
    text_section = parsed_bin.get_section(".text")

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = parsed_bin.imagebase

    with open(output, 'w') as out:
        for i, byte in enumerate(text_bytes):

            # Starting at the text section, the address of each byte is 
            # the base_address + the text_section's virtual address 
            # plus the number of bytes we've gone over 
            address = base_address + text_section.virtual_address + i
            func_start = True if address in func_start_addrs.keys() else False
            func_end = True if address in func_end_addrs.keys() else False
            func_middle = True if not func_start and not func_end else False

            if func_start:
                lbl = 'F'
            elif func_end:
                lbl= 'R'
            else:
                lbl = '-'
            line = f"{str(hex(address))[2:]} {lbl}"
            #print(line)
            out.write(line+'\n')

    #print("WARNING THIS ONLY HAS THE .TEXT section")
    return



@app.command()
def generate_xda_func_finetune_files():
    return
@app.command()
def generate_xda_train_in_files():
    '''
    '''
    #TODO: Does XDA test on data used for finetuning
    #TODO: Does XDA test on data used for pre-training (pre-training data 
    #           has no labels)
    #TODO: Does XDA fine-tune on data used in pre-training and vic versa 
    # 
    # XDA -> pre-training, has no labels 


    # Data directories:
    # 1. data-src: USED to generate data-bin. I I I put data here 
    #       | pretrain_all
    #       | funcbound
    #   a. In pretrain_all there is a train.in file without all the bytes from all inputs
    #       concatenated and demilited every 512 characters by a newline 
    #   b. In func bound there is a train.data train.label, train.data is all bytes from all
    #       inputs concatenated and demilited every 512 characters by a newline, but the
    #       train.data label is a corresponding label for every byte either (S,E,N) Start
    #       End, Neither
    # 
    # 2. data-bin: USED directly by the pretraining process, and finetuning 
    #       | pretrain_all : bin_data_used_for_pretraining
    #       | funcbound    : bin_data_used_for_fine_tuning
    # 
    # 3. data-raw: NOT used for pretraining NOT used for finetuning
    #               USED for testing individual files, USED in play_func_bound

    return


def get_all_bins()->dict:
    '''
    Get all the binaries by the optimization
    '''

    bin_by_opt = {
        '0': [],
        '1': [],
        '2': [],
        '3': [],
        'z': [],
        's': [],
    }


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

        # Define the binary file name
        bin_file = parent / info['binary_name']

        opt = info['optimization']

        if opt not in bin_by_opt.keys():
            bin_by_opt[opt] = []
        else:
            bin_by_opt[opt].append(bin_file.resolve())
    return bin_by_opt




#TODO: I don't think this should exist or be used 
@app.command()
def generate_unlbl_xda_in_files(
    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
    bit: Annotated[str, typer.Argument(help="32 or 64")],
    filetype: Annotated[str, typer.Argument(help="pe or elf")],
    ):
    if opt_lvl == "O0":
        opt = RustcOptimization.O0
    elif opt_lvl == "O1":
        opt = RustcOptimization.O1
    elif opt_lvl == "O2":
        opt = RustcOptimization.O2
    elif opt_lvl == "O3":
        opt = RustcOptimization.O3
    elif opt_lvl == "Oz":
        opt = RustcOptimization.OZ
    elif opt_lvl == "Os":
        opt = RustcOptimization.OS
    else:
        return

    if bit == "64":
        if filetype == "elf":
            target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.X86_64_PC_WINDOWS_GNU 
        else:
            return
    elif bit == "32":
        if filetype == "elf":
            target = RustcTarget.I686_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.I686_PC_WINDOWS_GNU 
        else:
            return
    else:
        return

    # List of all binaries to generate ground truth for 
    files = []
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


        if info['optimization'].upper() in opt.value.upper():
            #npz_file = parent / "onehot_plus_func_labels.npz"

            # Append the binary to files 
            bin_path = parent / info['binary_name']
            files.append(bin_path)

    for file in alive_it(files):
        # Parse every byte in the summary 
        
        # Write two columns in hex file 

        # BYTE (in hext no 0x) | F or R or '-' F=start R=end '-'=neither
        #save_lief_ground_truth(file)
        gen_data_raw_func_bound(file, file.parent / 'xda_lbled_in')

    return 

@app.command()
def generate_lief_ground_truth(
    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
    bit: Annotated[str, typer.Argument(help="32 or 64")],
    filetype: Annotated[str, typer.Argument(help="pe or elf")],
    ):
    '''
    Generate lief ground turth for all binarys in db of opt and target
    '''
    if opt_lvl == "O0":
        opt = RustcOptimization.O0
    elif opt_lvl == "O1":
        opt = RustcOptimization.O1
    elif opt_lvl == "O2":
        opt = RustcOptimization.O2
    elif opt_lvl == "O3":
        opt = RustcOptimization.O3
    elif opt_lvl == "Oz":
        opt = RustcOptimization.OZ
    elif opt_lvl == "Os":
        opt = RustcOptimization.OS
    else:
        return

    if bit == "64":
        if filetype == "elf":
            target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.X86_64_PC_WINDOWS_GNU 
        else:
            return
    elif bit == "32":
        if filetype == "elf":
            target = RustcTarget.I686_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.I686_PC_WINDOWS_GNU 
        else:
            return
    else:
        return

    # List of all binaries to generate ground truth for 
    files = []
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


        if info['optimization'].upper() in opt.value.upper():
            #npz_file = parent / "onehot_plus_func_labels.npz"

            # Append the binary to files 
            bin_path = parent / info['binary_name']
            files.append(bin_path)

    for file in alive_it(files):
        save_lief_ground_truth(file)

    return 

@app.command()
def list_functions(
        binary: Annotated[str, typer.Argument()],
        count: Annotated[bool, typer.Option()] = False,
    ):
    '''
    Print the list of function that lief detects
    '''

    path = Path(binary)
    functions = get_functions(path)
    func_start_addrs = {x.addr : (x.name, x.size) for x in functions}

    # Fancy line to get the longest addr and round it up to 2 bytes 
    max_len = math.ceil(max(len(str(x)) for x in func_start_addrs.keys()) / 2) * 2

    for addr, info in func_start_addrs.items():
        #print(f"0x{str(int(hex(addr),16)).zfill(max_len)}: {info[0]}")
        #print(f"{str(hex(addr)).zfill(max_len)}: {info[0]}")
        print(f"{hex(addr)}: {info[0]}")
    if count:
        print(f"{len(func_start_addrs.keys())} functions")

    return
    

@app.command()
def init():
    '''
    Initialize ripkit with rust data base,
    and register files
    '''
    init_crates_io()
    return

@app.command()
def is_crate_exe(
        crate: Annotated[str, typer.Argument()]):

    print(is_remote_crate_exe(crate))
    return


@app.command()
def cargo_clone(
        crate: Annotated[str, typer.Argument()]):

    clone_crate(crate)

    return

@app.command()
def show_cratesio(
    column: 
        Annotated[str, typer.Option()] = '',
    ):
    '''
    Show the head of cratesw io dataframe
    '''

    # Get the df
    crates_df = crates_io_df()


    if column == '':
        print(crates_df.head())
    else:
        print(crates_df[column])
    print(crates_df.columns)


@app.command()
def clone_many_exe(
    number: Annotated[int,typer.Argument()],
    verbose: Annotated[bool,typer.Option()] = False):
    '''
    Clone many new executable rust crates.
    '''

    # Get the remote crate reg
    reg = crates_io_df()

    # List of crate current installed
    installed_crates = [x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() 
        if x.is_dir()
    ]

    # List of crate names
    crate_names = [x for x in reg['name'].tolist() if x not in installed_crates]
    print("Finding uninstalled registry...")

    # With progress bar, enumerate over the registry 
    cloned_count = 0
    with alive_bar(number) as bar:
        for i, crate in enumerate(crate_names):
            if i % 100 == 0:
                print(f"Searching... {i} crates so far")
            # See if the crate is exe before cloning
            if is_remote_crate_exe(crate):
                print(f"Cloning crate {crate}")
                try:
                    if verbose:
                        clone_crate(crate, debug=True)
                    else:
                        clone_crate(crate)

                    cloned_count+=1
                    bar()
                except Exception as e:
                    print(e)
                    #bar(skipped=True)
                #bar(skipped=True)
            # Break out of the loop if enough have cloned
            if cloned_count >= number:
                break


@app.command()
def build(
    crate: Annotated[str, typer.Argument(help="crate name")],
    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
    bit: Annotated[str, typer.Argument(help="32 or 64")],
    filetype: Annotated[str, typer.Argument(help="pe or elf")],
    strip: Annotated[bool, typer.Option()] = False,
    ):
    '''
    Build a crate for a specific target
    '''

    #TODO: For simpilicity I prompt for only
    # 64 vs 32 bit and pe vs elf. Really I 
    # should prompt for the whole target arch
    # b/c theres many different ways to get
    # a 64bit pe  or 32bit elf 

    if opt_lvl == "O0":
        opt = RustcOptimization.O0
    elif opt_lvl == "O1":
        opt = RustcOptimization.O1
    elif opt_lvl == "O2":
        opt = RustcOptimization.O2
    elif opt_lvl == "O3":
        opt = RustcOptimization.O3
    elif opt_lvl == "Oz":
        opt = RustcOptimization.OZ
    elif opt_lvl == "Os":
        opt = RustcOptimization.OS
    else:
        print("UNknown opt")
        return

    if bit == "64":
        if filetype == "elf":
            target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.X86_64_PC_WINDOWS_GNU 
        else:
            print("UNknown filetype")
            return
    elif bit == "32":
        if filetype == "elf":
            target = RustcTarget.I686_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.I686_PC_WINDOWS_GNU 
        else:
            print("UNknown filetype")
            return
    else:
        print("UNknown bit")
        return

    if not strip:
        strip_lvl = RustcStripFlags.NOSTRIP
    else:
        # SYM_TABLE is the all the symbols
        strip_lvl = RustcStripFlags.SYM_TABLE


    if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
        build_crate(crate, opt, target, strip_lvl,
                    use_cargo=True, debug=True)
    else:
        build_crate(crate, opt, target, strip_lvl,debug=True)

    print(f"Crate {crate} built")
    return


@app.command()
def build_all(
    opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
    bit: Annotated[str, typer.Argument(help="32 or 64")],
    filetype: Annotated[str, typer.Argument(help="pe or elf")],
    strip: Annotated[bool, typer.Option()] = False,
    ):
    '''
    Build all the installed crates
    '''

    #TODO: For simpilicity I prompt for only
    # 64 vs 32 bit and pe vs elf. Really I 
    # should prompt for the whole target arch
    # b/c theres many different ways to get
    # a 64bit pe  or 32bit elf 

    if opt_lvl == "O0":
        opt = RustcOptimization.O0
    elif opt_lvl == "O1":
        opt = RustcOptimization.O1
    elif opt_lvl == "O2":
        opt = RustcOptimization.O2
    elif opt_lvl == "O3":
        opt = RustcOptimization.O3
    elif opt_lvl == "Oz":
        opt = RustcOptimization.OZ
    elif opt_lvl == "Os":
        opt = RustcOptimization.OS
    else:
        return

    if bit == "64":
        if filetype == "elf":
            target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.X86_64_PC_WINDOWS_GNU 
        else:
            return
    elif bit == "32":
        if filetype == "elf":
            target = RustcTarget.I686_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.I686_PC_WINDOWS_GNU 
        else:
            return
    else:
        return

    if not strip:
        strip_lvl = RustcStripFlags.NOSTRIP
    else:
        # SYM_TABLE is the all the symbols
        strip_lvl = RustcStripFlags.SYM_TABLE








    # List of crate current installed
    installed_crates = [x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
    ]

    for crate in alive_it(installed_crates):

        if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
            build_crate(crate, opt, target, strip_lvl,
                        use_cargo=True, debug=True)
        else:
            build_crate(crate, opt, target, strip_lvl)



@app.command()
def list_cloned():
    '''
    List the cloned crates
    '''

    # List of crate current installed
    installed_crates = [x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()]

    for crate in installed_crates:
        print(crate)
    print(f"Thats {len(installed_crates)} crates")
                        


@app.command()
def analyze(bin_path: Annotated[str, typer.Argument()],
            language: Annotated[str, typer.Argument()],
            opt_lvl: Annotated[str, typer.Argument(help="O0, O1, O2, O3, Oz, Os")],
            bit: Annotated[str, typer.Argument(help="32 or 64")],
            filetype: Annotated[str, typer.Argument(help="pe or elf")],
            save: Annotated[bool, typer.Option()] = True,
            ):
    '''
    Analyze binary file 
    '''

    binary = Path(bin_path).resolve()
    if not binary.exists():
        print(f"Binary {binary} doesn't exist")
        return

    # Generate analysis
    print("Generating Tensors...")
    data = generate_minimal_labeled_features(binary)
    print("Tensors generated")


    # Create the file info
    print("Calculating bin hash...")
    binHash = calculate_md5(binary)
    print("bin hash calculated...")


    # TODO: Anlysis not being saved with target or ELF vs PE?


    # Create the file info
    info = RustFileBundle(binary.name,
                          binHash,
                          "",
                          filetype,
                          opt_lvl,
                          binary.name,
                          "",
                          "")

    print("Saving Tensor and binary")
    # Save analyiss
    save_analysis(binary,
                    data,
                    AnalysisType.ONEHOT_PLUS_FUNC_LABELS,
                    info,
                    overwrite_existing=False)
    print("Done!")


@app.command()
def stats():
    '''
    Print stats about the rippe binaries
    '''

    stats = {
        'total':0,
        'num_opt0': 0,
        'num_opt1': 0,
        'num_opt2': 0,
        'num_opt3': 0,
        'num_optz': 0,
        'num_opts': 0,
    }

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

        if '0' in info['optimization']:
            stats['num_opt0']+=1
        if '1' in info['optimization']:
            stats['num_opt1']+=1
        if '2' in info['optimization']:
            stats['num_opt2']+=1
        if '3' in info['optimization']:
            stats['num_opt3']+=1
        if 'z' in info['optimization']:
            stats['num_optz']+=1
        if 's' in info['optimization']:
            stats['num_opts']+=1

        stats['total'] +=1

    for key, value in stats.items():
        print(f"{key} = {value}")
    return

@app.command()
def export_dataset(
    opt_lvl: Annotated[str, typer.Argument()],
    bit: Annotated[int, typer.Argument()],
    filetype: Annotated[str, typer.Argument()],
    output_dir: Annotated[str, typer.Option(
        help="Save the binaries to a directory")]="",
    output_file: Annotated[str, typer.Option(
        help="Save the binaries paths to a file")]="",
    min_text_bytes: Annotated[int, typer.Option()]=2000,
    drop_dups: Annotated[bool, typer.Option()]=True,
    ):
    '''
    Generate a dataset of files from the ripbin database.
    Either copy all the binaries to a output directory 
    -or-
    Create a file containing the absolute paths to the binaries
    '''

    if opt_lvl not in ['0','1','2','3','z','s']:
        print("opt lvl must be 0 1 2 3 z s")
        return

    out_to_dir = False
    out_to_file = False

    if output_dir != "":
        out_to_dir = True

        out_dir = Path(output_dir)

        if out_dir.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_dir.resolve()}")
            return

    if output_file != "":
        out_to_file = True
        out_file = Path(output_file)
        if out_file.exists():
            print("The output directory already exists, please remove it:!")
            print("Run the following command if you are sure...")
            print(f"rm -rf {out_file.resolve()}")
            return


    if not out_to_file and not out_to_dir:
        print("No output to file or directory given")
        return

        return

    # Get a dictionary of all the binaries that are in the ripbin db
    bins = get_all_bins()

    # Create the set of binary names that ripbin has a binary for as long 
    # as the binary has been compiled for all optimization levels
    set_of_names = set([x.name for x in bins[opt_lvl]])
    for key in bins.keys():
        set_of_names= set_of_names.intersection([x.name for x in bins[key]])

    print(f"Found {len(set_of_names)} bins that are present in all opt lvls")

    # Get a list of pathlib objects for the binaries 
    potential_bins = [x for x in bins[opt_lvl] if x.name in set_of_names]

    #TODO: Binary files can have the same name if they come from different 
    #       packages, for now I'm not allowing these to be in any dataset
    o0_name_set =  [x.name for x in potential_bins]
    dup_names = []
    for bin in o0_name_set:
        if o0_name_set.count(bin) > 1:
            dup_names.append(bin)
    if dup_names != []:
        print(f"Dropping {len(dup_names)} binaries with matching names")

    bins = [x for x in potential_bins if x.name not in dup_names]

    final_binset = []
    for bin in track(bins, description=f"Checking {len(bins)} bin sizes..."):
        parsed_bin = lief.parse(str(bin.resolve()))

        # Get the text section and the bytes themselse
        text_section = parsed_bin.get_section(".text")
        num_text_bytes = len(text_section.content)
        if num_text_bytes > min_text_bytes:
            final_binset.append(bin)

    if out_to_file:
        with open(output_file,'w') as f:
            f.write("\n".join(bin.resolve for bin in final_binset))

    if out_to_dir:
        out_dir = Path(output_dir)
        out_dir.mkdir()
        for bin in track(bins, description=f"Copying {len(final_binset)}..."):
            dest_file = out_dir / bin.name
            shutil.copy(bin.resolve(),dest_file.resolve())

    return


@app.command()
def build_analyze_all(
    opt_lvl: Annotated[str, typer.Argument()],
    bit: Annotated[int, typer.Argument()],
    filetype: Annotated[str, typer.Argument()],
    stop_on_fail: Annotated[bool,typer.Option()]=False,
    force_build_all: Annotated[bool,typer.Option()]=False,
    ):
    '''
    Build and analyze pkgs
    '''
    if opt_lvl == "O0":
        opt = RustcOptimization.O0
    elif opt_lvl == "O1":
        opt = RustcOptimization.O1
    elif opt_lvl == "O2":
        opt = RustcOptimization.O2
    elif opt_lvl == "O3":
        opt = RustcOptimization.O3
    elif opt_lvl == "Oz":
        opt = RustcOptimization.OZ
    elif opt_lvl == "Os":
        opt = RustcOptimization.OS
    else:
        print("Invalid opt lvl")
        return

    if bit == 64:
        if filetype == "elf":
            target = RustcTarget.X86_64_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.X86_64_PC_WINDOWS_GNU 
        else:
            print("Invlaid filetype")
            return
    elif bit == 32:
        if filetype == "elf":
            target = RustcTarget.I686_UNKNOWN_LINUX_GNU
        elif filetype == "pe":
            target = RustcTarget.I686_PC_WINDOWS_GNU 
        else:
            print("Invlaid filetype")
            return
    else:
        print(f"Invlaid bit lvl {bit}")
        return

    # List of crate current installed
    installed_crates = [x.name for x in Path(LocalCratesIO.CRATES_DIR.value).iterdir() if x.is_dir()
    ]


    if not force_build_all:

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
                # Remove this file from the installed crates list 
                if (x:=info['binary_name']) in installed_crates:
                    installed_crates.remove(x)

    # Any crates that are already built with the same target don't rebuild or analyze

    # Need to get all the analysis for the given optimization and target... 
    # TODO: Assuming all targets are 64bit elf right now 

    crates_with_no_interest = Path(f"~/.crates_io/uninteresting_crates_cache_{target.value}").expanduser()

    boring_crates = []
    # If the file doesn't exist throw in the empty list
    if not crates_with_no_interest.exists():
        crates_with_no_interest.touch()
        with open(crates_with_no_interest, 'w') as f:
            json.dump({'names' : boring_crates},f)

    if not force_build_all:
        # If the file does exist read it, ex
        with open(crates_with_no_interest, 'r') as f:
            boring_crates.extend(json.load(f)['names'])

    for x in boring_crates:
        if x in installed_crates:
            installed_crates.remove(x)


    # Build and analyze each crate
    for crate in alive_it(installed_crates):
        #TODO: the following conditional is here because when building for 
        #       x86_64 linux I know that cargo will work, and I know 
        #       cargo's toolchain version 
        res = 0
        if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
            res = build_analyze_crate(crate, opt, target, filetype,
                            RustcStripFlags.NOSTRIP,
                            use_cargo=True)
        else:
            res = build_analyze_crate(crate, opt, target, filetype,
                            RustcStripFlags.NOSTRIP)
        if res == 99:
            boring_crates.append(crate)
            print(f"Adding crate {crate} to boring crates")
            with open(crates_with_no_interest, 'w') as f:
                json.dump({'names' : boring_crates}, f)


    # Build the crate, add the binary to a list of binaries
    #bins = []
    #crates_with_no_files_of_interest = []
    #for crate in alive_it(installed_crates):

    #    if target == RustcTarget.X86_64_UNKNOWN_LINUX_GNU:
    #        build_crate(crate, opt, target, RustcStripFlags.NOSTRIP,
    #                    use_cargo=True, debug=True)
    #    else:
    #        build_crate(crate, opt, target, RustcStripFlags.NOSTRIP)

    #    # Get files of interest from the crate at the target <target>
    #    files_of_interest = [x for x in get_target_productions(crate, target) if is_executable(x)]

    #    if files_of_interest != []:
    #        bins.append(files_of_interest[0])
    #    else:
    #        print(f"Crate {crate} had no build executable productions")
    #        crates_with_no_files_of_interest.append(crate)
    #    # TODO: in the crates_io cache which cloned pkgs don't build any 
    #    #       files of interest so they are not rebuilt


    #boring_crates = []
    #if crates_with_no_interest.exists():
    #    with open(crates_with_no_interest, 'r') as f:
    #        boring_crates.extend(json.load(f)['names'])
    #if boring_crates != []
    #    with open(crates_with_no_interest, 'w') as f:
    #        json.dump({'names': boring_crates},f)

    #for binary in alive_it(bins):
    #    try:

    #        # TODO: Don't use an analyze function from here, 
    #        #       use a function from ripbin

    #        # Analyze the file
    #        #analyze(binary,
    #        #        'rust',
    #        #        opt.value,
    #        #        str(bit),
    #        #        str(filetype),
    #        #        )

    #        #binary = Path(bin_path).resolve()
    #        if not binary.exists():
    #            print(f"Binary {binary} doesn't exist")
    #            return

    #        # Generate analysis
    #        print("Generating Tensors...")
    #        data = generate_minimal_labeled_features(binary)
    #        print("Tensors generated")


    #        # Create the file info
    #        print("Calculating bin hash...")
    #        binHash = calculate_md5(binary)
    #        print("bin hash calculated...")


    #        # TODO: Anlysis not being saved with target or ELF vs PE?


    #        # Create the file info
    #        info = RustFileBundle(binary.name,
    #                              binHash,
    #                              "",
    #                              filetype,
    #                              opt_lvl,
    #                              binary.name,
    #                              "",
    #                              "")

    #        print("Saving Tensor and binary")
    #        # Save analyiss
    #        save_analysis(binary,
    #                        data,
    #                        AnalysisType.ONEHOT_PLUS_FUNC_LABELS,
    #                        info,
    #                        overwrite_existing=False)
    #        print("Done!")
    #    except Exception:
    #        print(f"Error for file {binary}")
    #        if stop_on_fail:
    #            return
    #        pass


if __name__ == "__main__":
    app()
