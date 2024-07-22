from typing_extensions import Annotated
import lief
from typing import List, Any
from alive_progress import alive_bar, alive_it
from pathlib import Path
import multiprocessing
from rich.console import Console
import typer
import math


from ripkit.ripbin import (
    get_functions,
    save_analysis,
    calculate_md5,
    RustFileBundle,
    generate_minimal_labeled_features,
    AnalysisType,
    disasm_at,
    iterable_path_shallow_callback,
)


num_cores = multiprocessing.cpu_count()
CPU_COUNT_75 = math.floor(num_cores * (3 / 4))


console = Console()
app = typer.Typer(pretty_exceptions_show_locals=False)


def profile_worker(dataset_and_sequence: List[Any]) -> List[Any]:
    """
    Worker intened to run in process pool to help profiling
    """

    dataset = dataset_and_sequence[0]
    sequence = dataset_and_sequence[1]

    prog_occurs, non_prog_occurs = byte_search(dataset, sequence, count_only=True)
    return sequence, prog_occurs, non_prog_occurs


@app.command()
def profile_epilogues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int, typer.Argument(help="Number of bytes for the epilogue")],
    logfile: Annotated[Path, typer.Argument(help="File to save to")],
    workers: Annotated[int, typer.Argument(help="Number of workers")] = CPU_COUNT_75,
):
    """
    Profile the dataset for it's epilogues. Get info about epilogue frequencey,
    whether or not the epilogues occur in other places that are not epilogues.
    """

    if logfile.exists():
        print(f"Path {logfile} already exists")
        return

    progs = {}
    files = list(Path(dataset.glob("*")))
    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)
        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase
        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i
            if address in func_start_addrs.keys():

                base_index = i + func_start_addrs[address][1] - length

                epilogue = " ".join(
                    str(hex(x)) for x in text_bytes[base_index : i + length]
                )
                epilogue = epilogue.strip()
                if epilogue in progs.keys():
                    progs[epilogue].append((file, address))
                else:
                    progs[epilogue] = [(file, address)]

    prog_counter = {}
    chunks = []

    for epilogue in progs.keys():
        chunks.append((dataset, epilogue))

    with Pool(processes=workers) as pool:
        results = pool.map(profile_worker, chunks)

    for seq, pro, nonpro in alive_it(results):
        if seq in prog_counter.keys():
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro
        else:
            prog_counter[seq] = [0, 0]
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro

    print(f"Total number of epilogues: {len(progs.keys())}")

    start_counter = SequenceCounter(0, 0, 0, 0, 0, 0)

    # Iterate over each sequence, looking it the number of occurance in epilogue,
    # and non-epilogue
    start_counter.sequences = len(prog_counter.keys())
    for seq, (pro_count, nonpro_count) in prog_counter.items():

        if pro_count == 1:
            start_counter.found_once_in_start += 1

        if nonpro_count == 0:
            start_counter.found_only_in_start += 1
        else:
            start_counter.found_in_nonstart += 1

        start_counter.nonstart_occurances += nonpro_count
        start_counter.start_occurances += pro_count

    print(
        f"Number of epilogues that occur else where: {start_counter.found_in_nonstart}"
    )
    print(
        f"Number of epilogues that didnot occur else where: {start_counter.found_only_in_start}"
    )
    print(f"Number of epilogues that are unique: {start_counter.found_once_in_start}")

    prog_counter["dataset"] = dataset
    prog_counter["seq_len"] = length
    prog_counter["counts"] = asdict(start_counter)

    with open(logfile, "w") as f:
        json.dump(prog_counter, f)
    return


@app.command()
def profile_prologues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int, typer.Argument(help="Number of bytes for the prologue")],
    logfile: Annotated[str, typer.Argument(help="File to save to")],
    workers: Annotated[int, typer.Argument(help="Number of workers")] = CPU_COUNT_75,
):
    """
    Profile the dataset for it's prologues. Get info about prologue frequencey,
    whether or not the prologues occur in other places that are not prologues.
    """

    if logfile.exists():
        print(f"Path {logfile} already exists")
        return

    progs = {}
    files = list(Path(dataset).glob("*"))
    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)
        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase
        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i
            if address in func_start_addrs.keys():

                prologue = " ".join(str(hex(x)) for x in text_bytes[i : i + length])
                prologue = prologue.strip()
                if prologue in progs.keys():
                    progs[prologue].append((file, address))
                else:
                    progs[prologue] = [(file, address)]

    prog_counter = {}
    chunks = []

    for prologue in progs.keys():
        chunks.append((dataset, prologue))

    with Pool(processes=workers) as pool:
        results = pool.map(profile_worker, chunks)

    for seq, pro, nonpro in alive_it(results):
        if seq in prog_counter.keys():
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro
        else:
            prog_counter[seq] = [0, 0]
            prog_counter[seq][0] += pro
            prog_counter[seq][1] += nonpro

    print(f"Total number of prologues: {len(progs.keys())}")

    start_counter = SequenceCounter(0, 0, 0, 0, 0, 0)

    # Iterate over each sequence, looking it the number of occurance in prologue,
    # and non-prologue
    start_counter.sequences = len(prog_counter.keys())
    for seq, (pro_count, nonpro_count) in prog_counter.items():

        if pro_count == 1:
            start_counter.found_once_in_start += 1

        if nonpro_count == 0:
            start_counter.found_only_in_start += 1
        else:
            start_counter.found_in_nonstart += 1

        start_counter.nonstart_occurances += nonpro_count
        start_counter.start_occurances += pro_count

    print(
        f"Number of prologues that occur else where: {start_counter.found_in_nonstart}"
    )
    print(
        f"Number of prologues that didnot occur else where: {start_counter.found_only_in_start}"
    )
    print(f"Number of prologues that are unique: {start_counter.found_once_in_start}")

    prog_counter["dataset"] = dataset
    prog_counter["seq_len"] = length
    prog_counter["counts"] = asdict(start_counter)

    with open(logfile, "w") as f:
        json.dump(prog_counter, f)
    return


@app.command()
def top_epilogues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int, typer.Argument(help="Number of bytes for the prologue")],
    examples: Annotated[int, typer.Argument(help="Num of head and tail prologues")],
):
    """
    Find Common prologues
    """

    if Path(dataset).is_dir():
        files = list(Path(dataset).glob("*"))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return

    prologues = {}

    # Save the adresses where a prologue occurs
    addrs = {}
    file_names = {}

    # Save the disasm
    disams = {}

    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)

        # Add to the prologues dict the prologues

        bin = lief.parse(str(file.resolve()))

        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}
        func_end_addrs = {x.addr + x.size: (x.name, x.size, x.addr) for x in functions}

        # Want to count the number of times a prolog accors and in what file
        # and address it occurs in

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):

            # The end address need to be the last byte
            address = base_address + text_section.virtual_address + i
            # if address in func_start_addrs.keys():
            if address + length in func_end_addrs.keys():
                key = " ".join(str(hex(x)) for x in text_bytes[i : i + length])
                key = key.strip()
                if key in prologues.keys():
                    prologues[key] += 1
                    # addrs[key].append((address,file))
                    addrs[key].append(address)
                    file_names[key].append(
                        (
                            file.name,
                            address,
                            func_end_addrs[address + length][2],
                            address + length,
                        )
                    )
                else:
                    prologues[key] = 1
                    # addrs[key] = [(address,file)]
                    addrs[key] = [(address)]
                    file_names[key] = [
                        (
                            (
                                file.name,
                                address,
                                func_end_addrs[address + length][2],
                                address + length,
                            )
                        )
                    ]

                # BUG: This was not working, I was unable to correctly diasm
                # Want to get the disasmable of a key
                # disams[key] = disasm_at(file, address, length)
                # disams[key] = disasm_with(file, address, length, file_disasm)

    most_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=True)
    )
    print(f"Max occurances: {max(prologues.values())}")

    count = 0
    for key, value in most_common.items():
        print(file_names[key][0][0])
        print(hex(file_names[key][0][1]))
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:0x{hex(file_names[key][0][1])}"
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        # res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        # max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        # for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        # print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        # print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            break

    least_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=False)
    )
    # Least common
    print("Least common prologues...")
    count = 0
    for key, value in least_common.items():
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:{hex(file_names[key][0][1])}, Start at:{hex(file_names[key][0][2])}, End at {hex(file_names[key][0][3])} "
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        # res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        # max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        # for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        # print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        # print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            return
    return


# TODO: Parallelize this. Also get the disasm working
@app.command()
def top_prologues(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    length: Annotated[int, typer.Argument(help="Number of bytes for the prologue")],
    examples: Annotated[int, typer.Argument(help="Num of head and tail prologues")],
):
    """
    Find Common prologues
    """

    if Path(dataset).is_dir():
        files = list(Path(dataset).glob("*"))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return

    prologues = {}

    # Save the adresses where a prologue occurs
    addrs = {}
    file_names = {}

    # Save the disasm
    disams = {}

    for file in alive_it(files):

        # Get the functions
        functions = get_functions(file)

        # Add to the prologues dict the prologues

        bin = lief.parse(str(file.resolve()))

        text_section = bin.get_section(".text")
        text_bytes = text_section.content

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        func_start_addrs = {x.addr: (x.name, x.size) for x in functions}

        # Want to count the number of times a prolog accors and in what file
        # and address it occurs in

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i
            if address in func_start_addrs.keys():
                key = " ".join(str(hex(x)) for x in text_bytes[i : i + length])
                key = key.strip()
                if key in prologues.keys():
                    prologues[key] += 1
                    # addrs[key].append((address,file))
                    addrs[key].append(address)
                    file_names[key].append((file.name, address))
                else:
                    prologues[key] = 1
                    # addrs[key] = [(address,file)]
                    addrs[key] = [(address)]
                    file_names[key] = [(file.name, address)]

                # BUG: This was not working, I was unable to correctly diasm
                # Want to get the disasmable of a key
                # disams[key] = disasm_at(file, address, length)
                # disams[key] = disasm_with(file, address, length, file_disasm)

    most_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=True)
    )
    print(f"Max occurances: {max(prologues.values())}")

    count = 0
    for key, value in most_common.items():
        print(file_names[key][0][0])
        print(hex(file_names[key][0][1]))
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:0x{hex(file_names[key][0][1])}"
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        # res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        # max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        # for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        # print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        # print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            break

    least_common = dict(
        sorted(prologues.items(), key=lambda item: item[1], reverse=False)
    )
    # Least common
    print("Least common prologues...")
    count = 0
    for key, value in least_common.items():
        print(
            f"Count {value} | key: {key} | example at {file_names[key][0][0]}:0x{hex(file_names[key][0][1])}"
        )

        # TODO: The following was to print the assmebly for the prologue
        # to the screen, but... has been difficult, and doesn't make
        # sense for shorter prologues (however in the same breath, shorter
        # prologues don't make much sense unless they make atleast a whole
        # instruction)
        # res =  disasm_bytes(files[0], key.encode())

        ## See the below for how the bytes_string is created, this does that
        ## but finds the longest one so I can format the output string nicely
        # max_len = max(len(' '.join([f'{b:02x}' for b in x.bytes ])) for x in res)

        ## Format each byte in the res nicely
        # for thing in res:
        #    byte_ar = thing.bytes
        #    bytes_string = ' '.join([f'{b:02x}' for b in byte_ar])
        #    print(f"0x{thing.address:x}: {bytes_string:<{max_len}} {thing.mnemonic} {thing.op_str}")

        # print(f"Disass:\n{[str(disasm_bytes(files[0], key.encode())}")
        # Turn the key into the disasm

        # print(f"Disam: {disams[key]}")
        count += 1
        if count > examples:
            print(f"Total unique funcs {len(prologues.values())}")
            print(f"Total functions {sum(prologues.values())}")
            return
    return


def byte_search(dataset, input_seq, count_only=False):
    """
    Search the dataset for the byte sting.
    """

    if Path(dataset).is_dir():
        # Get the files
        files = list(Path(dataset).glob("*"))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return [], []

    # Save the occruacnes here
    prologue_occurances = []
    non_pro_occurances = []

    length = len(input_seq.split(" "))

    prog_occurs = 1
    non_prog_occurs = 0

    # for file in alive_it(files):
    for file in files:
        # get the start addrs
        func_start_addrs = {x.addr: (x.name, x.size) for x in get_functions(file)}

        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i

            if i + length > len(text_bytes) + 1:
                break

            sub_seq = " ".join(str(hex(x)) for x in text_bytes[i : i + length])

            if sub_seq == input_seq:
                if address in func_start_addrs.keys():
                    if count_only:
                        prog_occurs += 1
                    else:
                        prologue_occurances.append((address, file))
                else:
                    if count_only:
                        non_prog_occurs += 1
                    else:
                        non_pro_occurances.append((address, file))
    if count_only:
        return prog_occurs, non_prog_occurs
    else:
        return prologue_occurances, non_pro_occurances


@app.command()
def search_for_bytes(
    dataset: Annotated[str, typer.Argument(help="The dataset")],
    input_seq: Annotated[
        str, typer.Argument(help="Bytes in format: 0x<byte1> 0x<byte2> ")
    ],
    save_to_files: Annotated[bool, typer.Option()] = False,
):
    """
    Search the dataset for the byte sting.
    """

    if Path(dataset).is_dir():
        # Get the files
        files = list(Path(dataset).glob("*"))
    elif Path(dataset).is_file():
        files = [Path(dataset)]
    else:
        return

    # Save the occruacnes here
    prologue_occurances = []
    non_pro_occurances = []

    length = len(input_seq.split(" "))

    for file in alive_it(files):

        # get the start addrs
        func_start_addrs = {x.addr: (x.name, x.size) for x in get_functions(file)}

        bin = lief.parse(str(file.resolve()))
        text_section = bin.get_section(".text")

        # Get the bytes in the .text section
        text_bytes = text_section.content

        # Get the base address of the loaded binary
        base_address = bin.imagebase

        # This enumerate the .text byte and sees which ones are functions
        for i, _ in enumerate(text_bytes):
            address = base_address + text_section.virtual_address + i

            if i + length > len(text_bytes) + 1:
                break

            sub_seq = " ".join(str(hex(x)) for x in text_bytes[i : i + length])

            if sub_seq == input_seq:
                if address in func_start_addrs.keys():
                    prologue_occurances.append((address, file))
                else:
                    non_pro_occurances.append((address, file))

    # print("Done searching")

    # with open("NON_PRO_OCCURNACE", 'w') as f:
    #    for (addr, file) in non_pro_occurances:
    #        f.write(f"{file} ||||| {hex(addr)}\n")

    print(f"Total {len(prologue_occurances) + len(non_pro_occurances)}")
    if len(prologue_occurances) > 0:
        print(
            f"Prologue {len(prologue_occurances)} | First occurance {hex(prologue_occurances[0][0])} file: {prologue_occurances[0][1]}"
        )
    if len(non_pro_occurances) > 0:
        print(
            f"NonPrologue {len(non_pro_occurances)} | First occurance {hex(non_pro_occurances[0][0])}  file: {non_pro_occurances[0][1]}"
        )

    if save_to_files:
        with open("_PROLOGUES", "w") as f:
            for addr, file in prologue_occurances:
                f.write(f"{file}, {hex(addr)}\n")

        with open("NON_PROLOGUES", "w") as f:
            for addr, file in non_pro_occurances:
                f.write(f"{file}, {hex(addr)}\n")
    return


@app.command()
def get_function_list(
    binary: Annotated[str, typer.Argument(help="Binary File")],
):
    """
    Get list of functions
    """

    bin = Path(binary)

    # Get the functions
    functions = get_functions(bin)

    for i, func in enumerate(functions):
        print(f"{i}: {func.name} : {func.addr}")
    return


@app.command()
def get_function(
    binary: Annotated[str, typer.Argument(help="Binary File")],
    name_like: Annotated[str, typer.Option(help="Substring of function name")] = "",
    name_exact: Annotated[str, typer.Option(help="The exact function name")] = "",
):
    """
    Get information on the given function in the binary
    """

    exact = False
    like = False
    if name_like == "" and name_exact == "":
        print("Need a function name")
        return
    elif name_like != "":
        name = name_like
        like = True
    else:
        name = name_exact
        exact = True

    bin = Path(binary)

    # Get the functions
    functions = get_functions(bin)

    # Add to the prologues dict the prologues
    bin = lief.parse(str(bin.resolve()))

    text_section = bin.get_section(".text")
    text_bytes = text_section.content

    # Get the bytes in the .text section
    text_bytes = text_section.content

    # Get the base address of the loaded binary
    base_address = bin.imagebase

    func_info = ()
    for func in functions:
        if func.name == name and exact:
            func_info = (func.addr, func.name, func.size)
        elif name in func.name and like:
            func_info = (func.addr, func.name, func.size)

    if func_info == ():
        print(f"Function {name} not found in {binary}")
        return

    print("Lief info:")
    print(f"Raw address: {func_info[0]}")
    print(f"Length: {func_info[2]}")

    # Need to apply the offset to get the correct addr:
    # correct addr = cur_byte_index + base_image_addr + text_sec_addr
    offset = base_address + text_section.virtual_address
    blist = text_bytes[func_info[0] - offset : func_info[0] - offset + func_info[2]]

    hex_repr = " ".join(str(hex(x)) for x in blist)
    print(f"HEX REPR:\n {hex_repr}")
    return

@app.command()
def get_function_counts(
    dataset: Annotated[Path, typer.Argument(help="The dataset")],
    ):
    """
    Count functions per binary in the dataset
    Pass just a single optimization level for now 
    """

    #TODO: Function to iterate all opt levels and compare... this is more 
    # manaul rn 

    func_counts = {}

    for bin in alive_it(list(dataset.glob('*'))):
        funcs = len(get_functions(bin))

        if funcs not in func_counts.keys():
            func_counts[funcs] = []
        func_counts[funcs].append(bin.resolve())

    single_occurance = 0
    for k, _ in func_counts.items():
        print(f"{len(func_counts[k])} files had {k} functions")
        if len(func_counts[k]) == 1:
            single_occurance+=1

    print(f"Had {single_occurance} unique function counts")

    return


if __name__ == "__main__":
    app()
