# Welcome to the core of ripbin 


# Here is an example of functions usage:
```python
path = Path("~/.ripbin_db/c_files").expanduser().resolve()
analyzed_files = list(path.expanduser().resolve().rglob('*'))
analyzed_files = [x for x in analyzed_files if ".npz" not in x.name
                    and x.is_file()]

# Now I have all the binary files for c 
# I need to get the file type, the opt_lvl, and the compiler
for file in alive_it(analyzed_files):
    compiler = file.name.split('_')[0]
    compiler = get_enum_field(Compiler, compiler)
    if compiler is None:
        raise Exception("No compiler for file {}".format(file))
    if 'O0' in file.name:
        opt_level = Coptimization.O0
    elif 'O1' in file.name:
        opt_level = Coptimization.O1
    elif 'O2' in file.name:
        opt_level = Coptimization.O2
    elif 'O3' in file.name:
        opt_level = Coptimization.O3
    else:
        raise Exception("No opt {}".format(file))

    prog_lang = ProgLang.C

    filetype_str = file.parent.parent.name
    file_type = get_enum_field(FileType, filetype_str)
    if file_type is None:
        raise Exception("No file type for file {}".format(file))

    #db_save_analysis(file,gen, prog_lang, compiler, file_type, opt_lvl, False)
    print("Analyzing and saving {} in new db".format(file.resolve()))

    analysis_type = AnalysisType.DEC_REPR_BYTE_PLUS_FUNC_LABELS

    data_gen = generate_minimal_labeled_features(file,
                                                use_one_hot=False)

    save_and_register_analysis(file,
                               data_gen,
                               analysis_type,
                               prog_lang,
                               compiler,
                               file_type,
                               opt_level)

    analysis_type = AnalysisType.ONEHOT_PLUS_FUNC_LABELS
    data_gen = generate_minimal_labeled_features(file,
                                                use_one_hot=True)

    save_and_register_analysis(file,
                               data_gen,
                               analysis_type,
                               prog_lang,
                               compiler,
                               file_type,
                               opt_level)
```
This was used to convert old analyzed files to new ones
