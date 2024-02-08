
from pathlib import Path

def comp_opt(train_dir, other_dir: Path):
    '''
    '''
    train_dir_names = [x.name for x in train_dir.glob('*')]
    other_dir_names = [x.name for x in other_dir.glob('*')]


    found_match = False
    for train_name in train_dir_names:
        for other_name in other_dir_names:
            if train_name == other_name:
                found_match = True

    if not found_match:
        print(f"Good! {train_dir.name} : {other_dir.parent}/{other_dir.name}")
    return 


if __name__ == "__main__":

    test_base = Path("exported_datasets")
    large_test_base =  test_base / "200_file_subset"
    small_test_base =  test_base / "20_file_subset"

    train_base = Path("training_datasets")

    test0= large_test_base / "0_xda_tested"
    test1= large_test_base / "1_xda_tested"
    test2= large_test_base / "2_xda_tested"
    test3= large_test_base / "3_xda_tested"
    testz= large_test_base / "z_xda_tested"
    tests = [test0, test1, test2, test3, testz]

    pre0 = train_base / Path("O0") / Path("dataset_pretrain")
    pre1 = train_base / Path("O1") / Path("dataset_pretrain")
    pre2 = train_base / Path("O2") / Path("dataset_pretrain")
    pre3 = train_base / Path("O3") / Path("dataset_pretrain")
    prez = train_base / Path("Oz") / Path("dataset_pretrain")
    pres = [pre0, pre1, pre2, pre3, prez]

    fin0 = train_base / Path("O0") / Path("dataset_finetune")
    fin1 = train_base / Path("O1") / Path("dataset_finetune")
    fin2 = train_base / Path("O2") / Path("dataset_finetune")
    fin3 = train_base / Path("O3") / Path("dataset_finetune")
    finz = train_base / Path("Oz") / Path("dataset_finetune")
    fins = [fin0, fin1, fin2, fin3, finz]


    for test, pre in zip(tests,pres):
        comp_opt(test,pre)

    for test, fin in zip(tests,fins):
        comp_opt(test,fin)






