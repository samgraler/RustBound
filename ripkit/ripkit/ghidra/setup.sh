
# sudo apt install -y openjdk-17-jre
# sudo apt install -y openjdk-17-jdk
# sudo apt install -y wget 
# sudo apt install -y unzip

echo "Done installing deps"

if [ -d "$HOME/ghidra_10.3.3_PUBLIC" ]; then 
    rm -rf ~/ghidra_10.3.3_PUBLIC
fi

if [ -f "$HOME/ghidra_10.3.3_PUBLIC_20230829.zip" ]; then
    rm "$HOME/ghidra_10.3.3_PUBLIC_20230829.zip"
fi

CURRENT_DIR="$PWD"

cd ~ && wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip
cd ~ && unzip ghidra_10.3.3_PUBLIC_20230829.zip

echo "Installed ghidra"


if  [ ! -d "$HOME/ghidra_scripts" ]; then
    mkdir $HOME/ghidra_scripts
fi

if [ ! -f "$HOME/ghidra_10.3.3_PUBLIC_20230829.zip" ]; then
    cp $CURRENT_DIR/List_Function_and_Entry.py $HOME/ghidra_scripts/
fi

