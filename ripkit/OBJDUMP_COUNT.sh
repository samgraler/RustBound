objdump -d -j .text your_binary_file | grep -cE '^[[:xdigit:]]+ <[^>]+>:'
