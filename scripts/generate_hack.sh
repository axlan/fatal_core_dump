#! /usr/bin/env bash
set -e

SHELLCODE_FILE="bin/hack_bad"
if [[ "$1" == "--good" ]]; then
    SHELLCODE_FILE="bin/hack_good"
fi

make clean
make

gdb -x scripts/get_mem_locations.gdbinit bin/airlock_ctrl > bin/mem_locations.txt
scripts/generate_shellcode.py
./scripts/bin_to_array.py "$SHELLCODE_FILE" lib/shellcode.h

make
