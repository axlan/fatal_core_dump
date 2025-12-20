#! /usr/bin/env bash
set -e

make clean
make

gdb -x scripts/get_mem_locations.gdbinit bin/airlock_ctrl > bin/mem_locations.txt
scripts/generate_shellcode.py
./scripts/bin_to_array.py bin/hack_bad lib/shellcode.h

make
