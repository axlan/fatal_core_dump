#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

typedef void (*VoidFunc)(void);

void bar()
{
    printf("bar\n");
}

void foo()
{
    printf("foo\n");
}

int main(int argc, char *argv[])
{
    const size_t BUFFER_SIZE = 64;
    uint32_t *check_ptr = NULL;
    uint8_t *buffer = NULL;
    VoidFunc *cb = NULL;
    uint8_t stack_buffer[BUFFER_SIZE];

    check_ptr = malloc(sizeof(uint32_t));
    *check_ptr = 0xAAAAAAAA;

    buffer = malloc(BUFFER_SIZE);
    memset(buffer, 0xBB, BUFFER_SIZE);

    cb = malloc(sizeof(VoidFunc));
    *cb = foo;

    read(0, buffer, 10240);

    memcpy(stack_buffer, buffer, BUFFER_SIZE);

    (*cb)();

    return 0;
}

// gcc -fcf-protection=none -z execstack -fno-stack-protector -O0 -g -no-pie -o bin/heap_test minimal_example/heap_test.c
// objdump -d bin/heap_test
// 0000000000401136 <foo>:

// pwndbg -x minimal_example/heap_test.gdbinit bin/heap_test

// Looking at malloc of two 32 byte buffers before function pointer
// 03:0018│-018 0x7fffffffecb8 —▸ 0x405300 —▸ 0x40116c (foo) ◂— push rbp
// 04:0020│-010 0x7fffffffecc0 —▸ 0x4052d0 ◂— 0xbbbbbbbbbbbbbbbb
// 05:0028│-008 0x7fffffffecc8 —▸ 0x4052a0 ◂— 0xaaaaaaaaaaaaaaaa
// 0x405300 - 0x4052d0 = 48 (16 bytes extra)
// 0x4052d0 - 0x4052a0 = 48 (16 bytes extra)
// pwndbg> x/4wx (0x4052a0 - 16)
// 0x405290:       0x00000000      0x00000000      0x00000031      0x00000000
// pwndbg> x/4wx (0x4052d0 - 16)
// 0x4052c0:       0x00000000      0x00000000      0x00000031      0x00000000
// pwndbg> x/4wx (0x405300 - 16)
// 0x4052f0:       0x00000000      0x00000000      0x00000021      0x00000000
// The size has an extra 1 for some reason, but appears that the function pointer reserved 32 bytes. Possibly the block size is 16, so it's 16 + 16 for the metadata.

// minimal_example/vuln_test4.py

// env -i setarch $(uname -m) -R /home/jdiamond/src/fatal_core_dump/bin/heap_test < bin/input4
