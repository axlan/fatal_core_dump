#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

// Your ASCII-only shellcode
unsigned char shellcode[] = {
    0x50,            // push rax
    0x58,            // pop rax
    0x48, 0x21, 0x20 // and [rax+0x20], ah
};

int main()
{
    printf("Shellcode length: %lu bytes\n", sizeof(shellcode));

    // Allocate executable memory
    void *exec_mem = mmap(NULL, sizeof(shellcode),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec_mem == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    // Copy shellcode to executable memory
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    printf("Executing shellcode...\n");

    // Cast to function pointer and execute
    void (*func)() = (void (*)())exec_mem;
    func();

    // This won't be reached if segfault occurs
    printf("Shellcode completed without crashing\n");

    munmap(exec_mem, sizeof(shellcode));
    return 0;
}
