nasm -f elf64 minimal_example/ascci_test/ascii_segfault.asm -o bin/ascii_segfault.o
ld bin/ascii_segfault.o -o bin/ascii_segfault
./bin/ascii_segfault
objdump -d bin/ascii_segfault


*[master][~/src/fatal_core_dump]$ echo -ne '[0]' | ndisasm -b64 -
00000000  5B                pop rbx
00000001  30                db 0x30
00000002  5D                pop rbp

{"unit":"celsius","preferred_temperature":22.5,"min_temperature":15.0,"max_temperature":30.0,"auto_adjust":true,"emergency_cooling_threshold":35.0,"heating_mode":"adaptive"}


sudo pwndbg -x minimal_example/min_poc.gdbinit bin/min_poc $(pgrep min_poc)

