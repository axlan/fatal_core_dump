<https://ephemeral.cx/2013/12/writing-a-self-mutating-x86_64-c-program/>
<https://stackoverflow.com/questions/56905811/what-does-the-endbr64-instruction-actually-do> (avoided with -fcf-protection=none)

```sh
gcc -fcf-protection=none -o bin/mutate minimal_example/mutate.c
objdump -d bin/mutate > bin/mutate.dis
gcc -fcf-protection=none -o bin/mutate minimal_example/mutate.c && bin/mutate
```

Disable address randomization (ASLR):
`setarch $(uname -m) -R bin/mutate`


<https://tc.gts3.org/cs6265/tut/tut06-01-rop.html>
<https://github.com/Gallopsled/pwntools-tutorial#readme>

gcc -fcf-protection=none -z execstack -fno-stack-protector -O0 -g -o bin/vuln minimal_example/vuln.c

`echo -n "250382" | ./bin/vuln`

<https://tc.gts3.org/cs6265/tut/tut02-warmup2.html>

```sh
echo AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ | ./bin/vuln
```


```sh
pwndbg bin/vuln
set exec-wrapper env -i
break vuln.c:13
r < bin/input
n
```

```
──────────[ STACK ]────────────────────
00:0000│ rax rdi rsp 0x7fffffffddc0 ◂— 0
... ↓                3 skipped
04:0020│ rbp         0x7fffffffdde0 —▸ 0x7fffffffde10 ◂— 1
05:0028│+008         0x7fffffffdde8 —▸ 0x5555555552ce (main+161) ◂— mov eax, 0
06:0030│+010         0x7fffffffddf0 —▸ 0x7fffffffdf28 —▸ 0x7fffffffe238 ◂— '/home/jdiamond/src/fatal_core_dump/bin/vuln'
07:0038│+018         0x7fffffffddf8 ◂— 0x100000064 /* 'd' */

to

──────────[ STACK ]────────────────────
00:0000│ rsi rsp 0x7fffffffddc0 ◂— 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ\nRUUUU'
01:0008│-018     0x7fffffffddc8 ◂— 'CCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJ\nRUUUU'
02:0010│-010     0x7fffffffddd0 ◂— 'EEEEFFFFGGGGHHHHIIIIJJJJ\nRUUUU'
03:0018│-008     0x7fffffffddd8 ◂— 'GGGGHHHHIIIIJJJJ\nRUUUU'
04:0020│ rbp     0x7fffffffdde0 ◂— 'IIIIJJJJ\nRUUUU'
05:0028│+008     0x7fffffffdde8 —▸ 0x55555555520a (start+113) ◂— lea rax, [rip + 0xe1c]
06:0030│+010     0x7fffffffddf0 —▸ 0x7fffffffdf28 —▸ 0x7fffffffe238 ◂— '/home/jdiamond/src/fatal_core_dump/bin/vuln'
07:0038│+018     0x7fffffffddf8 ◂— 0x100000064 /* 'd' */
```

See minimal_example/vuln_test1.py

```
0000000000001199 <start>:
    1199:	55                   	push   %rbp
    119a:	48 89 e5             	mov    %rsp,%rbp
    119d:	48 83 ec 20          	sub    $0x20,%rsp
``

```
*[master][~/src/fatal_core_dump]$ setarch $(uname -m) -R ./bin/vuln < bin/input
stack   : 0x7fffffffdfdc
system(): 0x7ffff7c50d70
printf(): 0x7ffff7c606f0
IOLI Crackme Level 0x00
Password:Invalid Password!
Password OK :)
```


`env -i setarch $(uname -m) -R /home/jdiamond/src/fatal_core_dump/bin/vuln < bin/input2`

```sh
pwndbg bin/vuln
set exec-wrapper env -i
break vuln.c:13
r < bin/input2
n
```

`pwndbg bin/vuln -p 1751199`


`gcc -fcf-protection=none -z execstack -fno-stack-protector -O0 -g -no-pie -o bin/demo minimal_example/demo.c`

```sh
pwndbg bin/demo
set exec-wrapper env -i
set context-stack-lines 32
break demo.c:27
break foo
r < bin/input3
x/19bx 0x401196
c
n
n
n
n
```

`env -i setarch $(uname -m) -R /home/jdiamond/src/fatal_core_dump/bin/demo < bin/input3`
