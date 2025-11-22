#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>


// gcc -fcf-protection=none -z execstack -fno-stack-protector -O0 -g -no-pie -o bin/demo -Xlinker -Map=bin/demo.map  minimal_example/demo.c
// objdump -d bin/demo > bin/demo.dis

void foo(void) {
    int i=0;
    i++;
    printf("i: %d\n", i);
}



void start() {
  printf("IOLI Crackme Level 0x00\n");
  printf("Password:");

  char buf[64];
  memset(buf, 0, sizeof(buf));
  read(0, buf, 10240);

  if (!strcmp(buf, "250382"))
    printf("Password OK :)\n");
  else
    printf("Invalid Password!\n");
}

int main(int argc, char *argv[])
{
  void *self = dlopen(NULL, RTLD_NOW);
  printf("stack   : %p\n", &argc);
  printf("system(): %p\n", dlsym(self, "system"));
  printf("printf(): %p\n", dlsym(self, "printf"));

  while(true){
    start();
    foo();
  }

  return 0;
}
