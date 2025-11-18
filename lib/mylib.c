#include <stdio.h>
#include "mylib.h"

void mylib_print(const char *name) {
    if (!name) name = "world";
    printf("Hello, %s!\n", name);
}
