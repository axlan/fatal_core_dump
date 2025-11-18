#include <stdio.h>
#include "mylib.h"

int main(int argc, char **argv) {
    const char *name = (argc > 1) ? argv[1] : "world";
    mylib_print(name);
    return 0;
}
