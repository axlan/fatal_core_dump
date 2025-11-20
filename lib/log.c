#include "log.h"

#include <stdio.h>
#include <stdarg.h>

void sdn_log(uint8_t severity, const char *fmt, ...) {
    (void)severity;
    va_list args;
    va_start(args, fmt);

    // Forward the variable arguments to vprintf
    vprintf(fmt, args);
    puts("\n");

    va_end(args);
}
