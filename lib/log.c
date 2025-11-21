#include "log.h"
#include "sdn_interface.h"

#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>

void sdn_log(uint8_t severity, const char *fmt, ...) {
    const char *prefix;
    switch (severity) {
        case SDN_CRITICAL: prefix = "CRITICAL: "; break;
        case SDN_ERROR:    prefix = "ERROR: ";    break;
        case SDN_WARN:     prefix = "WARN: ";     break;
        case SDN_INFO:     prefix = "INFO: ";     break;
        default:           prefix = "DEBUG: ";  break;
    }

    sdn_timestamp_t ts = GetCurrentTimestampMS();

    va_list args;
    va_start(args, fmt);

    fprintf(stdout, "%" PRIu64 " ", (uint64_t)ts);
    fputs(prefix, stdout);
    vprintf(fmt, args);
    fputc('\n', stdout);

    va_end(args);
}
