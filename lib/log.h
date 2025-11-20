#pragma once

#include <stdint.h>

#define SDN_CRITICAL 0
#define SDN_ERROR 1
#define SDN_WARN 2
#define SDN_INFO 3

void sdn_log(uint8_t severity, const char *fmt, ...);
