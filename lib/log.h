/* Simple logging macros.
 * LOG_ERROR prints always to stderr.
 * LOG_DEBUG prints only when ENABLE_LOG_DEBUG is defined at compile time.
 * Header placed in lib/ so it's available via -Ilib in the Makefile.
 */
#pragma once

#include <stdio.h>

#define LOG_ERROR(fmt, ...) \
    do { fprintf(stderr, (fmt), ##__VA_ARGS__); } while (0)

#if defined(ENABLE_LOG_DEBUG) && ENABLE_LOG_DEBUG
#define LOG_DEBUG(fmt, ...) \
    do { fprintf(stderr, (fmt), ##__VA_ARGS__); } while (0)
#else
#define LOG_DEBUG(fmt, ...) \
    do { (void)0; } while (0)
#endif
