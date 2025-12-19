#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool LoadConfigU32(uint32_t *out_value, const char *key);

bool WriteConfigU32(const char *key, uint32_t value);

bool LoadConfigFloat(double *out_value, const char *key);

bool WriteConfigFloat(const char *key, double value);

bool LoadConfigString(const char *out_value, size_t max_size, const char *key);

bool WriteConfigString(const char *key, const char *value);

bool LoadConfigBool(bool *out_value, const char *key);

bool WriteConfigBool(const char *key, bool value);
