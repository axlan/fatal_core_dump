#pragma once

#include <stdbool.h>
#include <stddef.h>

bool LoadConfigInt(int *out_value, const char *key);

bool WriteConfigInt(const char *key, int value);

bool LoadConfigFloat(double *out_value, const char *key);

bool WriteConfigFloat(const char *key, double value);

bool LoadConfigString(const char *out_value, size_t max_size, const char *key);

bool WriteConfigString(const char *key, const char *value);
