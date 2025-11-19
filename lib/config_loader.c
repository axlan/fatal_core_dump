#include "config_loader.h"
#include <string.h>
#include <stdint.h>

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
static const uint16_t DUMMY_DEVICE_ID = 0x1a35;
bool LoadConfigInt(int *out_value, const char *key) {
    if (out_value == NULL || key == NULL) {
        return false;
    }

    // For demonstration, we just set a dummy value based on the key.
    if (strcmp(key, "device_id") == 0) {
        *out_value = DUMMY_DEVICE_ID;
        return true;
    }

    return false;
}
