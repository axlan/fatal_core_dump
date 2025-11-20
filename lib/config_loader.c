#include "config_loader.h"
#include <string.h>
#include <stdint.h>

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
static const uint32_t DUMMY_DEVICE_ID = 0xae215d67;
static const uint32_t SDN_DEVICE_ID_DOOR_INNER = 0xae215e12;
static const uint32_t SDN_DEVICE_ID_DOOR_OUTER = 0xae215e13;
static const uint32_t SDN_DEVICE_ID_PRESSURE_CTRL = 0xae215e14;
static const uint32_t MESSAGE_BUFFER_SIZE = 1024;
bool LoadConfigInt(int *out_value, const char *key)
{
    if (out_value == NULL || key == NULL)
    {
        return false;
    }

    // For demonstration, we just set a dummy value based on the key.
    if (strcmp(key, "device_id") == 0)
    {
        *out_value = DUMMY_DEVICE_ID;
        return true;
    }

    // For demonstration, we just set a dummy value based on the key.
    if (strcmp(key, "inside_door_id") == 0)
    {
        *out_value = SDN_DEVICE_ID_DOOR_INNER;
        return true;
    }

    // For demonstration, we just set a dummy value based on the key.
    if (strcmp(key, "outside_door_id") == 0)
    {
        *out_value = SDN_DEVICE_ID_DOOR_OUTER;
        return true;
    }

    // For demonstration, we just set a dummy value based on the key.
    if (strcmp(key, "message_buffer_size") == 0)
    {
        *out_value = MESSAGE_BUFFER_SIZE;
        return true;
    }

    return false;
}
