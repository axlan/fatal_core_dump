#include "config_loader.h"
#include "log.h"
#include <string.h>
#include <stdint.h>

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
static uint32_t device_id = 0xae215d67;
static uint32_t inside_door_id = 0xae215e12;
static uint32_t outside_door_id = 0xae215e13;
static uint32_t pressure_ctrl_id = 0xae215e14;
static uint32_t occupancy_sensor_id = 0xae215e15;
static uint32_t message_buffer_size = 1024;

#define CL_LOAD_KEY(target_key)        \
    if (strcmp(key, #target_key) == 0) \
    {                                  \
        *out_value = target_key;       \
        return true;                   \
    }

#define CL_WRITE_KEY(target_key)       \
    if (strcmp(key, #target_key) == 0) \
    {                                  \
        target_key = value;            \
        return true;                   \
    }

bool LoadConfigInt(int *out_value, const char *key)
{
    if (out_value == NULL || key == NULL)
    {
        return false;
    }

    CL_LOAD_KEY(device_id);
    CL_LOAD_KEY(inside_door_id);
    CL_LOAD_KEY(outside_door_id);
    CL_LOAD_KEY(pressure_ctrl_id);
    CL_LOAD_KEY(occupancy_sensor_id);
    CL_LOAD_KEY(message_buffer_size);

    sdn_log(SDN_ERROR, "Unknown config %s", key);

    return false;
}

bool WriteConfigInt(const char *key, int value)
{
    if (key == NULL)
    {
        return false;
    }

    CL_WRITE_KEY(device_id);
    CL_WRITE_KEY(inside_door_id);
    CL_WRITE_KEY(outside_door_id);
    CL_WRITE_KEY(pressure_ctrl_id);
    CL_WRITE_KEY(occupancy_sensor_id);
    CL_WRITE_KEY(message_buffer_size);

    sdn_log(SDN_ERROR, "Unknown config %s", key);

    return false;
}
