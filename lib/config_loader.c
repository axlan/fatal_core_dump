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
static uint32_t suit_locker_id = 0xae215e16;
static uint32_t rx_message_buffer_size = 256;
static bool apply_config_change = true;
static bool remote_fault_clear = false;

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
    CL_LOAD_KEY(suit_locker_id);
    CL_LOAD_KEY(rx_message_buffer_size);

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
    CL_WRITE_KEY(suit_locker_id);
    CL_WRITE_KEY(rx_message_buffer_size);

    sdn_log(SDN_ERROR, "Unknown config %s", key);

    return false;
}

bool LoadConfigBool(bool *out_value, const char *key)
{
    if (out_value == NULL || key == NULL)
    {
        return false;
    }

    CL_LOAD_KEY(apply_config_change);
    CL_LOAD_KEY(remote_fault_clear);

    sdn_log(SDN_ERROR, "Unknown config %s", key);

    return false;
}

bool WriteConfigBool(const char *key, bool value)
{
    if (key == NULL)
    {
        return false;
    }

    CL_WRITE_KEY(apply_config_change);
    CL_WRITE_KEY(remote_fault_clear);

    sdn_log(SDN_ERROR, "Unknown config %s", key);

    return false;
}
