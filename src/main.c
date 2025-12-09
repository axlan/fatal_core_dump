#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "config_loader.h"
#include "log.h"
#include "sdn_interface.h"

/////////////// Macros ///////////////////
#ifndef APP_DEBUG_BUILD
    #define APP_DEBUG_BUILD 0
#endif


/////////////// Constants ////////////////

static const float PRESSURE_ERROR_TOLERANCE = 0.1;
static const unsigned DEVICE_WATCHDOG_TIMEOUT_MS = 100;
static const unsigned SLEEP_PERIOD_MS = 1;

static const unsigned PRESSURE_CHANGE_TIMEOUT_MS = 5000;

static const uint32_t FAULT_DOOR_BIT = 1 << 0;
static const uint32_t FAULT_DEBUGGER = 1 << 1;
static const uint32_t FAULT_PRESSURE = 1 << 2;

static const uint32_t INNER_DOOR_IDX = 0;
static const uint32_t OUTER_DOOR_IDX = 1;

static const uint32_t INNER_DOOR_STATION_SIDE_IDX = 0;
static const uint32_t INNER_DOOR_AIRLOCK_SIDE_IDX = 1;
static const uint32_t OUTER_DOOR_EXTERIOR_SIDE_IDX = 0;
static const uint32_t OUTER_DOOR_AIRLOCK_SIDE_IDX = 1;

static const uint8_t INNER_PRESSURE_ZONE = 0;
static const uint8_t OUTER_PRESSURE_ZONE = 1;

static const char *DOOR_NAMES[2] = {"station", "exterior"};

///////////// Definitions /////////////////////

typedef struct DoorStatus DoorStatus;
struct DoorStatus
{
    SDNHeartBeatMessage heartbeat;
    SDNPressureMessage pressure[2];
};

typedef enum AirlockState AirlockState;
enum AirlockState
{
    AIRLOCK_CLOSED_PRESSURIZED,
    AIRLOCK_CLOSED_DEPRESSURIZED,
    AIRLOCK_INTERIOR_OPEN,
    AIRLOCK_EXTERIOR_OPEN,
    AIRLOCK_PRESSURIZING,
    AIRLOCK_DEPRESSURIZING,
};

typedef struct AirlockConfig AirlockConfig;
struct AirlockConfig
{
    uint32_t device_id;
    uint32_t inside_door_id;
    uint32_t outside_door_id;
    uint32_t pressure_ctrl_id;
    uint32_t occupancy_sensor_id;
    uint32_t message_buffer_size;
};

////////////////////// Implementation ///////////////////////

static bool ControlDoor(uint32_t device_id, uint32_t door_device_id, bool is_open)
{
    SDNSetOpenMessage door_cmd = {
        .msg_header = {
            .device_id = device_id,
            .msg_length = sizeof(SDNSetOpenMessage),
            .msg_type = SDN_MSG_TYPE_SET_OPEN,
            .timestamp = GetCurrentTimestampMS()},
        .open = (is_open) ? 1 : 0};
    return ExecuteCmd(&door_cmd.msg_header, door_device_id);
}

static bool ControlPressure(uint32_t device_id, uint32_t pressure_device_id, bool use_internal_pressure, sdn_timestamp_t *pressure_change_time)
{
    assert(pressure_change_time != NULL);
    *pressure_change_time = GetCurrentTimestampMS();
    SDNSetPressureZoneMessage pressure_cmd = {
        .msg_header = {
            .device_id = device_id,
            .msg_length = sizeof(SDNSetPressureZoneMessage),
            .msg_type = SDN_MSG_TYPE_SET_PRESSURE_ZONE,
            .timestamp = *pressure_change_time},
        .zone_id = (use_internal_pressure) ? INNER_PRESSURE_ZONE : OUTER_PRESSURE_ZONE};
    return ExecuteCmd(&pressure_cmd.msg_header, pressure_device_id);
}

bool InitializeSDN(uint32_t device_id, uint32_t inside_door_id, uint32_t outside_door_id)
{
    if (!RegisterDevice(device_id, SDN_DEVICE_TYPE_AIRLOCK_CTRL))
    {
        return false;
    }
    if (!SubscribeToMessage(inside_door_id, SDN_MSG_TYPE_HEARTBEAT))
    {
        return false;
    }
    if (!SubscribeToMessage(inside_door_id, SDN_MSG_TYPE_SENSOR_PRESSURE))
    {
        return false;
    }
    if (!SubscribeToMessage(outside_door_id, SDN_MSG_TYPE_HEARTBEAT))
    {
        return false;
    }
    if (!SubscribeToMessage(outside_door_id, SDN_MSG_TYPE_SENSOR_PRESSURE))
    {
        return false;
    }
    return true;
}

static bool LoadConfig(AirlockConfig *config)
{
    int tmp = 0;

    if (!LoadConfigInt(&tmp, "device_id"))
    {
        return false;
    }
    config->device_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "inside_door_id"))
    {
        return false;
    }
    config->inside_door_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "outside_door_id"))
    {
        return false;
    }
    config->outside_door_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "pressure_ctrl_id"))
    {
        return false;
    }
    config->pressure_ctrl_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "occupancy_sensor_id"))
    {
        return false;
    }
    config->occupancy_sensor_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "message_buffer_size"))
    {
        return false;
    }
    config->message_buffer_size = (uint32_t)tmp;

    return true;
}

int main()
{
    AirlockConfig config = {0};
    void *message_buffer = NULL;
    uint32_t fault_bits = 0;

    if (!LoadConfig(&config))
    {
        return 1;
    }

    DoorStatus door_status[2];
    memset(door_status, 0, sizeof(door_status));

    sdn_timestamp_t start_time = GetCurrentTimestampMS();
    for (int i = 0; i < 2; i++) {
        door_status[i].heartbeat.msg_header.timestamp = start_time;
        door_status[i].pressure[0].msg_header.timestamp = start_time;
        door_status[i].pressure[1].msg_header.timestamp = start_time;
    }

    sdn_timestamp_t pressure_change_time = 0;
    AirlockState airlock_state = AIRLOCK_PRESSURIZING;
    sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_PRESSURIZING");

    float *station_pressure = &door_status[INNER_DOOR_IDX].pressure[INNER_DOOR_STATION_SIDE_IDX].pressure_pa;
    *station_pressure = NAN;

    float *exterior_pressure = &door_status[OUTER_DOOR_IDX].pressure[OUTER_DOOR_EXTERIOR_SIDE_IDX].pressure_pa;
    *exterior_pressure = NAN;

    float *airlock_pressures[2] = {&door_status[INNER_DOOR_IDX].pressure[INNER_DOOR_AIRLOCK_SIDE_IDX].pressure_pa, &door_status[OUTER_DOOR_IDX].pressure[OUTER_DOOR_AIRLOCK_SIDE_IDX].pressure_pa};
    *airlock_pressures[0] = NAN;
    *airlock_pressures[1] = NAN;

    if (!InitializeSDN(config.device_id, config.inside_door_id, config.outside_door_id))
    {
        return 2;
    }

    message_buffer = malloc(config.message_buffer_size);
    if (message_buffer == NULL)
    {
        return 3;
    }

    if (!ControlDoor(config.device_id, config.outside_door_id, false) || !ControlDoor(config.device_id, config.inside_door_id, false))
    {
        return 4;
    }

    if (!ControlPressure(config.device_id, config.pressure_ctrl_id, true, &pressure_change_time))
    {
        return 4;
    }

    while (true)
    {
        while (true)
        {
            int ret = ReadNextMessage(message_buffer, config.message_buffer_size);
            if (ret < 0)
            {
                return 5;
            }

            if (ret <= 0)
            {
                break;
            }

            SDNMsgHeader *msg_header = (SDNMsgHeader *)message_buffer;
            switch (msg_header->msg_type)
            {
            case SDN_MSG_TYPE_HEARTBEAT:
            {
                if ((size_t)ret >= sizeof(SDNHeartBeatMessage))
                {
                    SDNHeartBeatMessage *hb = (SDNHeartBeatMessage *)message_buffer;
                    uint32_t src_id = msg_header->device_id;
                    int idx = -1;
                    if (src_id == config.inside_door_id)
                        idx = INNER_DOOR_IDX;
                    else if (src_id == config.outside_door_id)
                        idx = OUTER_DOOR_IDX;
                    if (idx >= 0)
                    {
                        door_status[idx].heartbeat = *hb;
                    }
                }
                else
                {
                    sdn_log(SDN_WARN, "Received HEARTBEAT message with invalid length %d", ret);
                }
            }
            break;

            case SDN_MSG_TYPE_SENSOR_PRESSURE:
            {
                if ((size_t)ret >= sizeof(SDNPressureMessage))
                {
                    SDNPressureMessage *pm = (SDNPressureMessage *)message_buffer;
                    uint32_t src_id = msg_header->device_id;
                    int idx = -1;
                    if (src_id == config.inside_door_id)
                        idx = INNER_DOOR_IDX;
                    else if (src_id == config.outside_door_id)
                        idx = OUTER_DOOR_IDX;
                    if (idx >= 0)
                    {
                        int side_idx = -1;
                        if (pm->measurement_id == SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1)
                            side_idx = 0;
                        else if (pm->measurement_id == SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2)
                            side_idx = 1;
                        if (side_idx >= 0)
                        {
                            door_status[idx].pressure[side_idx] = *pm;
                        }
                    }
                }
                else
                {
                    sdn_log(SDN_WARN, "Received SENSOR_PRESSURE message with invalid length %d", ret);
                }
            }
            break;

            case SDN_MSG_TYPE_SET_AIRLOCK_OPEN:
            {
                if (fault_bits != 0){
                    sdn_log(SDN_WARN, "Door commands ignored while fault active.");
                }
                else if ((size_t)ret >= sizeof(SDNSetAirlockOpenMessage))
                {
                    SDNSetAirlockOpenMessage *cf = (SDNSetAirlockOpenMessage *)message_buffer;
                    SDNAirlockOpen airlock_req = cf->open;
                    if (airlock_req == SDN_AIRLOCK_CLOSED)
                    {
                        if (!ControlDoor(config.device_id, config.outside_door_id, false) || !ControlDoor(config.device_id, config.inside_door_id, false))
                        {
                            return 4;
                        }

                        if (airlock_state == AIRLOCK_INTERIOR_OPEN)
                        {
                            airlock_state = AIRLOCK_CLOSED_PRESSURIZED;
                            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_PRESSURIZED");
                        }
                        else if (airlock_state == AIRLOCK_EXTERIOR_OPEN)
                        {
                            airlock_state = AIRLOCK_CLOSED_DEPRESSURIZED;
                            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_DEPRESSURIZED");
                        }
                    }
                    else if (airlock_req == SDN_AIRLOCK_INTERIOR_OPEN)
                    {
                        switch (airlock_state)
                        {
                        case AIRLOCK_INTERIOR_OPEN:
                            // already open, nothing to do
                            break;
                        case AIRLOCK_CLOSED_PRESSURIZED:
                            // safe to open interior door
                            if (!ControlDoor(config.device_id, config.inside_door_id, true))
                            {
                                return 4;
                            }
                            airlock_state = AIRLOCK_INTERIOR_OPEN;
                            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_INTERIOR_OPEN");
                            break;
                        case AIRLOCK_EXTERIOR_OPEN:
                        case AIRLOCK_CLOSED_DEPRESSURIZED:
                        case AIRLOCK_DEPRESSURIZING:
                            // close exterior first (if needed), then pressurize
                            if (!ControlDoor(config.device_id, config.outside_door_id, false))
                            {
                                return 4;
                            }
                            if (!ControlPressure(config.device_id, config.pressure_ctrl_id, true, &pressure_change_time))
                            {
                                return 4;
                            }
                            airlock_state = AIRLOCK_PRESSURIZING;
                            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_PRESSURIZING");
                            break;
                        case AIRLOCK_PRESSURIZING:
                            // already working towards pressurization
                            break;
                        }
                    }
                    else if (airlock_req == SDN_AIRLOCK_EXTERIOR_OPEN)
                    {
                        // NOTE: Pointers to original request message are invalid now since buffer has been reused.
                        int occupancy_resp = GetResponse(message_buffer, config.message_buffer_size, config.occupancy_sensor_id, SDN_MSG_TYPE_SENSOR_OCCUPANCY);
                        if (occupancy_resp < (int)sizeof(SDNOccupancyMessage))
                        {
                            return 5;
                        }

                        const SDNOccupancyInfo *occupants = ((SDNOccupancyMessage *)message_buffer)->occupants;
                        size_t num_occupants = (occupancy_resp - sizeof(SDNOccupancyMessage)) / sizeof(SDNOccupancyInfo);
                        bool safe_to_open = true;
                        for (unsigned i = 0; i < num_occupants; i++)
                        {
                            if (occupants[i].suit_status != SDN_SUIT_STATUS_SEALED)
                            {
                                safe_to_open = false;
                                break;
                            }
                        }

                        if (safe_to_open)
                        {
                            switch (airlock_state)
                            {
                            case AIRLOCK_EXTERIOR_OPEN:
                                // already open, nothing to do
                                break;
                            case AIRLOCK_CLOSED_DEPRESSURIZED:
                                // safe to open exterior door
                                if (!ControlDoor(config.device_id, config.outside_door_id, true))
                                {
                                    return 4;
                                }
                                airlock_state = AIRLOCK_EXTERIOR_OPEN;
                                sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_EXTERIOR_OPEN");
                                break;
                            case AIRLOCK_INTERIOR_OPEN:
                            case AIRLOCK_CLOSED_PRESSURIZED:
                            case AIRLOCK_PRESSURIZING:
                                // close interior first (if needed), then depressurize
                                if (!ControlDoor(config.device_id, config.inside_door_id, false))
                                {
                                    return 4;
                                }
                                if (!ControlPressure(config.device_id, config.pressure_ctrl_id, false, &pressure_change_time))
                                {
                                    return 4;
                                }
                                airlock_state = AIRLOCK_DEPRESSURIZING;
                                sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_DEPRESSURIZING");
                                break;
                            case AIRLOCK_DEPRESSURIZING:
                                // already working towards depressurization
                                break;
                            default:
                                break;
                            }
                        }
                        else
                        {
                            sdn_log(SDN_WARN, "Received SDN_AIRLOCK_EXTERIOR_OPEN message with unsealed occupants");
                        }
                    }
                }
                else
                {
                    sdn_log(SDN_WARN, "Received SET_AIRLOCK_OPEN message with invalid length %d", ret);
                }
            }
            break;

            case SDN_MSG_TYPE_CLEAR_FAULTS:
            {
                if ((size_t)ret >= sizeof(SDNClearFaultsMessage))
                {
                    SDNClearFaultsMessage *cf = (SDNClearFaultsMessage *)message_buffer;
                    fault_bits &= ~cf->fault_mask;
                }
                else
                {
                    sdn_log(SDN_WARN, "Received CLEAR_FAULTS message with invalid length %d", ret);
                }
            }
            break;

#if APP_DEBUG_BUILD
            case SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT:
            {
                SDNDebugWriteConfigInt *cf = (SDNDebugWriteConfigInt *)message_buffer;
                cf->key[sizeof(cf->key) - 1] = 0;
                fault_bits &= FAULT_DEBUGGER;
                if (WriteConfigInt(cf->key, cf->value)) {
                    if (!LoadConfig(&config)) {
                        return 1;
                    }
                }
            }
            break;
#endif

            default:
                break;
            }
        }

        sdn_timestamp_t now = GetCurrentTimestampMS();

        /* Watchdog: check for missed messages from doors and set fault bit */
        if (!(fault_bits & FAULT_DOOR_BIT))
        {
            sdn_timestamp_t now = GetCurrentTimestampMS();
            uint32_t door_fault = 0;
            for (int i = 0; i < 2; ++i)
            {
                if (now - door_status[i].heartbeat.msg_header.timestamp > DEVICE_WATCHDOG_TIMEOUT_MS)
                {
                    door_fault = FAULT_DOOR_BIT;
                    sdn_log(SDN_CRITICAL, "%s door heartbeat timeout", DOOR_NAMES[i]);
                }
                for (int j = 0; j < 2; ++j)
                {
                    if (now - door_status[i].pressure[j].msg_header.timestamp > DEVICE_WATCHDOG_TIMEOUT_MS)
                    {
                        door_fault = FAULT_DOOR_BIT;
                        sdn_log(SDN_CRITICAL, "%s door pressure timeout", DOOR_NAMES[i]);
                    }
                }
            }
            fault_bits |= door_fault;
        }

        if (!(fault_bits & FAULT_DOOR_BIT) && !(fault_bits & FAULT_PRESSURE))
        {
            bool pressure_initialized = !isnan(*station_pressure) && !isnan(*exterior_pressure) && !isnan(*airlock_pressures[0]) && !isnan(*airlock_pressures[1]);
            if (pressure_initialized)
            {
                float sp = *station_pressure;
                float ep = *exterior_pressure;
                float ap0 = *airlock_pressures[0];
                float ap1 = *airlock_pressures[1];

                bool pressure_fault = false;

                switch (airlock_state)
                {
                case AIRLOCK_CLOSED_PRESSURIZED:
                    if (fabsf(ap0 - sp) > PRESSURE_ERROR_TOLERANCE || fabsf(ap1 - sp) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Airlock not pressurized: ap0=%.3f ap1=%.3f station=%.3f", ap0, ap1, sp);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_CLOSED_DEPRESSURIZED:
                    if (fabsf(ap0 - ep) > PRESSURE_ERROR_TOLERANCE || fabsf(ap1 - ep) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Airlock not depressurized: ap0=%.3f ap1=%.3f exterior=%.3f", ap0, ap1, ep);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_INTERIOR_OPEN:
                    if (fabsf(ap0 - sp) > PRESSURE_ERROR_TOLERANCE || fabsf(ap1 - sp) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Interior open but airlock pressure != station: ap0=%.3f ap1=%.3f exterior=%.3f", ap0, ap1, ep);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_EXTERIOR_OPEN:
                    if (fabsf(ap0 - ep) > PRESSURE_ERROR_TOLERANCE || fabsf(ap1 - ep) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Exterior open but airlock pressure != exterior: ap0=%.3f ap1=%.3f exterior=%.3f", ap0, ap1, ep);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_PRESSURIZING:
                    // Expect airlock to approach station pressure
                    if (fabsf(ap0 - sp) <= PRESSURE_ERROR_TOLERANCE && fabsf(ap1 - sp) <= PRESSURE_ERROR_TOLERANCE)
                    {
                        airlock_state = AIRLOCK_CLOSED_PRESSURIZED;
                        sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_PRESSURIZED");
                    }
                    break;
                case AIRLOCK_DEPRESSURIZING:
                    // Expect airlock to approach exterior pressure
                    if (fabsf(ap0 - ep) <= PRESSURE_ERROR_TOLERANCE && fabsf(ap1 - ep) <= PRESSURE_ERROR_TOLERANCE)
                    {
                        airlock_state = AIRLOCK_CLOSED_DEPRESSURIZED;
                        sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_DEPRESSURIZED");
                    }
                    break;
                default:
                    break;
                }

                if (pressure_fault)
                {
                    fault_bits |= FAULT_PRESSURE;
                }
                else
                {
                    if (airlock_state == AIRLOCK_PRESSURIZING || airlock_state == AIRLOCK_DEPRESSURIZING)
                    {
                        if (now - pressure_change_time > PRESSURE_CHANGE_TIMEOUT_MS)
                        {
                            sdn_log(SDN_ERROR, "Pressure change timeout exceeded");
                            fault_bits |= FAULT_PRESSURE;
                        }
                    }
                }
            }
        }

        BroadcastHeartbeat(fault_bits);
        SleepMS(SLEEP_PERIOD_MS);
    }

    return 0;
}
