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

static const double PRESSURE_ERROR_TOLERANCE = 0.1;
static const unsigned DEVICE_WATCHDOG_TIMEOUT_MS = 100;
static const unsigned SLEEP_PERIOD_MS = 1;

static const unsigned PRESSURE_CHANGE_TIMEOUT_MS = 5000;

static const uint32_t FAULT_DOOR_BIT = 1 << 0;
static const uint32_t FAULT_DEBUGGER = 1 << 1;
static const uint32_t FAULT_PRESSURE = 1 << 2;
static const uint32_t FAULT_OCCUPANCY = 1 << 3;

static const uint32_t INNER_DOOR_IDX = 0;
static const uint32_t OUTER_DOOR_IDX = 1;

static const uint32_t INNER_DOOR_STATION_SIDE_IDX = 0;
static const uint32_t INNER_DOOR_AIRLOCK_SIDE_IDX = 1;
static const uint32_t OUTER_DOOR_EXTERIOR_SIDE_IDX = 0;
static const uint32_t OUTER_DOOR_AIRLOCK_SIDE_IDX = 1;

static const uint8_t INNER_PRESSURE_ZONE = 0;
static const uint8_t OUTER_PRESSURE_ZONE = 1;

static const char *DOOR_NAMES[2] = {"station", "exterior"};

static const size_t MAX_USER_DATA_SIZE = 1024;
static const size_t MAX_NUM_OCCUPANTS = 10;
static const size_t MAX_SEND_MESSAGE_SIZE = MAX_USER_DATA_SIZE + sizeof(SDNSetSuitOccupantMessage);
static const size_t MAX_OCCUPANCY_DATA_SIZE = (MAX_USER_DATA_SIZE + sizeof(SDNOccupancyInfo)) * MAX_NUM_OCCUPANTS;
static const size_t MAX_OCCUPANCY_MESSAGE_SIZE = MAX_OCCUPANCY_DATA_SIZE + sizeof(SDNOccupancyMessage);

///////////// Definitions /////////////////////

typedef struct DoorStatus DoorStatus;
struct DoorStatus
{
    SDNHeartBeatMessage heartbeat;
    SDNPressureMessage pressure[2];
};

typedef enum AirlockStateMachine AirlockStateMachine;
enum AirlockStateMachine
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
    uint32_t suit_locker_id;
    uint32_t occupancy_sensor_id;
    uint32_t rx_message_buffer_size;
};

#pragma pack(push, 1)
typedef struct OccupancyMessageWithBuffer OccupancyMessageWithBuffer;
struct OccupancyMessageWithBuffer
{
    SDNOccupancyMessage msg;
    uint8_t data_buffer[MAX_OCCUPANCY_DATA_SIZE];
};
#pragma pack(pop)

typedef struct AirlockState AirlockState;
struct AirlockState
{
    AirlockConfig config;
    AirlockStateMachine airlock_state;
    uint32_t fault_bits;
    DoorStatus door_status[2];

    sdn_timestamp_t pressure_change_time;
    float *station_pressure;
    float *exterior_pressure;
    float *airlock_pressures[2];

    SDNHeartBeatMessage occupancy_heartbeat;
    OccupancyMessageWithBuffer occupancy_message;
};

////////////////////// Global Variables ///////////////////////

AirlockState state = {0};
void *rx_message_buffer = NULL;
uint8_t message_serialization_buffer[MAX_SEND_MESSAGE_SIZE];

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

static bool InitializeSDN(const AirlockConfig *config)
{
    assert(config != NULL);
    if (!RegisterDevice(config->device_id, SDN_DEVICE_TYPE_AIRLOCK_CTRL))
    {
        return false;
    }
    if (!SubscribeToMessage(config->inside_door_id, SDN_MSG_TYPE_HEARTBEAT))
    {
        return false;
    }
    if (!SubscribeToMessage(config->inside_door_id, SDN_MSG_TYPE_SENSOR_PRESSURE))
    {
        return false;
    }
    if (!SubscribeToMessage(config->outside_door_id, SDN_MSG_TYPE_HEARTBEAT))
    {
        return false;
    }
    if (!SubscribeToMessage(config->outside_door_id, SDN_MSG_TYPE_SENSOR_PRESSURE))
    {
        return false;
    }
    if (!SubscribeToMessage(config->occupancy_sensor_id, SDN_MSG_TYPE_HEARTBEAT))
    {
        return false;
    }
    if (!SubscribeToMessage(config->occupancy_sensor_id, SDN_MSG_TYPE_SENSOR_OCCUPANCY))
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
    config->suit_locker_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "suit_locker_id"))
    {
        return false;
    }
    config->suit_locker_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "rx_message_buffer_size"))
    {
        return false;
    }
    config->rx_message_buffer_size = (uint32_t)tmp;

    return true;
}

static void HandleHeartBeat(const void *message_data, size_t msg_len)
{
    if (msg_len >= sizeof(SDNHeartBeatMessage))
    {
        const SDNHeartBeatMessage *hb = (const SDNHeartBeatMessage *)message_data;
        uint32_t src_id = hb->msg_header.device_id;
        int idx = -1;
        if (src_id == state.config.inside_door_id)
            idx = INNER_DOOR_IDX;
        else if (src_id == state.config.outside_door_id)
            idx = OUTER_DOOR_IDX;
        else if (src_id == state.config.occupancy_sensor_id)
        {
            state.occupancy_heartbeat = *hb;
        }

        if (idx >= 0)
        {
            state.door_status[idx].heartbeat = *hb;
        }
    }
    else
    {
        sdn_log(SDN_WARN, "Received HEARTBEAT message with invalid length %d", msg_len);
    }
}

static void HandleSensorPressure(const void *message_data, size_t msg_len)
{
    if (msg_len >= sizeof(SDNPressureMessage))
    {
        const SDNPressureMessage *pm = (const SDNPressureMessage *)message_data;
        uint32_t src_id = pm->msg_header.device_id;
        int idx = -1;
        if (src_id == state.config.inside_door_id)
            idx = INNER_DOOR_IDX;
        else if (src_id == state.config.outside_door_id)
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
                state.door_status[idx].pressure[side_idx] = *pm;
            }
        }
    }
    else
    {
        sdn_log(SDN_WARN, "Received SENSOR_PRESSURE message with invalid length %d", msg_len);
    }
}

static void HandleSetAirlockOpen(const void *message_data, size_t msg_len)
{
    if (state.fault_bits != 0)
    {
        sdn_log(SDN_WARN, "Door commands ignored while fault active.");
        SendCmdResponse(0x100);
        return;
    }

    if (msg_len < sizeof(SDNSetAirlockOpenMessage))
    {
        sdn_log(SDN_WARN, "Received SET_AIRLOCK_OPEN message with invalid length %d", (int)msg_len);
        SendCmdResponse(0x200);
        return;
    }

    const SDNSetAirlockOpenMessage *cf = (const SDNSetAirlockOpenMessage *)message_data;
    SDNAirlockOpen airlock_req = cf->open;
    if (airlock_req == SDN_AIRLOCK_CLOSED)
    {
        if (!ControlDoor(state.config.device_id, state.config.outside_door_id, false) || !ControlDoor(state.config.device_id, state.config.inside_door_id, false))
        {
            /* fatal control error; keep behavior consistent with previous main */
            exit(4);
        }

        if (state.airlock_state == AIRLOCK_INTERIOR_OPEN)
        {
            state.airlock_state = AIRLOCK_CLOSED_PRESSURIZED;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_PRESSURIZED");
        }
        else if (state.airlock_state == AIRLOCK_EXTERIOR_OPEN)
        {
            state.airlock_state = AIRLOCK_CLOSED_DEPRESSURIZED;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_DEPRESSURIZED");
        }
    }
    else if (airlock_req == SDN_AIRLOCK_INTERIOR_OPEN)
    {
        switch (state.airlock_state)
        {
        case AIRLOCK_INTERIOR_OPEN:
            break;
        case AIRLOCK_CLOSED_PRESSURIZED:
            if (!ControlDoor(state.config.device_id, state.config.inside_door_id, true))
            {
                exit(4);
            }
            state.airlock_state = AIRLOCK_INTERIOR_OPEN;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_INTERIOR_OPEN");
            break;
        case AIRLOCK_EXTERIOR_OPEN:
        case AIRLOCK_CLOSED_DEPRESSURIZED:
        case AIRLOCK_DEPRESSURIZING:
            if (!ControlDoor(state.config.device_id, state.config.outside_door_id, false))
            {
                exit(4);
            }
            if (!ControlPressure(state.config.device_id, state.config.pressure_ctrl_id, true, &state.pressure_change_time))
            {
                exit(4);
            }
            state.airlock_state = AIRLOCK_PRESSURIZING;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_PRESSURIZING");
            break;
        case AIRLOCK_PRESSURIZING:
            break;
        }
    }
    else if (airlock_req == SDN_AIRLOCK_EXTERIOR_OPEN)
    {
        if (state.occupancy_message.msg.msg_header.msg_type != SDN_MSG_TYPE_SENSOR_OCCUPANCY)
        {
            sdn_log(SDN_WARN, "Received SDN_AIRLOCK_EXTERIOR_OPEN message before receiving occupancy data");
            SendCmdResponse(0x002);
        }

        bool safe_to_open = true;
        size_t remaining_len = 0;
        const SDNOccupancyInfo *occupant = GetFirstOccupant(&state.occupancy_message.msg, &remaining_len);
        while (remaining_len != 0)
        {
            if (occupant == NULL || occupant->suit_status != SDN_SUIT_STATUS_SEALED)
            {
                safe_to_open = false;
                break;
            }
            occupant = GetNextOccupant(occupant, &remaining_len);
        }

        if (safe_to_open)
        {
            switch (state.airlock_state)
            {
            case AIRLOCK_EXTERIOR_OPEN:
                break;
            case AIRLOCK_CLOSED_DEPRESSURIZED:
                if (!ControlDoor(state.config.device_id, state.config.outside_door_id, true))
                {
                    exit(4);
                }
                state.airlock_state = AIRLOCK_EXTERIOR_OPEN;
                sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_EXTERIOR_OPEN");
                break;
            case AIRLOCK_INTERIOR_OPEN:
            case AIRLOCK_CLOSED_PRESSURIZED:
            case AIRLOCK_PRESSURIZING:
                if (!ControlDoor(state.config.device_id, state.config.inside_door_id, false))
                {
                    exit(4);
                }
                if (!ControlPressure(state.config.device_id, state.config.pressure_ctrl_id, false, &state.pressure_change_time))
                {
                    exit(4);
                }
                state.airlock_state = AIRLOCK_DEPRESSURIZING;
                sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_DEPRESSURIZING");
                break;
            case AIRLOCK_DEPRESSURIZING:
                break;
            default:
                break;
            }
        }
        else
        {
            sdn_log(SDN_WARN, "Received SDN_AIRLOCK_EXTERIOR_OPEN message with unsealed occupants");
            SendCmdResponse(0x001);
            return;
        }
    }
    SendCmdResponse(SDN_CMD_SUCCESS);
}

static void HandleClearFaults(const void *message_data, size_t msg_len)
{
    if (msg_len >= sizeof(SDNClearFaultsMessage))
    {
        const SDNClearFaultsMessage *cf = (const SDNClearFaultsMessage *)message_data;
        state.fault_bits &= ~cf->fault_mask;
        SendCmdResponse(SDN_CMD_SUCCESS);
    }
    else
    {
        sdn_log(SDN_WARN, "Received CLEAR_FAULTS message with invalid length %d", (int)msg_len);
        SendCmdResponse(0x200);
    }
}

static void HandleRequestSuitOccupant(const void *message_data, size_t msg_len)
{
    if (msg_len >= sizeof(SDNRequestSuitOccupantMessage))
    {
        const SDNClearFaultsMessage *cf = (const SDNClearFaultsMessage *)message_data;
        bool safe_to_open = true;
        size_t remaining_len = 0;
        const SDNOccupancyInfo *occupant = GetFirstOccupant(&state.occupancy_message.msg, &remaining_len);
        while (remaining_len != 0)
        {
            if (occupant == NULL || occupant->suit_status != SDN_SUIT_STATUS_SEALED)
            {
                safe_to_open = false;
                break;
            }
            occupant = GetNextOccupant(occupant, &remaining_len);
        }
        SendCmdResponse(SDN_CMD_SUCCESS);
    }
    else
    {
        sdn_log(SDN_WARN, "Received CLEAR_FAULTS message with invalid length %d", (int)msg_len);
        SendCmdResponse(0x200);
    }
}

static void HandleSensorOccupancy(const void *message_data, size_t msg_len)
{
    if (msg_len <= MAX_OCCUPANCY_MESSAGE_SIZE && msg_len >= sizeof(SDNOccupancyMessage))
    {
        const SDNOccupancyMessage *pm = (const SDNOccupancyMessage *)message_data;
        if (pm->msg_header.device_id == state.config.occupancy_sensor_id)
        {
            // Validate user data sizes align with reported length
            size_t remaining_len = 0;
            const SDNOccupancyInfo *info = GetFirstOccupant(pm, &remaining_len);
            while (remaining_len != 0)
            {
                if (info == NULL)
                {
                    sdn_log(SDN_WARN, "Received SDN_MSG_TYPE_SENSOR_OCCUPANCY message with invalid user data lengths");
                    exit(5);
                }
                info = GetNextOccupant(info, &remaining_len);
            }

            const size_t total_info_len = pm->msg_header.msg_length - sizeof(SDNOccupancyMessage);
            state.occupancy_message.msg = *pm;
            memcpy(state.occupancy_message.data_buffer, pm->occupants, total_info_len);
        }
    }
    else
    {
        sdn_log(SDN_WARN, "Received SDN_MSG_TYPE_SENSOR_OCCUPANCY message with invalid length %d", msg_len);
        exit(5);
    }
}

#if APP_DEBUG_BUILD
static void HandleDebugWriteConfigInt(void *message_data, size_t msg_len)
{
    if (msg_len >= sizeof(SDNDebugWriteConfigInt))
    {
        uint32_t cmd_response = 0x001;
        SDNDebugWriteConfigInt *cf = (SDNDebugWriteConfigInt *)message_data;
        cf->key[sizeof(cf->key) - 1] = 0;
        state.fault_bits &= FAULT_DEBUGGER;
        if (WriteConfigInt(cf->key, cf->value))
        {
            cmd_response = SDN_CMD_SUCCESS;
            if (!LoadConfig(&state.config))
            {
                exit(1);
            }
        }
        SendCmdResponse(cmd_response);
    }
    else
    {
        sdn_log(SDN_WARN, "Received DEBUG_WRITE_CONFIG_INT with invalid length %d", (int)msg_len);
        SendCmdResponse(0x200);
    }
}
#endif

int main()
{
    if (!LoadConfig(&state.config))
    {
        return 1;
    }

    memset(state.door_status, 0, sizeof(state.door_status));

    sdn_timestamp_t start_time = GetCurrentTimestampMS();
    for (int i = 0; i < 2; i++)
    {
        state.door_status[i].heartbeat = (SDNHeartBeatMessage){.health = SDN_HEALTH_GOOD, .msg_header.timestamp = start_time};
        state.door_status[i].pressure[0].msg_header.timestamp = start_time;
        state.door_status[i].pressure[1].msg_header.timestamp = start_time;
    }

    state.airlock_state = AIRLOCK_PRESSURIZING;
    sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_PRESSURIZING");

    state.station_pressure = &state.door_status[INNER_DOOR_IDX].pressure[INNER_DOOR_STATION_SIDE_IDX].pressure_pa;
    *state.station_pressure = NAN;

    state.exterior_pressure = &state.door_status[OUTER_DOOR_IDX].pressure[OUTER_DOOR_EXTERIOR_SIDE_IDX].pressure_pa;
    *state.exterior_pressure = NAN;

    state.airlock_pressures[0] = &state.door_status[INNER_DOOR_IDX].pressure[INNER_DOOR_AIRLOCK_SIDE_IDX].pressure_pa;
    *state.airlock_pressures[0] = NAN;
    state.airlock_pressures[1] = &state.door_status[OUTER_DOOR_IDX].pressure[OUTER_DOOR_AIRLOCK_SIDE_IDX].pressure_pa;
    *state.airlock_pressures[1] = NAN;

    state.occupancy_heartbeat = (SDNHeartBeatMessage){.health = SDN_HEALTH_GOOD, .msg_header.timestamp = start_time};

    if (!InitializeSDN(&state.config))
    {
        return 2;
    }

    rx_message_buffer = malloc(state.config.rx_message_buffer_size);
    if (rx_message_buffer == NULL)
    {
        return 3;
    }

    if (!ControlDoor(state.config.device_id, state.config.outside_door_id, false) || !ControlDoor(state.config.device_id, state.config.inside_door_id, false))
    {
        return 4;
    }

    if (!ControlPressure(state.config.device_id, state.config.pressure_ctrl_id, true, &state.pressure_change_time))
    {
        return 4;
    }

    while (true)
    {
        while (true)
        {
            int ret = ReadNextMessage(rx_message_buffer, state.config.rx_message_buffer_size);
            if (ret < 0)
            {
                return 5;
            }

            if (ret <= 0)
            {
                break;
            }

            SDNMsgHeader *msg_header = (SDNMsgHeader *)rx_message_buffer;
            switch (msg_header->msg_type)
            {
            case SDN_MSG_TYPE_HEARTBEAT:
                HandleHeartBeat(rx_message_buffer, ret);
                break;

            case SDN_MSG_TYPE_SENSOR_PRESSURE:
                HandleSensorPressure(rx_message_buffer, ret);
                break;

            case SDN_MSG_TYPE_SENSOR_OCCUPANCY:
                HandleSensorOccupancy(rx_message_buffer, ret);
                break;

            case SDN_MSG_TYPE_SET_AIRLOCK_OPEN:
                HandleSetAirlockOpen(rx_message_buffer, ret);
                break;

            case SDN_MSG_TYPE_CLEAR_FAULTS:
                HandleClearFaults(rx_message_buffer, ret);
                break;

            case SDN_MSG_TYPE_REQUEST_SUIT_OCCUPANT:
                HandleRequestSuitOccupant(rx_message_buffer, ret);
                break;

#if APP_DEBUG_BUILD
            case SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT:
                HandleDebugWriteConfigInt(rx_message_buffer, ret);
                break;
#endif

            default:
                break;
            }
        }

        sdn_timestamp_t now = GetCurrentTimestampMS();

        /* Watchdog: check for missed messages from doors and set fault bit */
        if (!(state.fault_bits & FAULT_DOOR_BIT))
        {
            uint32_t door_fault = 0;
            for (int i = 0; i < 2; ++i)
            {
                if (now - state.door_status[i].heartbeat.msg_header.timestamp > DEVICE_WATCHDOG_TIMEOUT_MS)
                {
                    door_fault = FAULT_DOOR_BIT;
                    sdn_log(SDN_CRITICAL, "%s door heartbeat timeout", DOOR_NAMES[i]);
                }
                for (int j = 0; j < 2; ++j)
                {
                    if (now - state.door_status[i].pressure[j].msg_header.timestamp > DEVICE_WATCHDOG_TIMEOUT_MS)
                    {
                        door_fault = FAULT_DOOR_BIT;
                        sdn_log(SDN_CRITICAL, "%s door pressure timeout", DOOR_NAMES[i]);
                    }
                }
            }
            state.fault_bits |= door_fault;
        }

        if (!(state.fault_bits & FAULT_OCCUPANCY))
        {
            if (state.occupancy_heartbeat.health != SDN_HEALTH_GOOD || now - state.occupancy_heartbeat.msg_header.timestamp > DEVICE_WATCHDOG_TIMEOUT_MS)
            {
                state.fault_bits |= FAULT_OCCUPANCY;
                sdn_log(SDN_CRITICAL, "Occupancy sensor heartbeat timeout");
            }
        }

        if (!(state.fault_bits & FAULT_DOOR_BIT) && !(state.fault_bits & FAULT_PRESSURE))
        {
            bool pressure_initialized = !isnan(*state.station_pressure) && !isnan(*state.exterior_pressure) && !isnan(*state.airlock_pressures[0]) && !isnan(*state.airlock_pressures[1]);
            if (pressure_initialized)
            {
                double sp = (double)*state.station_pressure;
                double ep = (double)*state.exterior_pressure;
                double ap0 = (double)*state.airlock_pressures[0];
                double ap1 = (double)*state.airlock_pressures[1];

                bool pressure_fault = false;

                switch (state.airlock_state)
                {
                case AIRLOCK_CLOSED_PRESSURIZED:
                    if (fabs(ap0 - sp) > PRESSURE_ERROR_TOLERANCE || fabs(ap1 - sp) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Airlock not pressurized: ap0=%.3f ap1=%.3f station=%.3f", ap0, ap1, sp);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_CLOSED_DEPRESSURIZED:
                    if (fabs(ap0 - ep) > PRESSURE_ERROR_TOLERANCE || fabs(ap1 - ep) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Airlock not depressurized: ap0=%.3f ap1=%.3f exterior=%.3f", ap0, ap1, ep);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_INTERIOR_OPEN:
                    if (fabs(ap0 - sp) > PRESSURE_ERROR_TOLERANCE || fabs(ap1 - sp) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Interior open but airlock pressure != station: ap0=%.3f ap1=%.3f exterior=%.3f", ap0, ap1, ep);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_EXTERIOR_OPEN:
                    if (fabs(ap0 - ep) > PRESSURE_ERROR_TOLERANCE || fabs(ap1 - ep) > PRESSURE_ERROR_TOLERANCE)
                    {
                        sdn_log(SDN_CRITICAL, "Exterior open but airlock pressure != exterior: ap0=%.3f ap1=%.3f exterior=%.3f", ap0, ap1, ep);
                        pressure_fault = true;
                    }
                    break;
                case AIRLOCK_PRESSURIZING:
                    // Expect airlock to approach station pressure
                    if (fabs(ap0 - sp) <= PRESSURE_ERROR_TOLERANCE && fabs(ap1 - sp) <= PRESSURE_ERROR_TOLERANCE)
                    {
                        state.airlock_state = AIRLOCK_CLOSED_PRESSURIZED;
                        sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_PRESSURIZED");
                    }
                    break;
                case AIRLOCK_DEPRESSURIZING:
                    // Expect airlock to approach exterior pressure
                    if (fabs(ap0 - ep) <= PRESSURE_ERROR_TOLERANCE && fabs(ap1 - ep) <= PRESSURE_ERROR_TOLERANCE)
                    {
                        state.airlock_state = AIRLOCK_CLOSED_DEPRESSURIZED;
                        sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_DEPRESSURIZED");
                    }
                    break;
                default:
                    break;
                }

                if (pressure_fault)
                {
                    state.fault_bits |= FAULT_PRESSURE;
                }
                else
                {
                    if (state.airlock_state == AIRLOCK_PRESSURIZING || state.airlock_state == AIRLOCK_DEPRESSURIZING)
                    {
                        if (now - state.pressure_change_time > PRESSURE_CHANGE_TIMEOUT_MS)
                        {
                            sdn_log(SDN_ERROR, "Pressure change timeout exceeded");
                            state.fault_bits |= FAULT_PRESSURE;
                        }
                    }
                }
            }
        }

        BroadcastHeartbeat(state.fault_bits);
        SleepMS(SLEEP_PERIOD_MS);
    }

    return 0;
}
