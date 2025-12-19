#include <assert.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
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

static const uint32_t INNER_DOOR_IDX = 0;
static const uint32_t OUTER_DOOR_IDX = 1;

static const uint32_t INNER_DOOR_STATION_SIDE_IDX = 0;
static const uint32_t INNER_DOOR_AIRLOCK_SIDE_IDX = 1;
static const uint32_t OUTER_DOOR_EXTERIOR_SIDE_IDX = 0;
static const uint32_t OUTER_DOOR_AIRLOCK_SIDE_IDX = 1;

static const uint8_t INNER_PRESSURE_ZONE = 0;
static const uint8_t OUTER_PRESSURE_ZONE = 1;

static const char *DOOR_NAMES[2] = {"station", "exterior"};

#define MAX_USER_DATA_SIZE 1024
#define MAX_SEND_MESSAGE_SIZE (MAX_USER_DATA_SIZE + sizeof(SDNSetSuitOccupantMessage))
#define MAX_NUM_OCCUPANTS 10

// HandleHeartBeat
// HandleSensorPressure
// HandleSetAirlockOpen
// HandleSetSuitOccupant
// if state.config.remote_fault_clear
// HandleClearFaults
// #if APP_DEBUG_BUILD
// HandleDebugWriteConfigInt
#define MIN_NUM_MESSAGE_HANDLERS 4

///////////// Definitions /////////////////////

typedef enum ExitCode ExitCode;
enum ExitCode
{
    EXIT_CODE_SUCCESS = 0,
    EXIT_CODE_CONFIG_LOAD_FAILED = 1,
    EXIT_CODE_SDN_INIT_FAILED = 2,
    EXIT_CODE_MEMORY_ALLOC_FAILED = 3,
    EXIT_CODE_CONTROL_CMD_FAILED = 4,
    EXIT_CODE_MESSAGE_ERROR = 5,
};

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
    bool apply_config_change;
    bool remote_fault_clear;
};

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

    uint8_t message_serialization_buffer[MAX_SEND_MESSAGE_SIZE];
};

////////////////////// Implementation ///////////////////////

static void exit_with_error(ExitCode exit_code)
{
    switch (exit_code)
    {
    case EXIT_CODE_CONFIG_LOAD_FAILED:
        sdn_log(SDN_CRITICAL, "Failed to load configuration.");
        break;
    case EXIT_CODE_SDN_INIT_FAILED:
        sdn_log(SDN_CRITICAL, "Failed to initialize SDN.");
        break;
    case EXIT_CODE_MEMORY_ALLOC_FAILED:
        sdn_log(SDN_CRITICAL, "Memory allocation failed.");
        break;
    case EXIT_CODE_CONTROL_CMD_FAILED:
        sdn_log(SDN_CRITICAL, "Control command failed.");
        break;
    case EXIT_CODE_MESSAGE_ERROR:
        sdn_log(SDN_CRITICAL, "Message processing or request error.");
        break;
    case EXIT_CODE_SUCCESS:
    default:
        // No message for success or unhandled codes.
        break;
    }
    exit(exit_code);
}

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
    return true;
}

static bool LoadConfig(AirlockConfig *config)
{
    if (!LoadConfigU32(&config->device_id, "device_id"))
    {
        return false;
    }
    if (!LoadConfigU32(&config->inside_door_id, "inside_door_id"))
    {
        return false;
    }
    if (!LoadConfigU32(&config->outside_door_id, "outside_door_id"))
    {
        return false;
    }
    if (!LoadConfigU32(&config->pressure_ctrl_id, "pressure_ctrl_id"))
    {
        return false;
    }
    if (!LoadConfigU32(&config->occupancy_sensor_id, "occupancy_sensor_id"))
    {
        return false;
    }
    if (!LoadConfigU32(&config->suit_locker_id, "suit_locker_id"))
    {
        return false;
    }
    if (!LoadConfigU32(&config->rx_message_buffer_size, "rx_message_buffer_size"))
    {
        return false;
    }
    if (!LoadConfigBool(&config->apply_config_change, "apply_config_change"))
    {
        return false;
    }
    if (!LoadConfigBool(&config->remote_fault_clear, "remote_fault_clear"))
    {
        return false;
    }
    return true;
}

static inline int get_door_idx_from_id(const AirlockConfig *config, uint32_t device_id)
{
    if (device_id == config->inside_door_id)
        return INNER_DOOR_IDX;
    if (device_id == config->outside_door_id)
        return OUTER_DOOR_IDX;
    return -1;
}

static void HandleHeartBeat(const void *message_data, size_t msg_len, void *context)
{
    AirlockState *state = context;
    if (msg_len >= sizeof(SDNHeartBeatMessage))
    {
        const SDNHeartBeatMessage *hb = (const SDNHeartBeatMessage *)message_data;
        int idx = get_door_idx_from_id(&state->config, hb->msg_header.device_id);
        if (idx >= 0)
        {
            state->door_status[idx].heartbeat = *hb;
        }
    }
    else
    {
        sdn_log(SDN_WARN, "Received HEARTBEAT message with invalid length %d", msg_len);
    }
}

static void HandleSensorPressure(const void *message_data, size_t msg_len, void *context)
{
    AirlockState *state = context;
    if (msg_len >= sizeof(SDNPressureMessage))
    {
        const SDNPressureMessage *pm = (const SDNPressureMessage *)message_data;
        int idx = get_door_idx_from_id(&state->config, pm->msg_header.device_id);
        if (idx >= 0)
        {
            int side_idx = -1;
            if (pm->measurement_id == SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1)
                side_idx = 0;
            else if (pm->measurement_id == SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2)
                side_idx = 1;
            if (side_idx >= 0)
            {
                state->door_status[idx].pressure[side_idx] = *pm;
            }
        }
    }
    else
    {
        sdn_log(SDN_WARN, "Received SENSOR_PRESSURE message with invalid length %d", msg_len);
    }
}

static void HandleSetAirlockOpen(const void *message_data, size_t msg_len, void *context)
{
    AirlockState *state = context;
    SDNOccupancyMessage occupancy_msg_buffer[MAX_NUM_OCCUPANTS];
    if (state->fault_bits != 0)
    {
        sdn_log(SDN_WARN, "Door commands ignored while fault active.");
        SendCmdResponse(SDN_RESPONSE_CMD_ERROR_1);
        return;
    }

    if (msg_len < sizeof(SDNSetAirlockOpenMessage))
    {
        sdn_log(SDN_WARN, "Received SET_AIRLOCK_OPEN message with invalid length %d", (int)msg_len);
        SendCmdResponse(SDN_RESPONSE_INVALID_MSG_LEN);
        return;
    }

    const SDNSetAirlockOpenMessage *cf = (const SDNSetAirlockOpenMessage *)message_data;
    SDNAirlockOpen airlock_req = cf->open;
    if (airlock_req == SDN_AIRLOCK_CLOSED)
    {
        if (!ControlDoor(state->config.device_id, state->config.outside_door_id, false) || !ControlDoor(state->config.device_id, state->config.inside_door_id, false))
        {
            exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
        }

        if (state->airlock_state == AIRLOCK_INTERIOR_OPEN)
        {
            state->airlock_state = AIRLOCK_CLOSED_PRESSURIZED;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_PRESSURIZED");
        }
        else if (state->airlock_state == AIRLOCK_EXTERIOR_OPEN)
        {
            state->airlock_state = AIRLOCK_CLOSED_DEPRESSURIZED;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_CLOSED_DEPRESSURIZED");
        }
    }
    else if (airlock_req == SDN_AIRLOCK_INTERIOR_OPEN)
    {
        switch (state->airlock_state)
        {
        case AIRLOCK_INTERIOR_OPEN:
            break;
        case AIRLOCK_CLOSED_PRESSURIZED:
            if (!ControlDoor(state->config.device_id, state->config.inside_door_id, true))
            {
                exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
            }
            state->airlock_state = AIRLOCK_INTERIOR_OPEN;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_INTERIOR_OPEN");
            break;
        case AIRLOCK_EXTERIOR_OPEN:
        case AIRLOCK_CLOSED_DEPRESSURIZED:
        case AIRLOCK_DEPRESSURIZING:
            if (!ControlDoor(state->config.device_id, state->config.outside_door_id, false))
            {
                exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
            }
            if (!ControlPressure(state->config.device_id, state->config.pressure_ctrl_id, true, &state->pressure_change_time))
            {
                exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
            }
            state->airlock_state = AIRLOCK_PRESSURIZING;
            sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_PRESSURIZING");
            break;
        case AIRLOCK_PRESSURIZING:
            break;
        }
    }
    else if (airlock_req == SDN_AIRLOCK_EXTERIOR_OPEN)
    {
        bool safe_to_open = true;
        SDNResponseStatus occupancy_resp = RequestMessage(occupancy_msg_buffer, sizeof(occupancy_msg_buffer), state->config.occupancy_sensor_id, SDN_MSG_TYPE_SENSOR_OCCUPANCY);
        switch (occupancy_resp)
        {
        case SDN_RESPONSE_GOOD:
        {
            const size_t num_occupants = (occupancy_msg_buffer->msg_header.msg_length - sizeof(SDNOccupancyMessage)) /
                                         sizeof(SDNOccupancyInfo);

            if (num_occupants > MAX_NUM_OCCUPANTS)
            {
                safe_to_open = false;
            }
            else
            {
                for (const SDNOccupancyInfo *occupant = occupancy_msg_buffer->occupants; occupant < occupancy_msg_buffer->occupants + num_occupants; occupant++)
                {
                    if (occupant == NULL || occupant->suit_status != SDN_SUIT_STATUS_SEALED)
                    {
                        safe_to_open = false;
                        break;
                    }
                }
            }
        }
        break;
        case SDN_RESPONSE_BUFFER_TOO_SMALL:
        {
            sdn_log(SDN_WARN, "Received SDN_AIRLOCK_EXTERIOR_OPEN message with too many occupants");
            safe_to_open = false;
        }
        break;

        default:
            exit_with_error(EXIT_CODE_MESSAGE_ERROR);
        }

        if (safe_to_open)
        {
            switch (state->airlock_state)
            {
            case AIRLOCK_EXTERIOR_OPEN:
                break;
            case AIRLOCK_CLOSED_DEPRESSURIZED:
                if (!ControlDoor(state->config.device_id, state->config.outside_door_id, true))
                {
                    exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
                }
                state->airlock_state = AIRLOCK_EXTERIOR_OPEN;
                sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_EXTERIOR_OPEN");
                break;
            case AIRLOCK_INTERIOR_OPEN:
            case AIRLOCK_CLOSED_PRESSURIZED:
            case AIRLOCK_PRESSURIZING:
                if (!ControlDoor(state->config.device_id, state->config.inside_door_id, false))
                {
                    exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
                }
                if (!ControlPressure(state->config.device_id, state->config.pressure_ctrl_id, false, &state->pressure_change_time))
                {
                    exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
                }
                state->airlock_state = AIRLOCK_DEPRESSURIZING;
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
            SendCmdResponse(SDN_RESPONSE_CMD_ERROR_2);
            return;
        }
    }
    SendCmdResponse(SDN_RESPONSE_GOOD);
}

static void HandleClearFaults(const void *message_data, size_t msg_len, void *context)
{
    AirlockState *state = context;
    if (msg_len >= sizeof(SDNClearFaultsMessage))
    {
        const SDNClearFaultsMessage *cf = (const SDNClearFaultsMessage *)message_data;
        state->fault_bits &= ~cf->fault_mask;
        SendCmdResponse(SDN_RESPONSE_GOOD);
    }
    else
    {
        sdn_log(SDN_WARN, "Received CLEAR_FAULTS message with invalid length %d", (int)msg_len);
        SendCmdResponse(SDN_RESPONSE_INVALID_MSG_LEN);
    }
}

static void HandleSetSuitOccupant(const void *message_data, size_t msg_len, void *context)
{
    AirlockState *state = context;
    if (msg_len >= sizeof(SDNSetSuitOccupantMessage) && msg_len < MAX_SEND_MESSAGE_SIZE)
    {
        SDNSetSuitOccupantMessage *send_ptr = (SDNSetSuitOccupantMessage *)state->message_serialization_buffer;
        memcpy(send_ptr, message_data, msg_len);
        send_ptr->msg_header.device_id = state->config.device_id;
        if (ExecuteCmd(&send_ptr->msg_header, state->config.suit_locker_id))
        {
            SendCmdResponse(SDN_RESPONSE_GOOD);
        }
        else
        {
            SendCmdResponse(SDN_RESPONSE_CMD_ERROR_1);
        }
    }
    else
    {
        sdn_log(SDN_WARN, "Received SDN_MSG_TYPE_SET_SUIT_OCCUPANT message with invalid length %d", (int)msg_len);
        SendCmdResponse(SDN_RESPONSE_INVALID_MSG_LEN);
    }
}

#if APP_DEBUG_BUILD
static void HandleDebugWriteConfigInt(const void *message_data, size_t msg_len, void *context)
{
    AirlockState *state = context;
    if (msg_len >= sizeof(SDNDebugWriteConfigInt))
    {
        SDNResponseStatus cmd_response = SDN_RESPONSE_CMD_ERROR_3; // Default to error
        SDNDebugWriteConfigInt *cf = (SDNDebugWriteConfigInt *)message_data;
        cf->key[sizeof(cf->key) - 1] = 0;
        state->fault_bits |= FAULT_DEBUGGER;
        if (WriteConfigU32(cf->key, (uint32_t)cf->value) || WriteConfigBool(cf->key, (bool)cf->value))
        {
            cmd_response = SDN_RESPONSE_GOOD;
        }

        if (state->config.apply_config_change && cmd_response == SDN_RESPONSE_GOOD && !LoadConfig(&state->config))
        {
            exit_with_error(EXIT_CODE_CONFIG_LOAD_FAILED);
        }
        SendCmdResponse(cmd_response);
    }
    else
    {
        sdn_log(SDN_WARN, "Received DEBUG_WRITE_CONFIG_INT with invalid length %d", (int)msg_len);
        SendCmdResponse(SDN_RESPONSE_INVALID_MSG_LEN);
    }
}
#endif

static int ProcessMessageData(SDNHandler *handlers, size_t num_handlers,
                              void *msg_buffer, size_t buffer_size_bytes, void *context)
{
    assert(handlers != NULL);
    assert(msg_buffer != NULL);
    assert(buffer_size_bytes >= sizeof(SDNMsgHeader));
    while (true)
    {
        int ret = ReadNextMessage(msg_buffer, buffer_size_bytes);
        if (ret < 0)
        {
            return ret;
        }
        else if (ret == 0)
        {
            return 0;
        }
        else
        {
            SDNMsgHeader *msg_header = (SDNMsgHeader *)msg_buffer;
            for (SDNHandler *handler = handlers; handler < handlers + num_handlers;
                 handler++)
            {
                if (msg_header->msg_type == handler->type)
                {
                    handler->callback(msg_buffer, ret, context);
                }
            }
        }
    }
}

int main()
{
    AirlockState state = {0};

    void *rx_message_buffer = NULL;
    SDNHandler *message_handlers = NULL;

    if (!LoadConfig(&state.config))
    {
        exit_with_error(EXIT_CODE_CONFIG_LOAD_FAILED);
    }

    memset(state.door_status, 0, sizeof(state.door_status));

    sdn_timestamp_t start_time = GetCurrentTimestampMS();
    for (int i = 0; i < 2; i++)
    {
        state.door_status[i].heartbeat = (SDNHeartBeatMessage){.health = SDN_HEALTH_GOOD, .msg_header.timestamp = start_time};
        state.door_status[i].pressure[0].msg_header.timestamp = start_time;
        state.door_status[i].pressure[1].msg_header.timestamp = start_time;
    }

    state.station_pressure = &state.door_status[INNER_DOOR_IDX].pressure[INNER_DOOR_STATION_SIDE_IDX].pressure_pa;
    *state.station_pressure = NAN;

    state.exterior_pressure = &state.door_status[OUTER_DOOR_IDX].pressure[OUTER_DOOR_EXTERIOR_SIDE_IDX].pressure_pa;
    *state.exterior_pressure = NAN;

    state.airlock_pressures[0] = &state.door_status[INNER_DOOR_IDX].pressure[INNER_DOOR_AIRLOCK_SIDE_IDX].pressure_pa;
    *state.airlock_pressures[0] = NAN;
    state.airlock_pressures[1] = &state.door_status[OUTER_DOOR_IDX].pressure[OUTER_DOOR_AIRLOCK_SIDE_IDX].pressure_pa;
    *state.airlock_pressures[1] = NAN;

    if (!InitializeSDN(&state.config))
    {
        exit_with_error(EXIT_CODE_SDN_INIT_FAILED);
    }

    rx_message_buffer = malloc(state.config.rx_message_buffer_size);
    if (rx_message_buffer == NULL)
    {
        exit_with_error(EXIT_CODE_MEMORY_ALLOC_FAILED);
    }

    size_t num_message_handlers = MIN_NUM_MESSAGE_HANDLERS;
    if (state.config.remote_fault_clear)
    {
        num_message_handlers++;
    }
#if APP_DEBUG_BUILD
    num_message_handlers++;
#endif
    message_handlers = malloc(sizeof(SDNHandler) * num_message_handlers);
    if (message_handlers == NULL)
    {
        exit_with_error(EXIT_CODE_MEMORY_ALLOC_FAILED);
    }
    else
    {
        num_message_handlers = 0;
        message_handlers[num_message_handlers++] = (SDNHandler){.type = SDN_MSG_TYPE_SET_SUIT_OCCUPANT,
                                                                .callback = HandleSetSuitOccupant};
        message_handlers[num_message_handlers++] = (SDNHandler){.type = SDN_MSG_TYPE_HEARTBEAT,
                                                                .callback = HandleHeartBeat};
        message_handlers[num_message_handlers++] = (SDNHandler){.type = SDN_MSG_TYPE_SENSOR_PRESSURE,
                                                                .callback = HandleSensorPressure};
        message_handlers[num_message_handlers++] = (SDNHandler){.type = SDN_MSG_TYPE_SET_AIRLOCK_OPEN,
                                                                .callback = HandleSetAirlockOpen};
        if (state.config.remote_fault_clear)
        {
            message_handlers[num_message_handlers++] = (SDNHandler){.type = SDN_MSG_TYPE_CLEAR_FAULTS,
                                                                    .callback = HandleClearFaults};
        }
#if APP_DEBUG_BUILD
        message_handlers[num_message_handlers++] = (SDNHandler){.type = SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT,
                                                                .callback = HandleDebugWriteConfigInt};
#endif
    }

    if (!ControlDoor(state.config.device_id, state.config.outside_door_id, false) || !ControlDoor(state.config.device_id, state.config.inside_door_id, false))
    {
        exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
    }

    if (!ControlPressure(state.config.device_id, state.config.pressure_ctrl_id, true, &state.pressure_change_time))
    {
        exit_with_error(EXIT_CODE_CONTROL_CMD_FAILED);
    }
    state.airlock_state = AIRLOCK_PRESSURIZING;
    sdn_log(SDN_INFO, "airlock_state -> AIRLOCK_PRESSURIZING");

    while (true)
    {
        if (ProcessMessageData(message_handlers, num_message_handlers, rx_message_buffer, state.config.rx_message_buffer_size, &state) < 0)
        {
            exit_with_error(EXIT_CODE_MESSAGE_ERROR);
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
