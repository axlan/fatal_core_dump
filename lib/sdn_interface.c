#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "sdn_interface.h"
#include "log.h"

static const uint64_t YEAR_IN_MS = 365 * 24 * 60 * 60 * 1000ull;

static const float STATION_PRESSURE_PA = 101325;

static const sdn_timestamp_t START_TIMESTAMP = YEAR_IN_MS * 1.989438645;

static const uint32_t SDN_DEVICE_ID_DOOR_INNER = 0xae215e12;
static const uint32_t SDN_DEVICE_ID_DOOR_OUTER = 0xae215e13;
static const uint32_t SDN_DEVICE_ID_PRESSURE_CTRL = 0xae215e14;
static const uint32_t SDN_DEVICE_ID_OCCUPANCY_SENSOR = 0xae215e15;

static const uint32_t SDN_DEVICE_ID_CONTROL_PANEL_STATION = 0xae215e16;

static sdn_timestamp_t dummy_timestamp = START_TIMESTAMP;
static float airlock_pressure = STATION_PRESSURE_PA;

static const uint8_t INNER_PRESSURE_ZONE = 0;
static const uint8_t OUTER_PRESSURE_ZONE = 1;

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
sdn_timestamp_t GetCurrentTimestampMS(void)
{
    return dummy_timestamp;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
void SleepMS(unsigned ms)
{
    dummy_timestamp += ms;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool SubscribeToMessage(uint32_t device_id, SDNMsgType message_type)
{
    (void)device_id;
    (void)message_type;
    return true;
}

static size_t SendPressure(void *msg_buffer, size_t buffer_size_bytes, uint32_t pressure_device_id, uint32_t measurement_id, float pressure, sdn_timestamp_t *next_pressure_time)
{
    if (buffer_size_bytes >= sizeof(SDNPressureMessage))
    {
        SDNPressureMessage *msg = (SDNPressureMessage *)msg_buffer;
        msg->msg_header.device_id = pressure_device_id;
        msg->msg_header.msg_length = sizeof(SDNPressureMessage);
        msg->msg_header.msg_type = SDN_MSG_TYPE_SENSOR_PRESSURE;
        msg->msg_header.timestamp = dummy_timestamp;
        msg->measurement_id = measurement_id,
        msg->pressure_pa = pressure;
        *next_pressure_time += 50;
        return sizeof(SDNPressureMessage);
    }
    else
    {
        sdn_log(SDN_ERROR, "ReadNextMessage: buffer too small for SDNPressureMessage");
        return 0;
    }
}

static size_t SendPressureInt1(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendPressureInt1");
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER, SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1, STATION_PRESSURE_PA, next_time_ms);
}

static size_t SendPressureInt2(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendPressureInt2");
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER, SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2, airlock_pressure, next_time_ms);
}

static size_t SendPressureExt1(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendPressureExt1");
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_OUTER, SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1, 0, next_time_ms);
}

static size_t SendPressureExt2(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendPressureExt2");
    return SendPressure(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_OUTER, SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2, airlock_pressure, next_time_ms);
}

static size_t SendHeartBeat(void *msg_buffer, size_t buffer_size_bytes, uint32_t device_id, sdn_timestamp_t *next_time)
{
    if (buffer_size_bytes >= sizeof(SDNHeartBeatMessage))
    {
        SDNHeartBeatMessage *msg = (SDNHeartBeatMessage *)msg_buffer;
        msg->msg_header.device_id = device_id;
        msg->msg_header.msg_length = sizeof(SDNHeartBeatMessage);
        msg->msg_header.msg_type = SDN_MSG_TYPE_HEARTBEAT;
        msg->msg_header.timestamp = dummy_timestamp;
        msg->health = 0,
        *next_time += 50;
        return sizeof(SDNHeartBeatMessage);
    }
    else
    {
        sdn_log(SDN_ERROR, "ReadNextMessage: buffer too small for SDNHeartBeatMessage");
        return 0;
    }
}

static size_t SendHeartBeatInt(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendHeartBeatInt");
    return SendHeartBeat(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_INNER, next_time_ms);
}

static size_t SendHeartBeatExt(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SendHeartBeatExt");
    return SendHeartBeat(msg_buffer, buffer_size_bytes, SDN_DEVICE_ID_DOOR_OUTER, next_time_ms);
}

static size_t SendAirlockCmd(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms, SDNAirlockOpen open_state)
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
        sdn_log(SDN_ERROR, "ReadNextMessage: buffer too small for SDNSetAirlockOpenMessage");
    }
    return 0;
}

static size_t SendAirlockIntOpenCmd(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SDN_AIRLOCK_INTERIOR_OPEN");
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms, SDN_AIRLOCK_INTERIOR_OPEN);
}

static size_t SendAirlockExtOpenCmd(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SDN_AIRLOCK_EXTERIOR_OPEN");
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms, SDN_AIRLOCK_EXTERIOR_OPEN);
}

static size_t SendAirlockCloseCmd(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    sdn_log(SDN_DEBUG, "SDN_AIRLOCK_CLOSED");
    return SendAirlockCmd(msg_buffer, buffer_size_bytes, next_time_ms, SDN_AIRLOCK_CLOSED);
}

static size_t SendLargeBufferSizeConfigCmd(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms)
{
    *next_time_ms = 0xFFFFFFFFFFFFFFFF;
    if (buffer_size_bytes >= sizeof(SDNDebugWriteConfigInt))
    {
        SDNDebugWriteConfigInt *msg = (SDNDebugWriteConfigInt *)msg_buffer;
        msg->msg_header.device_id = SDN_DEVICE_ID_CONTROL_PANEL_STATION;
        msg->msg_header.msg_length = sizeof(SDNSetAirlockOpenMessage);
        msg->msg_header.msg_type = SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT;
        msg->msg_header.timestamp = dummy_timestamp;
        strcpy(msg->key, "message_buffer_size");
        msg->value = 10240;
        return sizeof(SDNDebugWriteConfigInt);
    }
    else
    {
        sdn_log(SDN_ERROR, "ReadNextMessage: buffer too small for SendLargeBufferSizeConfigCmd");
    }
    return 0;
}

typedef size_t (*MessageGenerator)(void *msg_buffer, size_t buffer_size_bytes, sdn_timestamp_t *next_time_ms);
typedef struct MessageEvent MessageEvent;
struct MessageEvent
{
    sdn_timestamp_t next_time_ms;
    MessageGenerator generator;
};

static MessageEvent message_events[] = {
    {.next_time_ms = 5,
     .generator = SendHeartBeatInt},
    {.next_time_ms = 5,
     .generator = SendPressureInt1},
    {.next_time_ms = 5,
     .generator = SendPressureInt2},
    {.next_time_ms = 6,
     .generator = SendHeartBeatExt},
    {.next_time_ms = 6,
     .generator = SendPressureExt1},
    {.next_time_ms = 6,
     .generator = SendPressureExt2},
    {.next_time_ms = 250,
     .generator = SendAirlockIntOpenCmd},
    {.next_time_ms = 350,
     .generator = SendAirlockExtOpenCmd},
    {.next_time_ms = 450,
     .generator = SendAirlockExtOpenCmd},
    {.next_time_ms = 550,
     .generator = SendAirlockIntOpenCmd},
    {.next_time_ms = 650,
     .generator = SendAirlockExtOpenCmd},
    {.next_time_ms = 1000,
     .generator = SendAirlockCloseCmd},
    {.next_time_ms = 2000,
     .generator = SendLargeBufferSizeConfigCmd},
};
static size_t NUM_MESSAGE_EVENTS = sizeof(message_events) / sizeof(MessageEvent);

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
int ReadNextMessage(void *msg_buffer, size_t buffer_size_bytes)
{
    for (size_t i = 0; i < NUM_MESSAGE_EVENTS; i++)
    {
        if (dummy_timestamp - START_TIMESTAMP > message_events[i].next_time_ms)
        {
            return (*message_events[i].generator)(msg_buffer, buffer_size_bytes, &message_events[i].next_time_ms);
        }
    }

    return 0;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool ExecuteCmd(const SDNMsgHeader *header, uint32_t target_device_id)
{
    if (target_device_id == SDN_DEVICE_ID_PRESSURE_CTRL && header->msg_type == SDN_MSG_TYPE_SET_PRESSURE_ZONE)
    {
        SDNSetPressureZoneMessage *pressure_cmd = (SDNSetPressureZoneMessage *)header;
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

SDNResponseStatus GetResponse(void *msg_buffer, size_t buffer_size_bytes, uint32_t target_device_id, SDNMsgType request_type)
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
            sdn_log(SDN_ERROR, "SDN_MSG_TYPE_SENSOR_OCCUPANCY too large %d", sizeof(SDNOccupancyMessage));
            return SDN_RESPONSE_BUFFER_TOO_SMALL;
        }
    }

    sdn_log(SDN_ERROR, "Response request failed");
    return SDN_RESPONSE_FAILED;
}

int ProcessMessageData(SDNHandler *handlers, size_t num_handlers, void *msg_buffer, size_t buffer_size_bytes)
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
            for (SDNHandler *handler = handlers; handler < handlers + num_handlers; handler++)
            {
                if (msg_header->msg_type == handler->type)
                {
                    handler->callback(msg_buffer, ret);
                }
            }
        }
    }
}

void SendCmdResponse(uint32_t response_code) { (void)response_code; }
