#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "config_loader.h"
#include "log.h"
#include "sdn_interface.h"

static const float PRESSURE_ERROR_TOLERANCE = 0.1;
static const size_t DEVICE_WATCHDOG_TIMEOUT_MS = 100;
static const size_t SLEEP_PERIOD_MS = 1;

static const uint32_t FAULT_DOOR_BIT = 1 << 0;
static const uint32_t FAULT_DEBUGGER = 1 << 1;


static const uint32_t INNER_DOOR_IDX = 0;
static const uint32_t OUTER_DOOR_IDX = 1;

static const uint32_t INNER_DOOR_STATION_SIDE_IDX = 0;
static const uint32_t INNER_DOOR_AIRLOCK_SIDE_IDX = 1;
static const uint32_t OUTER_DOOR_EXTERIOR_SIDE_IDX = 0;
static const uint32_t OUTER_DOOR_AIRLOCK_SIDE_IDX = 1;

typedef struct DoorStatus DoorStatus;
struct DoorStatus {
    SDNHeartBeatMessage heartbeat;
    SDNPressureMessage pressure[2];
};

static DoorStatus door_status[2];

static uint32_t fault_bits = 0;


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

int main()
{
    uint32_t device_id = 0;
    uint32_t inside_door_id = 0;
    uint32_t outside_door_id = 0;
    uint32_t message_buffer_size = 0;
    int tmp = 0;
    void* message_buffer = NULL;

    assert(sizeof(char*) == 8);

    memset(door_status, 0, sizeof(DoorStatus));

    sdn_timestamp_t start_time = GetCurrentTimestampMS();
    door_status->heartbeat.msg_header.timestamp = start_time;
    door_status->pressure[0].msg_header.timestamp = start_time;
    door_status->pressure[1].msg_header.timestamp = start_time;

    if (!LoadConfigInt(&tmp, "device_id"))
    {
        return 1;
    }
    device_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "inside_door_id"))
    {
        return 1;
    }
    inside_door_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "outside_door_id"))
    {
        return 1;
    }
    outside_door_id = (uint32_t)tmp;

    if (!LoadConfigInt(&tmp, "message_buffer_size"))
    {
        return 1;
    }
    message_buffer_size = (uint32_t)tmp;

    if (!InitializeSDN(device_id, inside_door_id, outside_door_id))
    {
        return 2;
    }

    message_buffer = malloc(message_buffer_size);
    if (message_buffer == NULL) {
        return 3;
    }

    while (true)
    {
        while(true) {
            int ret = ReadNextMessage(message_buffer, message_buffer_size);
            if (ret < 0) {
                return 4;
            }

            if (ret <= 0) {
                break;
            }

            SDNMsgHeader *msg_header = (SDNMsgHeader *)message_buffer;
            switch (msg_header->msg_type) {
                case SDN_MSG_TYPE_HEARTBEAT: {
                    if ((size_t)ret >= sizeof(SDNHeartBeatMessage)) {
                        SDNHeartBeatMessage *hb = (SDNHeartBeatMessage *)message_buffer;
                        uint32_t src_id = msg_header->device_id;
                        int idx = -1;
                        if (src_id == inside_door_id) idx = INNER_DOOR_IDX;
                        else if (src_id == outside_door_id) idx = OUTER_DOOR_IDX;
                        if (idx >= 0) {
                            door_status[idx].heartbeat = *hb;
                        }
                    } else {
                        sdn_log(SDN_WARN, "Received HEARTBEAT message with invalid length %d", ret);
                    }
                } break;

                case SDN_MSG_TYPE_SENSOR_PRESSURE: {
                    if ((size_t)ret >= sizeof(SDNPressureMessage)) {
                        SDNPressureMessage *pm = (SDNPressureMessage *)message_buffer;
                        uint32_t src_id = msg_header->device_id;
                        int idx = -1;
                        if (src_id == inside_door_id) idx = INNER_DOOR_IDX;
                        else if (src_id == outside_door_id) idx = OUTER_DOOR_IDX;
                        if (idx >= 0) {
                            int side_idx = -1;
                            if (pm->measurement_id == SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1) side_idx = 0;
                            else if (pm->measurement_id == SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2) side_idx = 1;
                            if (side_idx >= 0) {
                                door_status[idx].pressure[side_idx] = *pm;
                            }
                        }
                    } else {
                        sdn_log(SDN_WARN, "Received SENSOR_PRESSURE message with invalid length %d", ret);
                    }
                } break;

                case SDN_MSG_TYPE_CLEAR_FAULTS: {
                    if ((size_t)ret >= sizeof(SDNClearFaultsMessage)) {
                        SDNClearFaultsMessage *cf = (SDNClearFaultsMessage *)message_buffer;
                        fault_bits &= ~cf->fault_mask;
                    } else {
                        sdn_log(SDN_WARN, "Received CLEAR_FAULTS message with invalid length %d", ret);
                    }
                } break;

                case SDN_MSG_TYPE_DEBUG_WRITE_MEM: {
                    SDNDebugWriteMemMessage *cf = (SDNDebugWriteMemMessage *)message_buffer;
                    size_t payload_size = cf->msg_header.msg_length - sizeof(SDNDebugWriteMemMessage);
                    memcpy((uint8_t*)cf->address, cf->data, payload_size);
                    fault_bits &= FAULT_DEBUGGER;
                } break;

                default:
                    break;
            }
        }

        /* Watchdog: check for missed messages from doors and set fault bit */
        {
            sdn_timestamp_t now = GetCurrentTimestampMS();
            uint32_t door_fault = 0;
            for (int i = 0; i < 2; ++i) {
                if (now - door_status[i].heartbeat.msg_header.timestamp > DEVICE_WATCHDOG_TIMEOUT_MS) {
                    door_fault = FAULT_DOOR_BIT;
                }
                for (int j = 0; j < 2; ++j) {
                    if (now - door_status[i].pressure[j].msg_header.timestamp > DEVICE_WATCHDOG_TIMEOUT_MS) {
                        door_fault = FAULT_DOOR_BIT;
                    }
                }
            }
            fault_bits |= door_fault;
        }

        BroadcastHeartbeat(fault_bits);
        SleepMS(SLEEP_PERIOD_MS);
    }

    return 0;
}
