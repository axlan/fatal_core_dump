#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Station Device Network interface header */

#pragma pack(push, 1)

typedef uint64_t sdn_timestamp_t;

typedef void (*sdn_msg_callback_t)(const void *message_data, size_t msg_len);

#define SDN_CMD_SUCCESS 0
#define SDN_HEALTH_GOOD 0

typedef enum SDNMsgType SDNMsgType;
enum SDNMsgType
{
    SDN_MSG_TYPE_INVALID = 0,
    SDN_MSG_TYPE_HEARTBEAT = 1,
    SDN_MSG_TYPE_SENSOR_PRESSURE = 2,
    SDN_MSG_TYPE_SET_PRESSURE_ZONE = 3,
    SDN_MSG_TYPE_SET_OPEN = 4,
    SDN_MSG_TYPE_SET_AIRLOCK_OPEN = 4,
    SDN_MSG_TYPE_SENSOR_OCCUPANCY = 5,
    SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT = 6,
    SDN_MSG_TYPE_CLEAR_FAULTS = 7,
    SDN_MSG_TYPE_LOG = 8,
    SDN_MSG_TYPE_SET_SUIT_OCCUPANT = 10,
};

typedef struct SDNHandler SDNHandler;
struct SDNHandler
{
    SDNMsgType type;
    sdn_msg_callback_t callback;
};

typedef enum SDNResponseStatus SDNResponseStatus;
enum SDNResponseStatus
{
    SDN_RESPONSE_GOOD = 0,
    SDN_RESPONSE_FAILED = 1,
    SDN_RESPONSE_BUFFER_TOO_SMALL = 2,
};


typedef enum SDNDeviceType SDNDeviceType;
enum SDNDeviceType
{
    SDN_DEVICE_TYPE_INVALID = 0,
    SDN_DEVICE_TYPE_SUIT = 1,
    SDN_DEVICE_TYPE_PANEL = 2,
    SDN_DEVICE_TYPE_REMOTE = 3,
    SDN_DEVICE_TYPE_DOOR = 4,
    SDN_DEVICE_TYPE_AIRLOCK_CTRL = 5,
};

typedef struct SDNMsgHeader SDNMsgHeader;
struct SDNMsgHeader
{
    uint16_t msg_type;
    uint16_t msg_length; // Full message size including this SDNMsgHeader.
    uint32_t device_id;
    sdn_timestamp_t timestamp;
};

// All SDN Measurement structs start with the msg_header field and a measurement_id field.

typedef struct SDNPressureMessage SDNPressureMessage;
struct SDNPressureMessage
{
    SDNMsgHeader msg_header;
    uint32_t measurement_id;
    float pressure_pa;
};

typedef enum SDNSuitStatus SDNSuitStatus;
enum SDNSuitStatus
{
    SDN_SUIT_STATUS_INVALID = 0,
    SDN_SUIT_STATUS_SEALED = 1,
    SDN_SUIT_STATUS_UNSEALED = 2,
};

typedef struct SDNOccupancyInfo SDNOccupancyInfo;
struct SDNOccupancyInfo
{
    uint32_t user_id;
    uint8_t suit_status;
};

typedef struct SDNOccupancyMessage SDNOccupancyMessage;
struct SDNOccupancyMessage
{
    SDNMsgHeader msg_header;
    uint32_t measurement_id;
    // variable length payload follows; use msg_header.msg_length to determine size
    SDNOccupancyInfo occupants[];
};

typedef struct SDNSetSuitOccupantMessage SDNSetSuitOccupantMessage;
struct SDNSetSuitOccupantMessage
{
    SDNMsgHeader msg_header;
    uint32_t user_id;
    uint16_t user_preferences_len;
    // variable length payload follows; use user_preferences_len to determine size
    uint8_t user_preferences[];
};

typedef struct SDNHeartBeatMessage SDNHeartBeatMessage;
struct SDNHeartBeatMessage
{
    SDNMsgHeader msg_header;
    uint32_t health;
};

// Control messages
typedef struct SDNSetPressureZoneMessage SDNSetPressureZoneMessage;
struct SDNSetPressureZoneMessage
{
    SDNMsgHeader msg_header;
    uint8_t zone_id; // Open pressure valve to specified zone.
};

typedef struct SDNSetOpenMessage SDNSetOpenMessage;
struct SDNSetOpenMessage
{
    SDNMsgHeader msg_header;
    uint8_t open; // 0 = closed, non-zero = open
};

typedef enum SDNAirlockOpen SDNAirlockOpen;
enum SDNAirlockOpen
{
    SDN_AIRLOCK_CLOSED = 0,
    SDN_AIRLOCK_INTERIOR_OPEN = 1,
    SDN_AIRLOCK_EXTERIOR_OPEN = 2,
};

typedef struct SDNSetAirlockOpenMessage SDNSetAirlockOpenMessage;
struct SDNSetAirlockOpenMessage
{
    SDNMsgHeader msg_header;
    uint8_t open; // See SDNAirlockOpen
};

typedef struct SDNDebugWriteConfigInt SDNDebugWriteConfigInt;
struct SDNDebugWriteConfigInt
{
    SDNMsgHeader msg_header;
    char key[32]; // key to update
    int32_t value;
};

typedef struct SDNClearFaultsMessage SDNClearFaultsMessage;
struct SDNClearFaultsMessage
{
    SDNMsgHeader msg_header;
    uint32_t fault_mask; // bitmask of faults to clear, application-defined
};

typedef struct SDNLogMessage SDNLogMessage;
struct SDNLogMessage
{
    SDNMsgHeader msg_header;
    uint8_t severity; // 0 - CRITICAL, 1 - ERROR, 2 - WARNING. Higher values are less severe.
    // variable length payload follows; use msg_header.msg_length to determine size
    char message_str[];
};

#define SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1 1
#define SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2 2

bool RegisterDevice(uint32_t device_id, SDNDeviceType device_type);

bool SubscribeToMessage(uint32_t device_id, SDNMsgType message_type);

bool BroadcastHeartbeat(uint32_t fault_bits);

sdn_timestamp_t GetCurrentTimestampMS(void);

void SleepMS(unsigned ms);

int ReadNextMessage(void *msg_buffer, size_t buffer_size_bytes);

bool ExecuteCmd(const SDNMsgHeader *header, uint32_t target_device_id);

SDNResponseStatus GetResponse(void *msg_buffer, size_t buffer_size_bytes, uint32_t target_device_id, SDNMsgType request_type);

int ProcessMessageData(SDNHandler* handlers, size_t num_handlers, void *msg_buffer, size_t buffer_size_bytes);

void SendCmdResponse(uint32_t response_code);

#pragma pack(pop)
