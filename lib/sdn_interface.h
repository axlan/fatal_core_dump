#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Station Device Network interface header */

#pragma pack(push, 1)


typedef uint64_t measurement_timestamp_t;

enum SDNMsgType {
    SDN_MSG_TYPE_INVALID = 0,
    SDN_MSG_TYPE_HEARTBEAT = 1,
    SDN_MSG_TYPE_MEASUREMENT = 2,
};

enum SDNDeviceType {
    SDN_DEVICE_TYPE_INVALID = 0,
    SDN_DEVICE_TYPE_SUIT = 1,
    SDN_DEVICE_TYPE_DOOR = 2,
};

struct SDNMsgHeader {
    uint16_t msg_type;
    uint16_t msg_length;
    uint32_t device_id;
};

struct SDNDeviceInfo {
    uint16_t device_type;
    uint32_t device_id;
};

enum SDNMeasurementType {
    SDN_MEASUREMENT_TYPE_INVALID = 0,
    SDN_MEASUREMENT_TYPE_PRESSURE = 1,
};

struct SDNMeasurementHeader {
    uint16_t measurement_type;
    uint16_t measurement_id;
    measurement_timestamp_t timestamp_ms;
};

enum SDNDeviceHealth {
    SDN_HEALTH_INVALID = 0,
    SDN_HEALTH_GOOD = 1,
    SDN_HEALTH_FAULT = 2,
};

// All SDN Measurement structs start with the measurement_type field and a measurement_id field.

const uint16_t SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1 = 1;
const uint16_t SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2 = 2;

struct SDNPressureData {
    float pressure_pa;
};

struct SDNPressureMeasurement {
    struct SDNMeasurementHeader measurement_header;
    struct SDNPressureData data;
};

struct SDNPressureMessage {
    struct SDNMsgHeader msg_header;
    struct SDNMeasurementHeader measurement_header;
    struct SDNPressureData data;
};

struct SDNHeartBeatMessage {
    struct SDNMsgHeader msg_header;
    uint8_t health;
};

size_t DiscoverLocalDevices(struct SDNDeviceInfo *out_devices, size_t max_devices);

bool BroadcastHeartbeat(uint32_t device_id, enum SDNDeviceHealth health);

uint16_t DecodeMeasurementType(const uint8_t *msg_data, size_t msg_len);

bool DecodePressureMeasurement(const uint8_t *msg_data, size_t msg_len, struct SDNPressureMeasurement *out_measurement);

bool BroadcastHeartbeat(uint32_t device_id, enum SDNDeviceHealth health);


#pragma pack(pop)

