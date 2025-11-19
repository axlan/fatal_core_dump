#include <stdio.h>
#include "sdn_interface.h"

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
static const uint16_t SDN_DEVICE_ID_SUIT = 0xa953;
static const uint16_t SDN_DEVICE_ID_DOOR_INNER = 0x5e12;
static const uint16_t SDN_DEVICE_ID_DOOR_OUTER = 0x5e13;
size_t DiscoverLocalDevices(struct SDNDeviceInfo *out_devices, size_t max_devices) {
    if (out_devices == NULL || max_devices == 0) {
        return 0;
    }

    size_t devices_found = 0;

    if (devices_found < max_devices) {
        out_devices[devices_found].device_type = SDN_DEVICE_TYPE_DOOR;
        out_devices[devices_found].device_id = SDN_DEVICE_ID_DOOR_INNER;
        devices_found++;
    }

    if (devices_found < max_devices) {
        out_devices[devices_found].device_type = SDN_DEVICE_TYPE_DOOR;
        out_devices[devices_found].device_id = SDN_DEVICE_ID_DOOR_OUTER;
        devices_found++;
    }

    if (devices_found < max_devices) {
        out_devices[devices_found].device_type = SDN_DEVICE_TYPE_SUIT;
        out_devices[devices_found].device_id = SDN_DEVICE_ID_SUIT;
        devices_found++;
    }

    return devices_found;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool BroadcastHeartbeat(uint32_t device_id, enum SDNDeviceHealth health) {
    (void) device_id;
    (void) health;
    return true;
}


uint16_t DecodeMeasurementType(const uint8_t *msg_data, size_t msg_len) {
    if (msg_data == NULL || msg_len < sizeof(struct SDNMeasurementHeader)) {
        return SDN_MEASUREMENT_TYPE_INVALID;
    }

    const struct SDNMeasurementHeader *header = (const struct SDNMeasurementHeader *)msg_data;
    return header->measurement_type;
}

bool DecodePressureMeasurement(const uint8_t *msg_data, size_t msg_len, struct SDNPressureMeasurement *out_measurement) {
    if (msg_data == NULL || out_measurement == NULL ||
        msg_len < sizeof(struct SDNPressureMeasurement)) {
        return false;
    }

    const struct SDNMeasurementHeader *header = (const struct SDNMeasurementHeader *)msg_data;
    if (header->measurement_type != SDN_MEASUREMENT_TYPE_PRESSURE) {
        return false;
    }

    const struct SDNPressureMeasurement *pressure_measurement =
        (const struct SDNPressureMeasurement *)msg_data;

    // Copy the measurement data to the output structure
    *out_measurement = *pressure_measurement;

    return true;
}
