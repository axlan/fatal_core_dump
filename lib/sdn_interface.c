#include <stdio.h>
#include "sdn_interface.h"

static const uint64_t YEAR_IN_MS = 365 * 24 * 60 * 60 * 1000ull;

static sdn_timestamp_t dummy_timestamp = YEAR_IN_MS * 1.989438645;

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool RegisterDevice(uint32_t device_id,SDNDeviceType device_type) {
    (void) device_id;
    (void) device_type;

    return true;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool BroadcastHeartbeat(uint32_t fault_bits) {
    (void) fault_bits;
    return true;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
sdn_timestamp_t GetCurrentTimestampMS(void) {
    return dummy_timestamp;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
void SleepMS(sdn_timestamp_t ms) {
    dummy_timestamp += ms;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool SubscribeToMessage(uint32_t device_id,SDNMsgType message_type) {
    (void) device_id;
    (void) message_type;
    return true;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
int ReadNextMessage(void *msg_buffer, size_t buffer_size_bytes) {
    return 0;
}
