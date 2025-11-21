#include <stdio.h>
#include "sdn_interface.h"

static const uint64_t YEAR_IN_MS = 365 * 24 * 60 * 60 * 1000ull;

static sdn_timestamp_t dummy_timestamp = YEAR_IN_MS * 1.989438645;

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

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
int ReadNextMessage(void *msg_buffer, size_t buffer_size_bytes)
{
    return 0;
}

// DUMMY IMPLEMENTATIONS FOR GAME DATA GENERATION
bool ExecuteCmd(const SDNMsgHeader *header, uint32_t target_device_id)
{
    (void)header;
    (void)target_device_id;
    return true;
}

int GetResponse(void *msg_buffer, size_t buffer_size_bytes, uint32_t target_device_id, SDNMsgType request_type)
{
    (void)msg_buffer;
    (void)buffer_size_bytes;
    (void)target_device_id;
    (void)request_type;
    return true;
}
