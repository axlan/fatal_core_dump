#include "config_loader.h"
#include "log.h"
#include "sdn_interface.h"

static const size_t MAX_DEVICES = 1024;
static const size_t DEVICE_WATCHDOG_TIMEOUT_MS = 100;

int main()
{
    int device_id = 0;
    bool ret = LoadConfigInt(&device_id, "device_id");
    if (!ret)
    {
        return 1;
    }

    while (true)
    {
        struct SDNDeviceInfo devices[MAX_DEVICES];
        size_t num_devices = DiscoverLocalDevices(devices, MAX_DEVICES);

        LOG_DEBUG("Discovered %zu devices:\n", num_devices);
        for (size_t i = 0; i < num_devices; i++)
        {
            LOG_DEBUG("  Device %zu: Type=%u, ID=0x%X\n", i,
                      devices[i].device_type, devices[i].device_id);
        }

        BroadcastHeartbeat(device_id, SDN_HEALTH_GOOD);
    }

    return 0;
}
