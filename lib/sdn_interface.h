/**
 * @file sdn_interface.h
 * @brief Station Device Network (SDN) - Inter-device messaging framework for space station systems
 *
 * This header defines the communication protocol for devices within the station network.
 * The protocol supports sensor data transmission, control commands, health monitoring,
 * and device coordination for critical life support operations.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Begin section of declaring packed structs for serialization.
#pragma pack(push, 1)

/** Timestamp type in milliseconds since system epoch */
typedef uint64_t sdn_timestamp_t;

/**
 * @brief Callback function type for message handlers
 * @param message_data Pointer to the received message data. Always starts with @ref SDNMsgHeader.
 * @param msg_len Length of the message in bytes
 * @param context User-provided context pointer
 */
typedef void (*sdn_msg_callback_t)(const void *message_data, size_t msg_len, void *context);

/** Device health status indicating normal operation */
#define SDN_HEALTH_GOOD 0

/**
 * @brief Message type identifiers for SDN protocol
 *
 * Defines all supported message types for inter-device communication
 * including sensor telemetry, control commands, and diagnostic messages.
 */
typedef enum SDNMsgType SDNMsgType;
enum SDNMsgType
{
    SDN_MSG_TYPE_INVALID = 0,                ///< Invalid/uninitialized message type
    SDN_MSG_TYPE_HEARTBEAT = 1,              ///< Periodic health status message
    SDN_MSG_TYPE_SENSOR_PRESSURE = 2,        ///< Pressure sensor reading
    SDN_MSG_TYPE_SET_PRESSURE_ZONE = 3,      ///< Command to set pressure equalization zone
    SDN_MSG_TYPE_SET_OPEN = 4,               ///< Generic open/close command
    SDN_MSG_TYPE_SET_AIRLOCK_OPEN = 5,       ///< Airlock door control (alias for SET_OPEN)
    SDN_MSG_TYPE_SENSOR_OCCUPANCY = 6,       ///< Occupancy sensor data with user information
    SDN_MSG_TYPE_DEBUG_WRITE_CONFIG_INT = 7, ///< Debug command to update configuration values
    SDN_MSG_TYPE_CLEAR_FAULTS = 8,           ///< Command to clear fault conditions
    SDN_MSG_TYPE_LOG = 9,                    ///< Log message with severity level
    SDN_MSG_TYPE_SET_SUIT_OCCUPANT = 10,     ///< Configure suit for specific occupant
};

/**
 * @brief Message handler registration structure
 *
 * Associates a message type with a callback function for processing
 * incoming messages of that type.
 */
typedef struct SDNHandler SDNHandler;
struct SDNHandler
{
    SDNMsgType type;             ///< Message type this handler processes
    sdn_msg_callback_t callback; ///< Function to call when message is received
};

/**
 * @brief Response status codes for SDN operations
 */
typedef enum SDNResponseStatus SDNResponseStatus;
enum SDNResponseStatus
{
    SDN_RESPONSE_GOOD = 0,             ///< Operation completed successfully
    SDN_RESPONSE_FAILED = 1,           ///< Operation failed
    SDN_RESPONSE_BUFFER_TOO_SMALL = 2, ///< Provided buffer insufficient for response
    SDN_RESPONSE_INVALID_MSG_LEN = 3,  ///< Message had invalid length
    SDN_RESPONSE_CMD_ERROR_1 = 4,      ///< Command specific error
    SDN_RESPONSE_CMD_ERROR_2 = 5,      ///< Command specific error
    SDN_RESPONSE_CMD_ERROR_3 = 6,      ///< Command specific error
};

/**
 * @brief Device type identifiers for station components
 *
 * Categorizes devices by their functional role in the station network.
 */
typedef enum SDNDeviceType SDNDeviceType;
enum SDNDeviceType
{
    SDN_DEVICE_TYPE_INVALID = 0,      ///< Invalid/uninitialized device type
    SDN_DEVICE_TYPE_SUIT = 1,         ///< Pressure suit with life support
    SDN_DEVICE_TYPE_PANEL = 2,        ///< Control panel interface
    SDN_DEVICE_TYPE_REMOTE = 3,       ///< Remote terminal or monitoring station
    SDN_DEVICE_TYPE_DOOR = 4,         ///< Standard door with pressure sensors
    SDN_DEVICE_TYPE_AIRLOCK_CTRL = 5, ///< Airlock controller with dual-door coordination
};

/**
 * @brief Common header for all SDN messages
 *
 * Every message in the protocol begins with this header to provide
 * type identification, routing, and timing information.
 */
typedef struct SDNMsgHeader SDNMsgHeader;
struct SDNMsgHeader
{
    uint16_t msg_type;         ///< Message type (@ref SDNMsgType)
    uint16_t msg_length;       ///< Total message size in bytes including this header
    uint32_t device_id;        ///< Unique identifier of the sending device
    sdn_timestamp_t timestamp; ///< Message creation time in milliseconds
};

// All SDN Measurement structs start with the msg_header field and a measurement_id field.
// The measurement_id identifies the source of that particular measurement for that device.
// For example a device may have multiple temperature sensors, and the measurement_id
// disambiguates them.

/**
 * @brief Pressure sensor measurement message
 */
typedef struct SDNPressureMessage SDNPressureMessage;
struct SDNPressureMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint32_t measurement_id; ///< Identifies which sensor produced this reading
    float pressure_pa;       ///< Pressure reading in Pascals
};

/**
 * @brief Pressure suit seal status
 */
typedef enum SDNSuitStatus SDNSuitStatus;
enum SDNSuitStatus
{
    SDN_SUIT_STATUS_INVALID = 0,  ///< Invalid/unknown status
    SDN_SUIT_STATUS_SEALED = 1,   ///< Suit is sealed and pressurized
    SDN_SUIT_STATUS_UNSEALED = 2, ///< Suit is open/unpressurized
};

/**
 * @brief Information about a single occupant
 *
 * Used within occupancy messages to describe individuals present
 * in a space and their suit status.
 */
typedef struct SDNOccupancyInfo SDNOccupancyInfo;
struct SDNOccupancyInfo
{
    uint32_t user_id;    ///< Unique identifier for the person
    uint8_t suit_status; ///< Current suit status (see SDNSuitStatus)
};

/**
 * @brief Occupancy sensor message with variable-length occupant list
 *
 * Reports who is present in a space (airlock, room, etc.) and their
 * current suit status. Uses flexible array member for variable payload.
 */
typedef struct SDNOccupancyMessage SDNOccupancyMessage;
struct SDNOccupancyMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint32_t measurement_id; ///< Identifies the sensor/location
    // variable length payload follows; use msg_header.msg_length to determine size
    SDNOccupancyInfo occupants[]; ///< Array of occupant information (flexible array)
};

/**
 * @brief Configure a pressure suit for a specific occupant
 *
 * Unlocks a suit and sets preferences for the assigned user.
 * Includes variable-length user preference data.
 */
typedef struct SDNSetSuitOccupantMessage SDNSetSuitOccupantMessage;
struct SDNSetSuitOccupantMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint32_t user_id;        ///< User to configure suit for
    // variable length payload follows; use msg_header.msg_length to determine size
    uint8_t user_preferences[]; ///< Custom preference data (flexible array)
};

/**
 * @brief Periodic heartbeat message for health monitoring
 *
 * Sent regularly by devices to indicate operational status and report
 * any fault conditions.
 */
typedef struct SDNHeartBeatMessage SDNHeartBeatMessage;
struct SDNHeartBeatMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint32_t health;         ///< Health status (0 = good, non-zero = fault bits)
};

/**
 * @brief Command to open pressure valve to specified zone
 *
 * Controls pressure equalization by connecting the device to a
 * designated pressure zone.
 */
typedef struct SDNSetPressureZoneMessage SDNSetPressureZoneMessage;
struct SDNSetPressureZoneMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint8_t zone_id;         ///< Target pressure zone identifier
};

/**
 * @brief Generic open/close command for doors and hatches
 */
typedef struct SDNSetOpenMessage SDNSetOpenMessage;
struct SDNSetOpenMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint8_t open;            ///< 0 = closed, non-zero = open
};

/**
 * @brief Airlock door position states
 *
 * Airlocks maintain safety by allowing only one door open at a time.
 */
typedef enum SDNAirlockOpen SDNAirlockOpen;
enum SDNAirlockOpen
{
    SDN_AIRLOCK_CLOSED = 0,        ///< Both doors closed
    SDN_AIRLOCK_INTERIOR_OPEN = 1, ///< Interior (station-side) door open
    SDN_AIRLOCK_EXTERIOR_OPEN = 2, ///< Exterior (space-side) door open
};

/**
 * @brief Command to control airlock door state
 *
 * Controls which airlock door (if any) is open. Safety interlocks
 * prevent both doors from opening simultaneously.
 *
 * Pre-Conditions:
 * Command is rejected if any fault bits are active (returns CMD_ERROR_1)
 * Message length must be valid (returns INVALID_MSG_LEN if too small)
 *
 * Command Logic:
 * 1. SDN_AIRLOCK_CLOSED
 *   Closes both interior and exterior doors
 *   Transitions state based on which door was previously open:
 *
 *   From INTERIOR_OPEN → CLOSED_PRESSURIZED
 *   From EXTERIOR_OPEN → CLOSED_DEPRESSURIZED
 *
 *
 *
 * 2. SDN_AIRLOCK_INTERIOR_OPEN (Station-side)
 *   From CLOSED_PRESSURIZED: Directly opens interior door
 *   From EXTERIOR_OPEN/CLOSED_DEPRESSURIZED/DEPRESSURIZING:
 *
 *   Closes exterior door
 *   Initiates pressurization sequence
 *   Enters PRESSURIZING state (door opens when pressurization completes)
 *
 *   Already INTERIOR_OPEN or PRESSURIZING: No action (idempotent)
 *
 * 3. SDN_AIRLOCK_EXTERIOR_OPEN (Space-side)
 *   Critical Safety Check: Queries occupancy sensor to verify all occupants have sealed suits
 *
 *   Rejects command if any occupant is unsealed (returns CMD_ERROR_2)
 *   Rejects if too many occupants present
 *
 *
 *   From CLOSED_DEPRESSURIZED: Directly opens exterior door
 *   From INTERIOR_OPEN/CLOSED_PRESSURIZED/PRESSURIZING:
 *
 *   Closes interior door
 *   Initiates depressurization sequence
 *   Enters DEPRESSURIZING state (door opens when depressurization completes)
 *
 *   Already EXTERIOR_OPEN or DEPRESSURIZING: No action
 *
 * Key Safety Features:
 *
 *   Never allows both doors open simultaneously
 *   Requires pressure equalization before door transitions
 *   Validates suit status before exposing occupants to vacuum
 *   Fatal error (exit) on door/pressure control failures
 *
 */
typedef struct SDNSetAirlockOpenMessage SDNSetAirlockOpenMessage;
struct SDNSetAirlockOpenMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint8_t open;            ///< Door state (see SDNAirlockOpen)
};

/**
 * @brief Debug command to update integer configuration values
 *
 * Allows modification of device configuration parameters
 * for testing and calibration purposes.
 *
 * By default configuration is only reloaded by resetting device.
 */
typedef struct SDNDebugWriteConfigInt SDNDebugWriteConfigInt;
struct SDNDebugWriteConfigInt
{
    SDNMsgHeader msg_header; ///< Standard message header
    char key[32];            ///< Configuration key name (null-terminated)
    int32_t value;           ///< New value to set
};

/**
 * @brief Command to clear fault conditions
 *
 * Attempts to reset specified fault states after corrective action
 * has been taken.
 */
typedef struct SDNClearFaultsMessage SDNClearFaultsMessage;
struct SDNClearFaultsMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint32_t fault_mask;     ///< Bitmask of faults to clear (application-defined)
};

/**
 * @brief Log message with severity level
 *
 * Transmits diagnostic and operational log messages across the network.
 * Includes variable-length text content.
 */
typedef struct SDNLogMessage SDNLogMessage;
struct SDNLogMessage
{
    SDNMsgHeader msg_header; ///< Standard message header
    uint8_t severity;        ///< 0=CRITICAL, 1=ERROR, 2=WARNING, higher=less severe
    // variable length payload follows; use msg_header.msg_length to determine size
    char message_str[]; ///< Log message text (flexible array, null-terminated)
};

/** Measurement ID for door pressure sensor on side 1 */
#define SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_1 1

/** Measurement ID for door pressure sensor on side 2 */
#define SDN_MEASUREMENT_ID_DOOR_PRESSURE_SIDE_2 2

// End section of declaring packed structs for serialization.
#pragma pack(pop)

/**
 * @brief Register a device with the SDN network
 *
 * Must be called during device initialization to join the network
 * and enable message transmission/reception.
 *
 * @param device_id Unique identifier for this device
 * @param device_type Category of device (see SDNDeviceType)
 * @return true if registration successful, false otherwise
 */
bool RegisterDevice(uint32_t device_id, SDNDeviceType device_type);

/**
 * @brief Subscribe to receive messages of a specific type from a specific
 *        device.
 *
 * @param device_id The device to subscribe to.
 * @param message_type Type of message to receive
 * @return true if subscription successful, false otherwise
 */
bool SubscribeToMessage(uint32_t device_id, SDNMsgType message_type);

/**
 * @brief Broadcast a heartbeat message to the network
 *
 * Sends health status to all listening devices. Must be called
 * periodically to avoid timing out.
 *
 * @param fault_bits Bitmask of current fault conditions (0 = healthy)
 * @return true if broadcast successful, false otherwise
 */
bool BroadcastHeartbeat(uint32_t fault_bits);

/**
 * @brief Get current system timestamp
 *
 * @return Current time in milliseconds since system epoch
 */
sdn_timestamp_t GetCurrentTimestampMS(void);

/**
 * @brief Sleep for specified duration
 *
 * @param ms Duration to sleep in milliseconds
 */
void SleepMS(unsigned ms);

/**
 * @brief Read the next available message from the network
 *
 * Blocking call that retrieves the next message addressed to this device.
 * Returns when a message is available or an error occurs.
 *
 * @param msg_buffer Buffer to store the received message
 * @param buffer_size_bytes Size of the provided buffer
 * @return Number of bytes read on success, negative value on error
 */
int ReadNextMessage(void *msg_buffer, size_t buffer_size_bytes);

/**
 * @brief Execute a command on a target device
 *
 * Sends a command message to the specified device and waits for
 * acknowledgment of execution.
 *
 * @param header Pointer to the command message (with header)
 * @param target_device_id Device to execute the command
 * @return true if command accepted, false if rejected or failed
 */
bool ExecuteCmd(const SDNMsgHeader *header, uint32_t target_device_id);

/**
 * @brief Request a device send a message type
 *
 * After sending a command, this function retrieves the response
 * from the target device.
 *
 * @param msg_buffer Buffer to store the response message
 * @param buffer_size_bytes Size of the provided buffer
 * @param target_device_id Device that should respond
 * @param request_type Type of message to request
 * @return Status code indicating success or reason for failure
 */
SDNResponseStatus RequestMessage(void *msg_buffer, size_t buffer_size_bytes, uint32_t target_device_id, SDNMsgType request_type);

/**
 * @brief Send response code after processing a received command
 *
 * Called by command handlers to acknowledge command processing.
 *
 * @param response_code Status code indicating success or reason for failure
 */
void SendCmdResponse(SDNResponseStatus response_code);
