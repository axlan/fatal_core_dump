#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "sdn_interface.h"

typedef struct AirlockState AirlockState;
struct AirlockState
{
};

typedef void (*sdn_msg_callback_t)(const void *message_data, size_t msg_len, AirlockState *state);

// device_id in RDI, door_device_id in RSI, is_open in RDX
static bool ControlDoor(uint32_t device_id, uint32_t door_device_id, bool is_open)
{
    printf("ControlDoor: %d\n", is_open);
    SDNSetOpenMessage door_cmd = {
        .msg_header = {
            .device_id = device_id,
            .msg_length = sizeof(SDNSetOpenMessage),
            .msg_type = SDN_MSG_TYPE_SET_OPEN,
            .timestamp = GetCurrentTimestampMS()},
        .open = (is_open) ? 1 : 0};
    return ExecuteCmd(&door_cmd.msg_header, door_device_id);
}

// message_data in RDI, msg_len in RSI, context in RDX
static void HandleSetSuitOccupant(const void *message_data, size_t msg_len, AirlockState* state)
{
    (void)msg_len;
    (void)state;
    SDNSetSuitOccupantMessage *send_ptr = (SDNSetSuitOccupantMessage *)message_data;
    printf("HandleSetSuitOccupant user_id: 0x%X\n", send_ptr->user_id);
}

#define BUFFER_SIZE 128

int main()
{
    uint8_t stack_buffer[BUFFER_SIZE * 2];

    uint8_t *buffer = NULL;
    sdn_msg_callback_t *cb = NULL;

    buffer = malloc(BUFFER_SIZE);
    memset(buffer, 0xBB, BUFFER_SIZE);

    cb = malloc(sizeof(sdn_msg_callback_t));
    *cb = HandleSetSuitOccupant;

    printf("stack_buffer   : %p\n", stack_buffer);
    printf("cb   : %p\n", cb);
    printf("ControlDoor   : %p\n", ControlDoor);
    printf("HandleSetSuitOccupant   : %p\n", HandleSetSuitOccupant);
    printf("offsetof  user_id: %zu\n", offsetof(SDNSetSuitOccupantMessage, user_id));

    FILE *input_file = fopen("bin/input5", "rb");
    if (!input_file)
    {
        exit(1);
    }
    size_t bytes_read = fread(buffer, 1, sizeof(stack_buffer), input_file);
    fclose(input_file);
    memcpy(stack_buffer, buffer, bytes_read);

    while (true)
    {

        ssize_t len = read(0, buffer, BUFFER_SIZE);
        if (len == 0)
        {
            return 0;
        }
        const SDNSetSuitOccupantMessage DUMMY_MSG = {
            .user_id = buffer[0],
        };
        memcpy(buffer, &DUMMY_MSG, sizeof(DUMMY_MSG));

        (*cb)(buffer, sizeof(DUMMY_MSG), NULL);
    }
}

// gcc -fcf-protection=none -z execstack -fno-stack-protector -O0 -g -no-pie -o bin/min_poc minimal_example/min_poc.c
// *[master][~/src/fatal_core_dump]$ objdump -d bin/min_poc | grep foo
// 000000000040116c <foo>:
// *[master][~/src/fatal_core_dump]$ objdump -d bin/min_poc | grep bar
// 0000000000401156 <bar>:

// pwndbg -x minimal_example/min_poc.gdbinit bin/min_poc

// pwndbg> print (void*)stack_buffer
// $3 = (void *) 0x7fffffffec60

// pwndbg> print check_ptr
// $4 = (uint32_t *) 0x4052a0

// minimal_example/vuln_test5.py

// env -i setarch $(uname -m) -R /home/jdiamond/src/fatal_core_dump/bin/min_poc < bin/input5
