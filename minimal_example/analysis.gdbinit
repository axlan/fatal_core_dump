add-symbol-file bin/libsdn_interface.so

break main.c:577
break SendAttackCmd
break SendFailureCmd
#break sdn_interface.c:453

set exec-wrapper env -i
r

print HandleSetSuitOccupant
print ControlDoor
print rx_message_buffer
print (void*)state->message_serialization_buffer
print message_handlers
print(sizeof(SDNHandler))
print *(sdn_msg_callback_t*)((char*)message_handlers + 12 * 0 + 4)
