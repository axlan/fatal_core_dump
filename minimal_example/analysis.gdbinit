add-symbol-file bin/libsdn_interface.so

break main.c:568
break sdn_interface.c:246
break sdn_interface.c:282
#break sdn_interface.c:393

set exec-wrapper env -i
r

print HandleSetSuitOccupant
print ControlDoor
print rx_message_buffer
print (void*)message_serialization_buffer
print message_handlers
print(sizeof(SDNHandler))
print *(sdn_msg_callback_t*)((char*)message_handlers + 12 * 0 + 4)
