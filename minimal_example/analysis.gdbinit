add-symbol-file bin/libsdn_interface.so

define xbt
  set $xbp = (void **)$arg0
  while 1
    x/2a $xbp
    set $xbp = (void **)$xbp[0]
  end
end

break main.c:609
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
