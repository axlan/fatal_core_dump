set pagination off

break ProcessMessageData

set exec-wrapper env -i
r

print HandleSetSuitOccupant
print ControlDoor
print (void*)state->message_serialization_buffer
print handlers
q
