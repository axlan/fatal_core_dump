set pagination off

break ProcessMessageData

set exec-wrapper env -i
r

print (void*)HandleSetSuitOccupant
print (void*)ControlDoor
print (void*)state->message_serialization_buffer
print (void*)handlers
q
