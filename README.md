dot -Tpng doc/airlock_state.dot -o doc/airlock_state.png

-exec p (enum SDNDeviceType)devices[0].device_type

tasks.json:
```json
{
    "tasks": [
        {
            "type": "shell",
            "label": "Debug Build",
            "command": "make clean && make debug",
            "problemMatcher": [
                "$gcc"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            },
        }
    ],
    "version": "2.0.0"
}
```

launch.json:
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "(gdb) Launch",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/bin/airlock_ctrl",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${fileDirname}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "preLaunchTask": "Debug Build",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                },
                {
                    "description": "Set Disassembly Flavor to Intel",
                    "text": "-gdb-set disassembly-flavor intel",
                    "ignoreFailures": true
                }
            ]
        }

    ]
}
```

`make && ./bin/airlock_ctrl | grep -v DEBUG`

`pwndbg -x minimal_example/analysis.gdbinit bin/airlock_ctrl`


Sequence of events:
1. Maintenance puts controller into debug mode.
2. Possibly additional maintenance?
3. ??? Updates the in memory max buffer size to be big enough to hold code for payload making it inconsistent with the actual buffer size. ???. This causes the data after the loaded max buffer size to smash the stack.
   1. This could be done as code bug where the value can be loaded without reallocating buffer
   2. Bug where buffer is reallocated but there's a mistake
   3. Could be done through GDB modifying value (this might be hard to leave clue for)
4. N users use door normally.
5. Malicious payload is loaded by unwitting user
6. When the user X tries to checkout the spacesuit, it instead runs the payload causing the room to vent and


