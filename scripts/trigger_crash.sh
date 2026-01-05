#! /usr/bin/env bash

rm -f bin/core.dump*
rm -f bin/crash_output.txt

# No idea why log cuts off when redirecting to a file, so using screen to capture all output
screen -L -Logfile bin/crash_output.txt -m env -i setarch $(uname -m) -R "$PWD/bin/airlock_ctrl"

python3 scripts/convert_timestamps.py

for file in bin/core.dump.*; do
    if [ -f "$file" ]; then
        mv "$file" "bin/core.dump"
    fi
done
