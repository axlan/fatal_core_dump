#! /usr/bin/env bash
set -e

sudo rm -rf bin/

docker build -t core_dump_build .

docker run --rm --privileged -v "$PWD":/fatal_core_dump core_dump_build sh ./scripts/generate_hack.sh

docker run --rm -it --privileged -v "$PWD":/fatal_core_dump core_dump_build ./scripts/trigger_crash.sh

sudo chown -R $USER:$USER bin
