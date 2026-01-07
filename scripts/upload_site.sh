#! /usr/bin/env bash
set -e

aws s3 sync --profile robopenguin --delete site/ s3://www.robopenguins.com/fatal_core_dump/
