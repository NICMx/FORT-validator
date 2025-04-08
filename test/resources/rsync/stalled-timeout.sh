#!/bin/sh

STR="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

echo "$STR"
# The spawner has to kill us after 4 seconds.
# (This is what we're testing.)
# If it doesn't, check will fail the unit test during the 6th second.
sleep 20
echo "$STR"
