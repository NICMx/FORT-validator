#!/bin/sh

STR="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

echo "$STR"
sleep 1 # 3999
echo "$STR"
echo "$STR" 1>&2
sleep 1 # 2998
echo "$STR"
sleep 1 # 1997
echo "$STR" 1>&2
sleep 1 # The spawner should kill us around the end of this.
echo "$STR"
sleep 1
echo "$STR"
sleep 1 # Otherwise, check will kill the spawner around here.
echo "$STR"
sleep 1
echo "$STR"
sleep 1
echo "$STR"
