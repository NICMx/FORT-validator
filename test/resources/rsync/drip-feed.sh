#!/bin/sh

STR="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "

echo "$STR"
sleep 1
echo "$STR"
echo "$STR" 1>&2
sleep 1
echo "$STR"
sleep 1
echo "$STR" 1>&2
