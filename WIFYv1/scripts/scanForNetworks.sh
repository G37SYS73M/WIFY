#!/bin/bash

if [ "$#" -lt 2 ]
then
	echo "[*] Usages: ./scanForNetworks.sh {Interface_name} {time_to_listen}"
	exit 1
fi

if [ "$#" -eq 2 ]
then
	foldername=$(date +%d-%m-%y)
	filename=$(date +%H_%M)
	mkdir -p "/tmp/$foldername"
	xterm -e sudo timeout "$2"m airodump-ng "$1" -w "/tmp/$foldername/$filename"
	echo -e "\n\033[32m[*] SCAN RESULTS:\033[0m"

	csv="/tmp/$foldername/$filename-01.csv"
	if [ ! -f "$csv" ]; then
		echo -e "\033[31m[!] No capture file was produced. The scan may have failed (check the airodump-ng window for errors).\033[0m"
		exit 1
	fi

	echo 'BSSID                     PWR     CH     Privacy         Cipher              ESSID'
	awk -F',' '{print $1 "\t" $9 "\t" $4 "\t" $6 "\t\t" $7 "\t\t" $14}' "$csv" | tail --lines=+3 | grep -B 99999 "Station MAC" | grep -v "Station MAC"
fi



