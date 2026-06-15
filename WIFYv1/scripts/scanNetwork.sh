#!/bin/bash

if [ "$#" -lt 4 ]
then
	echo "[*] Usages: ./scanNetwork.sh {Interface_name} {BSSID} {Channel_Number} {time_to_listen}"
	exit 1
fi

if [ "$#" -eq 4 ]
then
	foldername=$(date +%d-%m-%y)
	filename=$(date +%H-%M_"$2")
	mkdir -p "/tmp/$foldername"
	sudo iw "$1" set channel "$3" > /dev/null
	xterm -e sudo timeout "$4"m airodump-ng "$1" --bssid "$2" --channel "$3" -w "/tmp/$foldername/$filename"
	csv="/tmp/$foldername/$filename-01.csv"
	if [ ! -f "$csv" ]; then
		echo -e "\033[31m[!] No capture file was produced. The scan may have failed (check the airodump-ng window for errors).\033[0m"
		exit 1
	fi
	echo "[*] ESSID of the AP:"
	grep "$2" "$csv" | head -n 1 | awk -F',' '{print $14}'
	echo "[*] BSSID of the AP:"
	grep "$2" "$csv" | head -n 1 | awk -F',' '{print $1}'
	echo "[*] Channel Number of the AP:"
	grep "$2" "$csv" | head -n 1 | awk -F',' '{print $4}'
	echo "[*] Encryption used by the AP:"
	grep "$2" "$csv" | head -n 1 | awk -F',' '{print $6}'
	echo "[*] Cipher used by the AP:"
	grep "$2" "$csv" | head -n 1 | awk -F',' '{print $7}'
	echo "[*] Authentication used by the AP:"
	grep "$2" "$csv" | head -n 1 | awk -F',' '{print $8}'
	echo "[*] Number of Stations Connected to the AP:"
	grep "$2" "$csv" | awk -F',' '{print $1}' | grep -v "$2" | wc -l
	echo "[*] MAC Addresses of Stations Connected to AP:"
	grep "$2" "$csv" | awk -F',' '{print $1}' | grep -v "$2"
fi

