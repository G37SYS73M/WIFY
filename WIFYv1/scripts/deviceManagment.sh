#!/bin/sh

if [ "$#" -lt 2 ]
then
	echo "[*] Usages: ./deviceManagment.sh {Interface_name} {1 for Monitor Mode OR 2 for Managed Mode} "
	exit 1
fi

if [ "$2" -eq 1 ]
then
	sudo airmon-ng check kill > /dev/null
	sudo ip link set "$1" down > /dev/null
	sudo iw dev "$1" set type monitor > /dev/null
	sudo ip link set "$1" up > /dev/null
	sudo iw "$1" info > /dev/null
	echo "\n\033[32m [*] $1 is now in Monitor Mode\033[0m"
fi

if [ "$2" -eq 2 ]
then
	sudo ip link set "$1" down > /dev/null
	sudo iw dev "$1" set type managed > /dev/null
	sudo ip link set "$1" up > /dev/null
	sudo service NetworkManager restart > /dev/null
	sudo iw "$1" info > /dev/null
	echo "\n\033[32m [*] $1 is now in Managed Mode\033[0m"
fi
