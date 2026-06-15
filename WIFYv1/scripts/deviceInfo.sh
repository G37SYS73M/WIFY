#!/bin/bash

echo "[*] Available Wireless Interfaces:"
interfaces=$(iw dev | awk '/Interface/ {print $2}')

if [ -z "$interfaces" ]; then
	echo "    None found."
	exit 1
fi

for interface_name in $interfaces; do
	echo "  - $interface_name"
	mode=$(iwconfig "$interface_name" 2>/dev/null | grep -o 'Mode:[^ ]*' | cut -d ':' -f2)
	channel=$(iwlist "$interface_name" channel 2>/dev/null | grep "Current" | grep -oP '(?<=Channel )[0-9]+')
	echo "    Mode:    ${mode:-Unknown}"
	echo "    Channel: ${channel:-Unknown}"
done
