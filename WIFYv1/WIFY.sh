#!/bin/bash

source ./scripts/common.sh

if [ "$#" -lt 1 ]
then
	echo "[*] Usages: ./WIFY.sh {Interface_name}"
	./scripts/deviceInfo.sh
	exit 1
fi

if [ "$#" -eq 1 ]; then

echo "!!!!!!!!!!!WELCOME!!!!!!!!!!!"

interface_name=$1

check_deps iw ip iwconfig iwlist airodump-ng aireplay-ng mdk4 wifite xterm awk || exit 1

if ! interface_exists "$interface_name"; then
	echo -e "${RED}[!] Interface '$interface_name' not found.${NC}"
	./scripts/deviceInfo.sh
	exit 1
fi

# Almost everything below needs root (iw, airodump-ng, aireplay-ng, mdk4, wifite).
# Cache sudo credentials now so background xterm windows don't get stuck on a
# hidden password prompt.
echo -e "${YELLOW}[*] Most operations require root - sudo may prompt for your password.${NC}"
sudo -v || exit 1

echo -e "\n${YELLOW} [*] Using Device => $interface_name ${NC}\n"

project_name=''
read -p "Enter the Project's Name: " project_name
project_name=$(sanitize_name "$project_name")
if [ -z "$project_name" ]; then
	echo -e "${RED}[!] Invalid project name.${NC}"
	exit 1
fi
mkdir -p "projects/$project_name"
touch "projects/$project_name/command.logs"

OPTIONS='\n
OPTIONS:\n
1 => Put Device in Monitor Mode \n
2 => Put Device in Managed Mode \n
3 => Scan For Access Points (APs) \n
4 => Scan An Access Point (AP) \n
5 => Show Scanned Access Points (APs) \n
6 => All DOS Attacks \n
9 => Auto WPA Attacks Using Wifite \n
10 => Auto WEP Attacks Using Wifite \n
'

echo -e $OPTIONS


keyword="exit"
user_input=""

read -p "Enter an option (type 'exit' to stop): " user_input

while [ "$user_input" != "$keyword" ]
do

    case "$user_input" in

    #Putting in monitor mode.
    1)
    	log_header "projects/$project_name" "Monitor Mode"
    	./scripts/deviceManagment.sh "$interface_name" 1 | tee -a "projects/$project_name/command.logs"
    	;;

    #putting in managed mode
    2)
    	log_header "projects/$project_name" "Managed Mode"
    	./scripts/deviceManagment.sh "$interface_name" 2 | tee -a "projects/$project_name/command.logs"
    	;;

    #Scanning for all networks
    3)
    	mins=5
    	user_input_mins=''
    	read -p "Enter time to sniff (Minutes)(Default: 5mins): " user_input_mins
    	if valid_number "$user_input_mins"; then
    		mins=$user_input_mins
		fi
    	log_header "projects/$project_name" "Scan For Networks (${mins}min)"
    	echo "./scripts/scanForNetworks.sh $interface_name $mins" >> "projects/$project_name/command.logs"
    	date +%d-%m-%y-%H_%M >> "projects/$project_name/scanForNetworks.txt"
    	echo "Command Output" >> "projects/$project_name/command.logs"
    	./scripts/scanForNetworks.sh "$interface_name" "$mins" | tee -a "projects/$project_name/command.logs" | tee -a "projects/$project_name/scanForNetworks.txt"
    	;;

    #Scanning an AP
    4)
    	mins=5
    	bssid=''
    	channel=''
    	user_input_mins=''
    	cat "projects/$project_name/scanForNetworks.txt" 2>/dev/null
    	read -p "Enter BSSID: " bssid
    	if ! valid_mac "$bssid"; then
    		echo -e "${RED}[!] Invalid BSSID format.${NC}"
    		user_input=''
    		echo -e $OPTIONS
    		read -p "Enter an option (type 'exit' to stop): " user_input
    		continue
    	fi
    	read -p "Enter Channel Number: " channel
    	if ! valid_number "$channel"; then
    		echo -e "${RED}[!] Invalid channel number.${NC}"
    		user_input=''
    		echo -e $OPTIONS
    		read -p "Enter an option (type 'exit' to stop): " user_input
    		continue
    	fi
    	read -p "Enter time to scan AP (Minutes)(Default: 5mins): " user_input_mins
    	if valid_number "$user_input_mins"; then
    		mins=$user_input_mins
		fi
    	log_header "projects/$project_name" "Scan AP $bssid"
    	echo "./scripts/scanNetwork.sh $interface_name $bssid $channel $mins" >> "projects/$project_name/command.logs"
    	echo "Command Output" >> "projects/$project_name/command.logs"
		./scripts/scanNetwork.sh "$interface_name" "$bssid" "$channel" "$mins" | tee -a "projects/$project_name/command.logs" | tee "projects/$project_name/scan-$bssid.txt"
		awk '/ESSID of the AP:/ {getline; essid=$0} /BSSID of the AP:/ {getline; bssid=$0} /Channel Number of the AP:/ {getline; channel=$0} END {print "\"" essid "\",\"" bssid "\",\"" channel "\""}' "projects/$project_name/scan-$bssid.txt" >> "projects/$project_name/ScannedAPs.csv"
    	;;

    #Show scanned APs
    5)
		echo "[*] ScannedAPs:"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	;;

    # All DOS ATTACKS
   	6)
		./dosAttacks.sh "$interface_name" "$project_name"
    	;;

	#Auto WPA attacks Using Wifite
    9)
    	echo "[*] ScannedAPs:"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	essid=''
    	read -p "Enter target AP's ESSID: " essid
    	log_header "projects/$project_name" "WPA Attack (Wifite) - $essid"
    	./scripts/wpaAttacks.sh "$interface_name" "$essid" | tee -a "projects/$project_name/command.logs" | tee "projects/$project_name/Attack-WPA-Wifite-$essid.txt"
    	;;

	#Auto WEP attacks Using Wifite
    10)
    	echo "[*] ScannedAPs:"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	essid=''
    	read -p "Enter target AP's ESSID: " essid
    	log_header "projects/$project_name" "WEP Attack (Wifite) - $essid"
    	./scripts/wepAttacks.sh "$interface_name" "$essid" | tee -a "projects/$project_name/command.logs" | tee "projects/$project_name/Attack-WEP-Wifite-$essid.txt"
    	;;

    *)
    	echo -e "\n${RED}Invalid Options!!!${NC}"
    	;;
    esac

    echo -e $OPTIONS
    read -p "Enter an option (type 'exit' to stop): " user_input

done

fi #EOF DO NOT EDIT
