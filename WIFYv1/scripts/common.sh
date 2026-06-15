#!/bin/bash
# Shared helpers sourced by WIFY.sh, dosAttacks.sh and the individual attack scripts.

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
NC='\033[0m'

# log_header <project_dir> [label]
# Writes a timestamped separator into the project's command.logs
log_header() {
	local project_dir="$1"
	local label="$2"
	{
		echo "----------------------------------------------------------------------"
		echo "$(date +%d-%m-%y-%H_%M)${label:+ - $label}"
	} >> "$project_dir/command.logs"
}

# log_msg <project_dir> <message>
# Prints a message and appends it to the project's command.logs
log_msg() {
	local project_dir="$1"
	shift
	echo -e "$*"
	echo -e "$*" >> "$project_dir/command.logs"
}

# check_deps <cmd1> <cmd2> ...
# Verifies that the listed commands are available, prints what's missing.
check_deps() {
	local missing=()
	for cmd in "$@"; do
		command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
	done
	if [ "${#missing[@]}" -gt 0 ]; then
		echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
		echo -e "${YELLOW}[*] Run ./install.sh to install dependencies.${NC}"
		return 1
	fi
	return 0
}

# interface_exists <interface_name>
interface_exists() {
	iw dev 2>/dev/null | grep -qw "Interface $1"
}

# valid_mac <mac_address>
valid_mac() {
	[[ "$1" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

# valid_number <value>
valid_number() {
	[[ "$1" =~ ^[0-9]+$ ]]
}

# sanitize_name <name>
# Strips anything but letters, numbers, dashes and underscores.
sanitize_name() {
	echo "$1" | tr -cd 'A-Za-z0-9_-'
}
