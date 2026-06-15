# This is WiFY
## Description
A semi-automated Wifi Pentesting Tool for Security Auditors. This tool creates logs and attack related files that makes the process of Report Writing Easy. This tool is developed using multiple other open-source projects. The author has only written the scripts to automate the pentesting process.
# Functionalities Added Till Now (Scripts)
- Device Managment
- Project Managment
- Logs keeping
- Scanning for Networks
- Scanning An Access Point
- De-Authentication Attack
- De-Association Attack
- Becon Flooding
- Authentication DOS Attack
- Michael Countermeasures Exploitation Attack
- EAPOL Start and Logoff Packet Injection

# v1.1 Changes
- Fixed Monitor Mode / Managed Mode being swapped in device management
- Fixed `install.sh` dependency list (was comma-separated, apt requires spaces)
- Fixed broken current-channel detection in device info
- Quoted variables throughout to handle spaces/special characters safely
- Replaced fragile `ps aux | grep xterm` PID lookup with direct PID tracking
- Added missing channel selection to Authentication DOS, Michael Countermeasures, and EAPOL attacks
- Added BSSID/channel/numeric input validation and dependency checks (`scripts/common.sh`)
- Added unified logging helper and cleanup traps so background captures are killed on exit/Ctrl-C
