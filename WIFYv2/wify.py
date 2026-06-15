#!/usr/bin/env python3
"""WIFY v2 entrypoint, replacing WIFY.sh."""

import os
import sys

from core import colors, device, validation
from core.project import Project
from menu.main_menu import run_menu

REQUIRED_TOOLS = [
    "iw", "ip", "iwconfig", "iwlist",
    "airodump-ng", "aireplay-ng", "aircrack-ng", "packetforge-ng", "mdk4",
    "hcxdumptool", "hcxpcapngtool", "hashcat",
]


def main() -> int:
    if os.geteuid() != 0:
        colors.err("This tool must be run as root (try: sudo python3 wify.py <interface>).")
        return 1

    if len(sys.argv) != 2:
        print(f"[*] Usage: sudo python3 {sys.argv[0]} <interface_name>")
        device.print_device_info()
        return 1

    iface = sys.argv[1]

    missing = validation.check_deps(*REQUIRED_TOOLS)
    if missing:
        colors.err(f"Missing required tools: {', '.join(missing)}")
        colors.warn("Run ./install.sh to install dependencies.")
        return 1

    if not validation.interface_exists(iface):
        colors.err(f"Interface '{iface}' not found.")
        device.print_device_info()
        return 1

    colors.warn(f"Using device => {iface}")

    name = validation.sanitize_name(input("Enter the Project's Name: ").strip())
    if not name:
        colors.err("Invalid project name.")
        return 1

    project = Project(name)
    run_menu(iface, project)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
