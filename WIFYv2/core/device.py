"""Device/interface management, replacing deviceManagment.sh, deviceInfo.sh,
selectChannel.sh and showChannels.sh."""

import re
import subprocess

_INTERFACE_RE = re.compile(r"Interface (\S+)")
_MODE_RE = re.compile(r"Mode:(\S+)")
_CHANNEL_RE = re.compile(r"Channel\s+(\d+)")


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def list_interfaces() -> list[str]:
    result = _run(["iw", "dev"])
    return _INTERFACE_RE.findall(result.stdout)


def get_mode(iface: str) -> str:
    """Returns the interface's current mode (e.g. "Managed"/"Monitor"), or "Unknown"."""
    result = _run(["iwconfig", iface])
    match = _MODE_RE.search(result.stdout)
    return match.group(1) if match else "Unknown"


def get_channel(iface: str) -> str:
    """Returns the interface's current channel number as a string, or "Unknown"."""
    result = _run(["iwlist", iface, "channel"])
    for line in result.stdout.splitlines():
        if "Current" in line:
            match = _CHANNEL_RE.search(line)
            if match:
                return match.group(1)
    return "Unknown"


def set_monitor_mode(iface: str) -> None:
    _run(["airmon-ng", "check", "kill"])
    _run(["ip", "link", "set", iface, "down"])
    _run(["iw", "dev", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])


def set_managed_mode(iface: str) -> None:
    _run(["ip", "link", "set", iface, "down"])
    _run(["iw", "dev", iface, "set", "type", "managed"])
    _run(["ip", "link", "set", iface, "up"])
    _run(["service", "NetworkManager", "restart"])


def set_channel(iface: str, channel: str) -> None:
    _run(["iw", "dev", iface, "set", "channel", str(channel)])


def print_device_info() -> None:
    """Lists wireless interfaces with their current mode/channel, replacing deviceInfo.sh."""
    print("[*] Available Wireless Interfaces:")
    interfaces = list_interfaces()

    if not interfaces:
        print("    None found.")
        return

    for iface in interfaces:
        print(f"  - {iface}")
        print(f"    Mode:    {get_mode(iface)}")
        print(f"    Channel: {get_channel(iface)}")
