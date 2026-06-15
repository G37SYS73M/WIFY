"""Validation/dependency helpers, replacing scripts/common.sh's validators."""

import re
import shutil
import subprocess

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_NUMBER_RE = re.compile(r"^[0-9]+$")
_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_-]")


def valid_mac(value: str) -> bool:
    return bool(_MAC_RE.match(value))


def valid_number(value: str) -> bool:
    return bool(_NUMBER_RE.match(value))


def sanitize_name(name: str) -> str:
    """Strips anything but letters, numbers, dashes and underscores."""
    return _SANITIZE_RE.sub("", name)


def check_deps(*cmds: str) -> list[str]:
    """Returns the subset of cmds that are not found on PATH."""
    return [cmd for cmd in cmds if shutil.which(cmd) is None]


def interface_exists(iface: str) -> bool:
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        return False
    return f"Interface {iface}" in result.stdout
