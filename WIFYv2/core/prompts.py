"""Shared input-prompt helpers used by the menu modules."""

from core import colors, validation


def prompt_mac(message: str = "Enter BSSID: ") -> str | None:
    """Returns a validated MAC address, or None if invalid."""
    value = input(message).strip()
    if not validation.valid_mac(value):
        colors.err("Invalid BSSID format.")
        return None
    return value


def prompt_channel(message: str = "Enter Channel Number: ") -> str | None:
    """Returns a validated channel number (as a string), or None if invalid."""
    value = input(message).strip()
    if not validation.valid_number(value):
        colors.err("Invalid channel number.")
        return None
    return value


def prompt_number(message: str, default: int) -> int:
    """Returns the entered number, or `default` if blank/invalid."""
    value = input(message).strip()
    if validation.valid_number(value):
        return int(value)
    return default
