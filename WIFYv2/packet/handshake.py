"""EAPOL 4-way handshake detection from pcap captures."""

from pathlib import Path

from scapy.layers.dot11 import Dot11
from scapy.layers.eap import EAPOL_KEY
from scapy.utils import PcapReader


def _message_number(eapol_key: EAPOL_KEY) -> int | None:
    """Classifies an EAPOL-Key frame as 4-way handshake message 1-4, or None."""
    if eapol_key.key_ack and not eapol_key.has_key_mic:
        return 1
    if not eapol_key.key_ack and eapol_key.has_key_mic and not eapol_key.secure:
        return 2
    if eapol_key.key_ack and eapol_key.has_key_mic and eapol_key.secure:
        return 3
    if not eapol_key.key_ack and eapol_key.has_key_mic and eapol_key.secure and eapol_key.key_data_length == 0:
        return 4
    return None


def eapol_messages_seen(pcap_path: str | Path, bssid: str, client_mac: str | None = None) -> set[int]:
    """Returns the set of 4-way handshake message numbers (1-4) seen for `bssid`."""
    bssid = bssid.lower()
    client_mac = client_mac.lower() if client_mac else None
    seen: set[int] = set()

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if not pkt.haslayer(Dot11) or not pkt.haslayer(EAPOL_KEY):
                continue
            dot11 = pkt[Dot11]
            addrs = {a.lower() for a in (dot11.addr1, dot11.addr2, dot11.addr3) if a}
            if bssid not in addrs:
                continue
            if client_mac is not None and client_mac not in addrs:
                continue
            msg = _message_number(pkt[EAPOL_KEY])
            if msg is not None:
                seen.add(msg)

    return seen


def has_complete_handshake(pcap_path: str | Path, bssid: str, client_mac: str | None = None) -> bool:
    """Returns True if a crackable handshake (EAPOL messages 1 and 2) was captured for `bssid`."""
    seen = eapol_messages_seen(pcap_path, bssid, client_mac)
    return {1, 2}.issubset(seen)
