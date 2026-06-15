#!/usr/bin/env python3
"""One-off generator for tests/fixtures/handshake_*.pcap fixtures.

Run with: python3 tests/fixtures/generate_handshake_pcaps.py
"""

from pathlib import Path

from scapy.layers.dot11 import Dot11, RadioTap
from scapy.layers.eap import EAPOL, EAPOL_KEY
from scapy.layers.l2 import LLC, SNAP
from scapy.utils import wrpcap

FIXTURES_DIR = Path(__file__).parent

BSSID = "AA:BB:CC:11:22:33"
CLIENT = "DE:AD:BE:EF:00:01"
OTHER_BSSID = "11:22:33:44:55:66"

TO_AP = 0x01
FROM_AP = 0x02


def _eapol_key_frame(fcfield, addr1, addr2, addr3, **key_fields):
    return (
        RadioTap()
        / Dot11(type=2, FCfield=fcfield, addr1=addr1, addr2=addr2, addr3=addr3)
        / LLC()
        / SNAP(OUI=0, code=0x888E)
        / EAPOL(version=1, type=3)
        / EAPOL_KEY(**key_fields)
    )


def _m1():
    return _eapol_key_frame(FROM_AP, CLIENT, BSSID, BSSID, key_ack=1, has_key_mic=0, key_nonce=b"A" * 32)


def _m2():
    return _eapol_key_frame(TO_AP, BSSID, CLIENT, BSSID, key_ack=0, has_key_mic=1, secure=0, key_nonce=b"B" * 32, key_mic=b"M" * 16)


def _m3():
    return _eapol_key_frame(FROM_AP, CLIENT, BSSID, BSSID, key_ack=1, has_key_mic=1, secure=1, key_mic=b"M" * 16)


def _m4():
    return _eapol_key_frame(TO_AP, BSSID, CLIENT, BSSID, key_ack=0, has_key_mic=1, secure=1, key_data_length=0, key_mic=b"M" * 16)


def _unrelated_m1():
    return _eapol_key_frame(FROM_AP, CLIENT, OTHER_BSSID, OTHER_BSSID, key_ack=1, has_key_mic=0, key_nonce=b"C" * 32)


def main() -> None:
    wrpcap(str(FIXTURES_DIR / "handshake_complete.pcap"), [_unrelated_m1(), _m1(), _m2(), _m3(), _m4()])
    wrpcap(str(FIXTURES_DIR / "handshake_partial.pcap"), [_m1()])


if __name__ == "__main__":
    main()
