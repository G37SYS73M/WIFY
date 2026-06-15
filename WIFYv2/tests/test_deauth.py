import pytest
from scapy.layers.dot11 import Dot11Deauth, Dot11Disas

from core import device
from packet import deauth

BSSID = "AA:BB:CC:11:22:33"
CLIENT = "DE:AD:BE:EF:00:01"


@pytest.fixture(autouse=True)
def monitor_mode(monkeypatch):
    monkeypatch.setattr(device, "get_mode", lambda iface: "Monitor")


def test_not_in_monitor_mode_raises(monkeypatch):
    monkeypatch.setattr(device, "get_mode", lambda iface: "Managed")
    with pytest.raises(deauth.NotInMonitorModeError):
        deauth.send_deauth("wlan0", BSSID, CLIENT)


def test_build_deauth_frames():
    frames = deauth._build_frames(BSSID, CLIENT, deauth._DEAUTH_SUBTYPE, Dot11Deauth, deauth.DEFAULT_REASON)
    assert len(frames) == 2

    to_client, to_ap = frames

    assert to_client.addr1 == CLIENT
    assert to_client.addr2 == BSSID
    assert to_client.addr3 == BSSID
    assert to_client.subtype == 12
    assert to_client.haslayer(Dot11Deauth)
    assert to_client[Dot11Deauth].reason == deauth.DEFAULT_REASON

    assert to_ap.addr1 == BSSID
    assert to_ap.addr2 == CLIENT
    assert to_ap.addr3 == BSSID


def test_build_disassoc_frames():
    frames = deauth._build_frames(BSSID, CLIENT, deauth._DISASSOC_SUBTYPE, Dot11Disas, deauth.DEFAULT_REASON)
    to_client, to_ap = frames

    assert to_client.subtype == 10
    assert to_client.haslayer(Dot11Disas)
    assert to_ap.haslayer(Dot11Disas)


def test_send_deauth_calls_sendp(monkeypatch):
    sent = []
    monkeypatch.setattr(deauth, "sendp", lambda pkt, iface, count, inter, verbose: sent.append((pkt, iface, count)))

    deauth.send_deauth("wlan0", BSSID, CLIENT, count=3)

    assert len(sent) == 2  # AP->client and client->AP
    for _, iface, count in sent:
        assert iface == "wlan0"
        assert count == 3


def test_send_disassoc_broadcast_default(monkeypatch):
    sent = []
    monkeypatch.setattr(deauth, "sendp", lambda pkt, iface, count, inter, verbose: sent.append(pkt))

    deauth.send_disassoc("wlan0", BSSID)

    assert len(sent) == 2
    assert sent[0].addr1 == deauth.BROADCAST
