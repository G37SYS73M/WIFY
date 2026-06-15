from pathlib import Path

from packet import handshake

FIXTURES = Path(__file__).parent / "fixtures"
BSSID = "AA:BB:CC:11:22:33"
CLIENT = "DE:AD:BE:EF:00:01"
OTHER_BSSID = "11:22:33:44:55:66"


def test_eapol_messages_seen_complete():
    seen = handshake.eapol_messages_seen(FIXTURES / "handshake_complete.pcap", BSSID)
    assert seen == {1, 2, 3, 4}


def test_eapol_messages_seen_filters_by_bssid():
    seen = handshake.eapol_messages_seen(FIXTURES / "handshake_complete.pcap", OTHER_BSSID)
    assert seen == {1}


def test_eapol_messages_seen_filters_by_client():
    seen = handshake.eapol_messages_seen(FIXTURES / "handshake_complete.pcap", BSSID, client_mac=CLIENT)
    assert seen == {1, 2, 3, 4}

    seen_wrong_client = handshake.eapol_messages_seen(
        FIXTURES / "handshake_complete.pcap", BSSID, client_mac="00:00:00:00:00:99"
    )
    assert seen_wrong_client == set()


def test_eapol_messages_seen_partial():
    seen = handshake.eapol_messages_seen(FIXTURES / "handshake_partial.pcap", BSSID)
    assert seen == {1}


def test_has_complete_handshake_true():
    assert handshake.has_complete_handshake(FIXTURES / "handshake_complete.pcap", BSSID) is True


def test_has_complete_handshake_false_when_partial():
    assert handshake.has_complete_handshake(FIXTURES / "handshake_partial.pcap", BSSID) is False


def test_has_complete_handshake_false_for_unknown_bssid():
    assert handshake.has_complete_handshake(FIXTURES / "handshake_complete.pcap", "00:00:00:00:00:00") is False
