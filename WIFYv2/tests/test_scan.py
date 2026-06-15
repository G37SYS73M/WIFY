from pathlib import Path

import pytest

from core import scan
from core.project import AccessPoint, Project

FIXTURE = Path(__file__).parent / "fixtures" / "airodump_sample.csv"


def test_parse_airodump_csv():
    aps = scan.parse_airodump_csv(FIXTURE)
    by_bssid = {ap.bssid: ap for ap in aps}

    assert set(by_bssid) == {
        "72:91:E3:BA:DE:76",
        "30:B6:2D:93:68:F0",
        "10:10:81:E7:15:DA",
    }

    hidden = by_bssid["72:91:E3:BA:DE:76"]
    assert hidden.essid == ""
    assert hidden.channel == "48"
    assert hidden.privacy == "WPA2"
    assert hidden.cipher == "CCMP"
    assert hidden.clients == []

    jio = by_bssid["30:B6:2D:93:68:F0"]
    assert jio.essid == "JioPrivateNet"
    assert jio.channel == "40"
    assert jio.power == "-76"

    swapnil = by_bssid["10:10:81:E7:15:DA"]
    assert swapnil.essid == "Swapnil_5g"
    assert swapnil.cipher == "CCMP TKIP"
    assert swapnil.auth == "PSK"
    assert sorted(swapnil.clients) == ["DE:AD:BE:EF:00:01", "DE:AD:BE:EF:00:02"]


def test_parse_airodump_csv_missing_file(tmp_path):
    missing = tmp_path / "does-not-exist-01.csv"
    with pytest.raises(FileNotFoundError):
        scan.parse_airodump_csv(missing)


def test_scan_networks_no_capture_file(tmp_path, monkeypatch):
    monkeypatch.setattr(scan, "run_timed", lambda args, minutes: None)

    project = Project("TEST", base_dir=tmp_path)
    aps = scan.scan_networks("wlan0", 1, project)

    assert aps == []


def test_scan_ap_records_result(tmp_path, monkeypatch):
    monkeypatch.setattr(scan.device, "set_channel", lambda iface, channel: None)

    def fake_run_timed(args, minutes):
        # The -w prefix is the last arg; write a fixture-derived CSV there.
        prefix = args[-1]
        out_csv = Path(f"{prefix}-01.csv")
        out_csv.write_text(FIXTURE.read_text())
        return None

    monkeypatch.setattr(scan, "run_timed", fake_run_timed)

    project = Project("TEST", base_dir=tmp_path)
    ap = scan.scan_ap("wlan0", "10:10:81:E7:15:DA", "1", 1, project)

    assert ap is not None
    assert ap.essid == "Swapnil_5g"
    assert sorted(ap.clients) == ["DE:AD:BE:EF:00:01", "DE:AD:BE:EF:00:02"]

    loaded = project.load_aps()
    assert "10:10:81:E7:15:DA" in loaded


def test_print_networks_table(capsys):
    aps = scan.parse_airodump_csv(FIXTURE)
    scan.print_networks_table(aps)
    out = capsys.readouterr().out
    assert "JioPrivateNet" in out
    assert "Swapnil_5g" in out


def test_print_ap_details(capsys):
    ap = AccessPoint(
        bssid="10:10:81:E7:15:DA",
        essid="Swapnil_5g",
        channel="1",
        privacy="WPA2",
        cipher="CCMP TKIP",
        auth="PSK",
        power="-48",
        clients=["DE:AD:BE:EF:00:01"],
    )
    scan.print_ap_details(ap)
    out = capsys.readouterr().out
    assert "Swapnil_5g" in out
    assert "DE:AD:BE:EF:00:01" in out
    assert "Number of Stations Connected to the AP: 1" in out


def test_print_scanned_aps_empty(tmp_path, capsys):
    project = Project("TEST", base_dir=tmp_path)
    scan.print_scanned_aps(project)
    out = capsys.readouterr().out
    assert "No APs scanned yet" in out
