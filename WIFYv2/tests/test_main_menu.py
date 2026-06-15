from pathlib import Path

from attacks import wep, wpa
from core import device
from core.project import AccessPoint, Project
from menu import main_menu


def test_monitor_mode_option(tmp_path: Path, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(device, "set_monitor_mode", lambda iface: calls.append(("monitor", iface)))
    monkeypatch.setattr(device, "get_mode", lambda iface: "Monitor")

    inputs = iter(["1", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = Project("TEST", base_dir=tmp_path)
    main_menu.run_menu("wlan0", project)

    assert calls == [("monitor", "wlan0")]
    assert "Monitor Mode" in project.log_path.read_text()
    assert "wlan0 is now in Monitor mode" in project.log_path.read_text()


def test_managed_mode_option(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setattr(device, "set_managed_mode", lambda iface: calls.append(("managed", iface)))
    monkeypatch.setattr(device, "get_mode", lambda iface: "Managed")

    inputs = iter(["2", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = Project("TEST", base_dir=tmp_path)
    main_menu.run_menu("wlan0", project)

    assert calls == [("managed", "wlan0")]
    assert "wlan0 is now in Managed mode" in project.log_path.read_text()


def test_not_in_monitor_mode_error_is_reported_not_raised(tmp_path: Path, monkeypatch, capsys):
    def _raise(iface, project):
        raise main_menu.NotInMonitorModeError(f"Interface '{iface}' must be in monitor mode.")

    monkeypatch.setattr(main_menu, "_wpa_attack", _raise)

    inputs = iter(["7", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = Project("TEST", base_dir=tmp_path)
    main_menu.run_menu("wlan0", project)

    out = capsys.readouterr().out
    assert "must be in monitor mode" in out


def test_invalid_option(tmp_path: Path, monkeypatch, capsys):
    inputs = iter(["99", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = Project("TEST", base_dir=tmp_path)
    main_menu.run_menu("wlan0", project)

    out = capsys.readouterr().out
    assert "Invalid option" in out


def test_wpa_attack_unscanned_ap(tmp_path: Path, monkeypatch, capsys):
    bssid = "AA:BB:CC:11:22:33"
    inputs = iter(["7", bssid, "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = Project("TEST", base_dir=tmp_path)
    main_menu.run_menu("wlan0", project)

    out = capsys.readouterr().out
    assert "has not been scanned yet" in out


def test_wpa_attack_wordlist_not_found(tmp_path: Path, monkeypatch, capsys):
    bssid = "AA:BB:CC:11:22:33"
    inputs = iter(["7", bssid, "/no/such/wordlist.txt", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = Project("TEST", base_dir=tmp_path)
    project.upsert_ap(AccessPoint(bssid=bssid, essid="TestAP", channel="6"))
    main_menu.run_menu("wlan0", project)

    out = capsys.readouterr().out
    assert "Wordlist not found" in out


def test_wpa_attack_success(tmp_path: Path, monkeypatch, capsys):
    bssid = "AA:BB:CC:11:22:33"
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("password123\n")

    inputs = iter(["7", bssid, str(wordlist), "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    calls = []
    monkeypatch.setattr(
        wpa, "run_wpa_attack",
        lambda iface, project, ap, wl: calls.append((iface, ap.bssid, wl)) or wpa.CrackResult(success=True, key="password123"),
    )

    project = Project("TEST", base_dir=tmp_path)
    project.upsert_ap(AccessPoint(bssid=bssid, essid="TestAP", channel="6"))
    main_menu.run_menu("wlan0", project)

    assert calls == [("wlan0", bssid, str(wordlist))]
    out = capsys.readouterr().out
    assert "Key found" in out


def test_wep_attack_unscanned_ap(tmp_path: Path, monkeypatch, capsys):
    bssid = "AA:BB:CC:11:22:33"
    inputs = iter(["8", bssid, "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = Project("TEST", base_dir=tmp_path)
    main_menu.run_menu("wlan0", project)

    out = capsys.readouterr().out
    assert "has not been scanned yet" in out


def test_wep_attack_success(tmp_path: Path, monkeypatch, capsys):
    bssid = "AA:BB:CC:11:22:33"
    inputs = iter(["8", bssid, "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    calls = []
    monkeypatch.setattr(
        wep, "run_wep_attack",
        lambda iface, project, ap: calls.append((iface, ap.bssid)) or wep.CrackResult(success=True, key="AB:CD:EF:01:23"),
    )

    project = Project("TEST", base_dir=tmp_path)
    project.upsert_ap(AccessPoint(bssid=bssid, essid="TestAP", channel="6"))
    main_menu.run_menu("wlan0", project)

    assert calls == [("wlan0", bssid)]
    out = capsys.readouterr().out
    assert "Key found" in out
