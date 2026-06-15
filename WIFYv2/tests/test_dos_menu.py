from pathlib import Path

from attacks import dos
from core.project import AccessPoint, Project
from menu import dos_menu


BSSID = "AA:BB:CC:11:22:33"


def _project(tmp_path: Path) -> Project:
    return Project("TEST", base_dir=tmp_path)


def _silence_scan_table(monkeypatch):
    monkeypatch.setattr(dos_menu.scan, "print_scanned_aps", lambda project: None)


def test_prompt_target_returns_none_on_invalid_bssid(tmp_path, monkeypatch):
    _silence_scan_table(monkeypatch)
    monkeypatch.setattr(dos_menu.prompts, "prompt_mac", lambda *a, **k: None)

    project = _project(tmp_path)
    assert dos_menu._prompt_target(project) is None


def test_prompt_target_returns_none_on_invalid_channel(tmp_path, monkeypatch):
    _silence_scan_table(monkeypatch)
    monkeypatch.setattr(dos_menu.prompts, "prompt_mac", lambda *a, **k: BSSID)
    monkeypatch.setattr(dos_menu.prompts, "prompt_channel", lambda *a, **k: None)

    project = _project(tmp_path)
    assert dos_menu._prompt_target(project) is None


def test_prompt_target_returns_known_clients(tmp_path, monkeypatch):
    _silence_scan_table(monkeypatch)
    monkeypatch.setattr(dos_menu.prompts, "prompt_mac", lambda *a, **k: BSSID)
    monkeypatch.setattr(dos_menu.prompts, "prompt_channel", lambda *a, **k: "6")

    project = _project(tmp_path)
    project.upsert_ap(AccessPoint(bssid=BSSID, clients=["DE:AD:00:00:00:01"]))

    assert dos_menu._prompt_target(project) == (BSSID, "6", ["DE:AD:00:00:00:01"])


def test_prompt_target_unknown_bssid_has_no_clients(tmp_path, monkeypatch):
    _silence_scan_table(monkeypatch)
    monkeypatch.setattr(dos_menu.prompts, "prompt_mac", lambda *a, **k: BSSID)
    monkeypatch.setattr(dos_menu.prompts, "prompt_channel", lambda *a, **k: "6")

    project = _project(tmp_path)
    assert dos_menu._prompt_target(project) == (BSSID, "6", [])


def test_deauth_dispatches_to_attacks_dos(tmp_path, monkeypatch):
    monkeypatch.setattr(dos_menu, "_prompt_target", lambda project: (BSSID, "6", ["DE:AD:00:00:00:01"]))
    monkeypatch.setattr(dos_menu.prompts, "prompt_number", lambda *a, **k: 3)

    calls = []
    monkeypatch.setattr(dos, "deauth_attack", lambda *args: calls.append(args))

    project = _project(tmp_path)
    dos_menu._deauth("wlan0", project)

    assert calls == [("wlan0", project, BSSID, "6", ["DE:AD:00:00:00:01"], 3, 3, 3)]
    assert f"Deauth Attack on {BSSID}" in project.log_path.read_text()


def test_deauth_aborts_on_missing_target(tmp_path, monkeypatch):
    monkeypatch.setattr(dos_menu, "_prompt_target", lambda project: None)

    calls = []
    monkeypatch.setattr(dos, "deauth_attack", lambda *args: calls.append(args))

    project = _project(tmp_path)
    dos_menu._deauth("wlan0", project)

    assert calls == []


def test_disassoc_dispatches_to_attacks_dos(tmp_path, monkeypatch):
    monkeypatch.setattr(dos_menu, "_prompt_target", lambda project: (BSSID, "6", []))
    monkeypatch.setattr(dos_menu.prompts, "prompt_number", lambda *a, **k: 5)

    calls = []
    monkeypatch.setattr(dos, "disassoc_attack", lambda *args: calls.append(args))

    project = _project(tmp_path)
    dos_menu._disassoc("wlan0", project)

    assert calls == [("wlan0", project, BSSID, "6", [], 5, 5, 5)]


def test_authentication_dos_dispatches_to_attacks_dos(tmp_path, monkeypatch):
    monkeypatch.setattr(dos_menu, "_prompt_target", lambda project: (BSSID, "6", []))
    monkeypatch.setattr(dos_menu.prompts, "prompt_number", lambda *a, **k: 5)

    calls = []
    monkeypatch.setattr(dos, "authentication_dos", lambda *args: calls.append(args))

    project = _project(tmp_path)
    dos_menu._authentication_dos("wlan0", project)

    assert calls == [("wlan0", project, BSSID, 5, 5, 5)]


def test_michael_countermeasures_dispatches_to_attacks_dos(tmp_path, monkeypatch):
    monkeypatch.setattr(dos_menu, "_prompt_target", lambda project: (BSSID, "6", []))
    monkeypatch.setattr(dos_menu.prompts, "prompt_number", lambda *a, **k: 5)

    calls = []
    monkeypatch.setattr(dos, "michael_countermeasures", lambda *args: calls.append(args))

    project = _project(tmp_path)
    dos_menu._michael_countermeasures("wlan0", project)

    assert calls == [("wlan0", project, BSSID, 5, 5, 5)]


def test_eapol_injection_dispatches_to_attacks_dos(tmp_path, monkeypatch):
    monkeypatch.setattr(dos_menu, "_prompt_target", lambda project: (BSSID, "6", []))
    monkeypatch.setattr(dos_menu.prompts, "prompt_number", lambda *a, **k: 5)

    calls = []
    monkeypatch.setattr(dos, "eapol_injection", lambda *args: calls.append(args))

    project = _project(tmp_path)
    dos_menu._eapol_injection("wlan0", project)

    assert calls == [("wlan0", project, BSSID, 5, 5, 5)]


def test_beacon_flood_dispatches_to_attacks_dos(tmp_path, monkeypatch):
    monkeypatch.setattr(dos_menu.prompts, "prompt_number", lambda *a, **k: 10)

    calls = []
    monkeypatch.setattr(dos, "beacon_flood", lambda *args: calls.append(args))

    project = _project(tmp_path)
    dos_menu._beacon_flood("wlan0", project)

    assert calls == [("wlan0", project, 10)]
    assert "Beacon Flooding" in project.log_path.read_text()


def test_run_dos_menu_reports_not_in_monitor_mode_error(tmp_path, monkeypatch, capsys):
    def _raise(iface, project):
        raise dos_menu.NotInMonitorModeError(f"Interface '{iface}' must be in monitor mode.")

    monkeypatch.setattr(dos_menu, "_deauth", _raise)

    inputs = iter(["1", "00"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    project = _project(tmp_path)
    dos_menu.run_dos_menu("wlan0", project)

    out = capsys.readouterr().out
    assert "must be in monitor mode" in out


def test_run_dos_menu_dispatches_and_exits(tmp_path, monkeypatch, capsys):
    inputs = iter(["1", "99", "00"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    calls = []
    monkeypatch.setattr(dos_menu, "_deauth", lambda iface, project: calls.append("deauth"))

    project = _project(tmp_path)
    dos_menu.run_dos_menu("wlan0", project)

    assert calls == ["deauth"]
    assert "Invalid Options!!!" in capsys.readouterr().out
