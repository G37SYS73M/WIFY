from pathlib import Path

from attacks import dos
from core.project import Project


def _project(tmp_path: Path) -> Project:
    return Project("TEST", base_dir=tmp_path)


def test_deauth_attack_targets_each_client(tmp_path, monkeypatch):
    monkeypatch.setattr(dos, "time", __import__("time"))
    monkeypatch.setattr(dos.time, "sleep", lambda s: None)
    monkeypatch.setattr(dos.device, "set_channel", lambda iface, channel: None)

    calls = []
    monkeypatch.setattr(dos.deauth, "send_deauth", lambda iface, bssid, client, count: calls.append((bssid, client, count)))

    project = _project(tmp_path)
    dos.deauth_attack("wlan0", project, "AA:BB:CC:11:22:33", "6", ["DE:AD:00:00:00:01", "DE:AD:00:00:00:02"], packets=3, iterations=2, delay=0)

    assert len(calls) == 4  # 2 clients x 2 iterations
    assert all(c[2] == 3 for c in calls)
    assert all(c[0] == "AA:BB:CC:11:22:33" for c in calls)


def test_deauth_attack_broadcast_when_no_clients(tmp_path, monkeypatch):
    monkeypatch.setattr(dos.time, "sleep", lambda s: None)
    monkeypatch.setattr(dos.device, "set_channel", lambda iface, channel: None)

    calls = []
    monkeypatch.setattr(dos.deauth, "send_deauth", lambda iface, bssid, client, count: calls.append(client))

    project = _project(tmp_path)
    dos.deauth_attack("wlan0", project, "AA:BB:CC:11:22:33", "6", [], iterations=1, delay=0)

    assert calls == [dos.deauth.BROADCAST]


def test_disassoc_attack_targets_each_client(tmp_path, monkeypatch):
    monkeypatch.setattr(dos.time, "sleep", lambda s: None)
    monkeypatch.setattr(dos.device, "set_channel", lambda iface, channel: None)

    calls = []
    monkeypatch.setattr(dos.deauth, "send_disassoc", lambda iface, bssid, client, count: calls.append(client))

    project = _project(tmp_path)
    dos.disassoc_attack("wlan0", project, "AA:BB:CC:11:22:33", "6", ["DE:AD:00:00:00:01"], iterations=2, delay=0)

    assert calls == ["DE:AD:00:00:00:01", "DE:AD:00:00:00:01"]


def test_authentication_dos_runs_both_mdk4_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(dos.time, "sleep", lambda s: None)

    calls = []
    monkeypatch.setattr(dos, "run_timed", lambda args, minutes: calls.append((tuple(args), minutes)))

    project = _project(tmp_path)
    dos.authentication_dos("wlan0", project, "AA:BB:CC:11:22:33", minutes=5, iterations=1, delay=0)

    assert calls == [
        (("mdk4", "wlan0", "a", "-a", "AA:BB:CC:11:22:33", "-m"), 5),
        (("mdk4", "wlan0", "a", "-i", "AA:BB:CC:11:22:33", "-m"), 5),
    ]


def test_michael_countermeasures_runs_both_mdk4_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(dos.time, "sleep", lambda s: None)

    calls = []
    monkeypatch.setattr(dos, "run_timed", lambda args, minutes: calls.append(tuple(args)))

    project = _project(tmp_path)
    dos.michael_countermeasures("wlan0", project, "AA:BB:CC:11:22:33", minutes=5, iterations=1, delay=0)

    assert calls == [
        ("mdk4", "wlan0", "m", "-t", "AA:BB:CC:11:22:33"),
        ("mdk4", "wlan0", "m", "-t", "AA:BB:CC:11:22:33", "-j"),
    ]


def test_eapol_injection_runs_mdk4(tmp_path, monkeypatch):
    monkeypatch.setattr(dos.time, "sleep", lambda s: None)

    calls = []
    monkeypatch.setattr(dos, "run_timed", lambda args, minutes: calls.append(tuple(args)))

    project = _project(tmp_path)
    dos.eapol_injection("wlan0", project, "AA:BB:CC:11:22:33", minutes=5, iterations=1, delay=0)

    assert calls == [("mdk4", "wlan0", "e", "-t", "AA:BB:CC:11:22:33", "-l")]


def test_beacon_flood_runs_mdk4(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(dos, "run_timed", lambda args, minutes: calls.append((tuple(args), minutes)))

    project = _project(tmp_path)
    dos.beacon_flood("wlan0", project, minutes=5)

    assert calls == [(("mdk4", "wlan0", "b", "-a", "-w", "nta", "-m"), 5)]
