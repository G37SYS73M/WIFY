from pathlib import Path
from types import SimpleNamespace

from attacks import wpa
from core.project import AccessPoint, Project

BSSID = "AA:BB:CC:11:22:33"
CLIENT = "DE:AD:BE:EF:00:01"


def _project(tmp_path: Path) -> Project:
    return Project("TEST", base_dir=tmp_path)


def _stub_capture_setup(monkeypatch):
    monkeypatch.setattr(wpa.device, "set_channel", lambda iface, channel: None)
    monkeypatch.setattr(wpa, "start_background", lambda args: "PROC")
    stopped = []
    monkeypatch.setattr(wpa, "stop_background", lambda proc: stopped.append(proc))
    monkeypatch.setattr(wpa.time, "sleep", lambda s: None)
    return stopped


def test_capture_handshake_success(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "_timestamp", lambda: "TS")
    stopped = _stub_capture_setup(monkeypatch)

    deauth_calls = []
    monkeypatch.setattr(wpa.deauth, "send_deauth", lambda iface, bssid, client, count: deauth_calls.append(client))
    monkeypatch.setattr(wpa.handshake, "has_complete_handshake", lambda cap, bssid: True)

    times = iter([0, 1])
    monkeypatch.setattr(wpa.time, "time", lambda: next(times))

    project = _project(tmp_path)
    cap_path = project.captures_dir / f"AA-BB-CC-11-22-33-handshake-TS-01.cap"
    cap_path.touch()

    result = wpa.capture_handshake("wlan0", project, BSSID, "TestAP", "6", [CLIENT])

    assert result.success is True
    assert result.cap_path == cap_path
    assert deauth_calls == [CLIENT]
    assert stopped == ["PROC"]


def test_capture_handshake_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "_timestamp", lambda: "TS")
    stopped = _stub_capture_setup(monkeypatch)

    monkeypatch.setattr(wpa.deauth, "send_deauth", lambda *a, **k: None)
    monkeypatch.setattr(wpa.handshake, "has_complete_handshake", lambda cap, bssid: False)

    times = iter([0, 1, 1000])
    monkeypatch.setattr(wpa.time, "time", lambda: next(times))

    project = _project(tmp_path)

    result = wpa.capture_handshake("wlan0", project, BSSID, "TestAP", "6", [], timeout_s=300)

    assert result.success is False
    assert result.cap_path is None
    assert stopped == ["PROC"]


def test_capture_handshake_uses_broadcast_when_no_clients(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "_timestamp", lambda: "TS")
    _stub_capture_setup(monkeypatch)

    deauth_calls = []
    monkeypatch.setattr(wpa.deauth, "send_deauth", lambda iface, bssid, client, count: deauth_calls.append(client))
    monkeypatch.setattr(wpa.handshake, "has_complete_handshake", lambda cap, bssid: True)

    times = iter([0, 1])
    monkeypatch.setattr(wpa.time, "time", lambda: next(times))

    project = _project(tmp_path)
    cap_path = project.captures_dir / f"AA-BB-CC-11-22-33-handshake-TS-01.cap"
    cap_path.touch()

    wpa.capture_handshake("wlan0", project, BSSID, "TestAP", "6", [])

    assert deauth_calls == [wpa.deauth.BROADCAST]


def test_crack_handshake_success(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "run_cmd", lambda args: SimpleNamespace(stdout="KEY FOUND! [ password123 ]\n", returncode=0))

    project = _project(tmp_path)
    result = wpa.crack_handshake(Path("/tmp/test.cap"), "wordlist.txt", BSSID, project)

    assert result.success is True
    assert result.key == "password123"
    assert "aircrack-ng found the key: password123" in project.log_path.read_text()


def test_crack_handshake_no_key_found(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "run_cmd", lambda args: SimpleNamespace(stdout="KEY NOT FOUND\n", returncode=0))

    project = _project(tmp_path)
    result = wpa.crack_handshake(Path("/tmp/test.cap"), "wordlist.txt", BSSID, project)

    assert result.success is False
    assert result.key is None


def test_capture_pmkid_success(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "_timestamp", lambda: "TS")
    monkeypatch.setattr(wpa.device, "set_channel", lambda iface, channel: None)

    def fake_run_cmd(args, timeout=None):
        pcapng_path = Path(args[args.index("-o") + 1])
        pcapng_path.write_bytes(b"data")
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(wpa, "run_cmd", fake_run_cmd)

    project = _project(tmp_path)
    result = wpa.capture_pmkid("wlan0", project, BSSID, "6")

    assert result == project.captures_dir / "AA-BB-CC-11-22-33-pmkid-TS.pcapng"
    assert result.exists()


def test_capture_pmkid_no_output(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "_timestamp", lambda: "TS")
    monkeypatch.setattr(wpa.device, "set_channel", lambda iface, channel: None)
    monkeypatch.setattr(wpa, "run_cmd", lambda args, timeout=None: SimpleNamespace(stdout="", returncode=0))

    project = _project(tmp_path)
    result = wpa.capture_pmkid("wlan0", project, BSSID, "6")

    assert result is None


def test_crack_pmkid_success(tmp_path, monkeypatch):
    project = _project(tmp_path)
    pcapng_path = project.captures_dir / "AA-BB-CC-11-22-33-pmkid-TS.pcapng"
    pcapng_path.write_bytes(b"data")

    def fake_run_cmd(args):
        if args[0] == "hcxpcapngtool":
            hash_path = Path(args[args.index("-o") + 1])
            hash_path.write_text("hash-line")
            return SimpleNamespace(stdout="", returncode=0)
        if "--show" in args:
            return SimpleNamespace(stdout=f"{BSSID}:TestAP:password123\n", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(wpa, "run_cmd", fake_run_cmd)

    result = wpa.crack_pmkid(pcapng_path, "wordlist.txt", project)

    assert result.success is True
    assert result.key == "password123"


def test_crack_pmkid_no_hash_extracted(tmp_path, monkeypatch):
    project = _project(tmp_path)
    pcapng_path = project.captures_dir / "AA-BB-CC-11-22-33-pmkid-TS.pcapng"
    pcapng_path.write_bytes(b"data")

    monkeypatch.setattr(wpa, "run_cmd", lambda args: SimpleNamespace(stdout="", returncode=0))

    result = wpa.crack_pmkid(pcapng_path, "wordlist.txt", project)

    assert result.success is False
    assert result.key is None


def test_crack_pmkid_hashcat_no_match(tmp_path, monkeypatch):
    project = _project(tmp_path)
    pcapng_path = project.captures_dir / "AA-BB-CC-11-22-33-pmkid-TS.pcapng"
    pcapng_path.write_bytes(b"data")

    def fake_run_cmd(args):
        if args[0] == "hcxpcapngtool":
            hash_path = Path(args[args.index("-o") + 1])
            hash_path.write_text("hash-line")
            return SimpleNamespace(stdout="", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(wpa, "run_cmd", fake_run_cmd)

    result = wpa.crack_pmkid(pcapng_path, "wordlist.txt", project)

    assert result.success is False
    assert result.key is None


def test_save_key_writes_file(tmp_path):
    project = _project(tmp_path)
    key_path = wpa._save_key(project, BSSID, "password123")

    assert key_path == project.captures_dir / "AA-BB-CC-11-22-33-key.txt"
    assert key_path.read_text() == "password123\n"


def test_run_wpa_attack_pmkid_success(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "capture_pmkid", lambda iface, project, bssid, channel: Path("/tmp/x.pcapng"))
    monkeypatch.setattr(wpa, "crack_pmkid", lambda pcapng, wordlist, project: wpa.CrackResult(success=True, key="password123"))

    handshake_calls = []
    monkeypatch.setattr(wpa, "capture_handshake", lambda *a, **k: handshake_calls.append(1))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6")

    result = wpa.run_wpa_attack("wlan0", project, ap, "wordlist.txt")

    assert result.success is True
    assert result.key == "password123"
    assert handshake_calls == []
    assert (project.captures_dir / "AA-BB-CC-11-22-33-key.txt").read_text() == "password123\n"


def test_run_wpa_attack_falls_back_to_handshake(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "capture_pmkid", lambda iface, project, bssid, channel: None)
    monkeypatch.setattr(
        wpa, "capture_handshake",
        lambda iface, project, bssid, essid, channel, clients: wpa.HandshakeResult(success=True, cap_path=Path("/tmp/x.cap")),
    )
    monkeypatch.setattr(wpa, "crack_handshake", lambda cap_path, wordlist, bssid, project: wpa.CrackResult(success=True, key="password123"))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6")

    result = wpa.run_wpa_attack("wlan0", project, ap, "wordlist.txt")

    assert result.success is True
    assert result.key == "password123"
    assert (project.captures_dir / "AA-BB-CC-11-22-33-key.txt").read_text() == "password123\n"


def test_run_wpa_attack_handshake_capture_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "capture_pmkid", lambda iface, project, bssid, channel: None)
    monkeypatch.setattr(
        wpa, "capture_handshake",
        lambda iface, project, bssid, essid, channel, clients: wpa.HandshakeResult(success=False, cap_path=None),
    )

    crack_calls = []
    monkeypatch.setattr(wpa, "crack_handshake", lambda *a, **k: crack_calls.append(1))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6")

    result = wpa.run_wpa_attack("wlan0", project, ap, "wordlist.txt")

    assert result.success is False
    assert result.key is None
    assert crack_calls == []


def test_run_wpa_attack_pmkid_fails_then_handshake_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(wpa, "capture_pmkid", lambda iface, project, bssid, channel: Path("/tmp/x.pcapng"))
    monkeypatch.setattr(wpa, "crack_pmkid", lambda pcapng, wordlist, project: wpa.CrackResult(success=False, key=None))
    monkeypatch.setattr(
        wpa, "capture_handshake",
        lambda iface, project, bssid, essid, channel, clients: wpa.HandshakeResult(success=True, cap_path=Path("/tmp/x.cap")),
    )
    monkeypatch.setattr(wpa, "crack_handshake", lambda cap_path, wordlist, bssid, project: wpa.CrackResult(success=False, key=None))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6")

    result = wpa.run_wpa_attack("wlan0", project, ap, "wordlist.txt")

    assert result.success is False
    assert not (project.captures_dir / "AA-BB-CC-11-22-33-key.txt").exists()
