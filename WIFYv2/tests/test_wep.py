from pathlib import Path
from types import SimpleNamespace

from attacks import wep
from core.project import AccessPoint, Project

BSSID = "AA:BB:CC:11:22:33"
CLIENT = "DE:AD:BE:EF:00:01"
MAC = "11:22:33:44:55:66"


def _project(tmp_path: Path) -> Project:
    return Project("TEST", base_dir=tmp_path)


def test_fake_auth_success(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    monkeypatch.setattr(wep, "run_cmd", lambda args, timeout=None: SimpleNamespace(stdout="Association successful :-)", returncode=0))

    project = _project(tmp_path)
    assert wep.fake_auth("wlan0", BSSID, project) is True
    assert "Fake authentication with" in project.log_path.read_text()


def test_fake_auth_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    monkeypatch.setattr(wep, "run_cmd", lambda args, timeout=None: SimpleNamespace(stdout="Got a deauthentication packet!", returncode=0))

    project = _project(tmp_path)
    assert wep.fake_auth("wlan0", BSSID, project) is False


def test_arp_replay_attack_without_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    calls = []
    monkeypatch.setattr(wep, "run_timed", lambda args, minutes: calls.append((tuple(args), minutes)))

    project = _project(tmp_path)
    wep.arp_replay_attack("wlan0", BSSID, project)

    assert calls == [(("aireplay-ng", "--arpreplay", "-b", BSSID, "-h", MAC, "wlan0"), wep.DEFAULT_ARPREPLAY_MINUTES)]


def test_arp_replay_attack_with_forged_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    calls = []
    monkeypatch.setattr(wep, "run_timed", lambda args, minutes: calls.append(tuple(args)))

    project = _project(tmp_path)
    forged = Path("/tmp/forged.cap")
    wep.arp_replay_attack("wlan0", BSSID, project, arp_cap=forged)

    assert calls == [("aireplay-ng", "--arpreplay", "-b", BSSID, "-h", MAC, "-r", str(forged), "wlan0")]


def test_fragmentation_attack_finds_xor_file(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    monkeypatch.setattr(wep, "_timestamp", lambda: "TS")

    project = _project(tmp_path)
    safe_bssid = BSSID.replace(":", "-")
    expected_prefix = project.captures_dir / f"{safe_bssid}-frag-TS"

    def fake_run_timed(args, minutes):
        (expected_prefix.parent / f"{expected_prefix.name}-0844-12345.xor").write_bytes(b"prga")

    monkeypatch.setattr(wep, "run_timed", fake_run_timed)

    xor_file = wep.fragmentation_attack("wlan0", BSSID, project)

    assert xor_file == expected_prefix.parent / f"{expected_prefix.name}-0844-12345.xor"


def test_fragmentation_attack_no_xor_file(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    monkeypatch.setattr(wep, "_timestamp", lambda: "TS")
    monkeypatch.setattr(wep, "run_timed", lambda args, minutes: None)

    project = _project(tmp_path)
    assert wep.fragmentation_attack("wlan0", BSSID, project) is None


def test_chopchop_attack_finds_xor_file(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    monkeypatch.setattr(wep, "_timestamp", lambda: "TS")

    project = _project(tmp_path)
    safe_bssid = BSSID.replace(":", "-")
    expected_prefix = project.captures_dir / f"{safe_bssid}-chopchop-TS"

    def fake_run_timed(args, minutes):
        (expected_prefix.parent / f"{expected_prefix.name}-0844-12345.xor").write_bytes(b"prga")

    monkeypatch.setattr(wep, "run_timed", fake_run_timed)

    xor_file = wep.chopchop_attack("wlan0", BSSID, project)

    assert xor_file == expected_prefix.parent / f"{expected_prefix.name}-0844-12345.xor"


def test_forge_arp_packet_success(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)

    project = _project(tmp_path)
    xor_file = project.captures_dir / "frag.xor"
    xor_file.write_bytes(b"prga")

    def fake_run_cmd(args):
        forged_path = Path(args[args.index("-w") + 1])
        forged_path.write_bytes(b"forged")
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(wep, "run_cmd", fake_run_cmd)

    forged = wep.forge_arp_packet("wlan0", xor_file, BSSID, project)

    assert forged == xor_file.with_suffix(".cap")
    assert forged.exists()


def test_forge_arp_packet_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "_interface_mac", lambda iface: MAC)
    monkeypatch.setattr(wep, "run_cmd", lambda args: SimpleNamespace(stdout="", returncode=1))

    project = _project(tmp_path)
    xor_file = project.captures_dir / "frag.xor"
    xor_file.write_bytes(b"prga")

    assert wep.forge_arp_packet("wlan0", xor_file, BSSID, project) is None


def test_crack_wep_success_first_try(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "run_cmd", lambda args: SimpleNamespace(stdout="KEY FOUND! [ AB:CD:EF:01:23 ]", returncode=0))
    monkeypatch.setattr(wep.time, "sleep", lambda s: None)

    times = iter([0, 1])
    monkeypatch.setattr(wep.time, "time", lambda: next(times))

    project = _project(tmp_path)
    result = wep.crack_wep(Path("/tmp/test.cap"), BSSID, project)

    assert result.success is True
    assert result.key == "AB:CD:EF:01:23"


def test_crack_wep_success_after_polling(tmp_path, monkeypatch):
    outputs = iter(["KEY NOT FOUND\n", "KEY FOUND! [ AB:CD:EF:01:23 ]"])
    monkeypatch.setattr(wep, "run_cmd", lambda args: SimpleNamespace(stdout=next(outputs), returncode=0))
    monkeypatch.setattr(wep.time, "sleep", lambda s: None)

    times = iter([0, 1, 2])
    monkeypatch.setattr(wep.time, "time", lambda: next(times))

    project = _project(tmp_path)
    result = wep.crack_wep(Path("/tmp/test.cap"), BSSID, project)

    assert result.success is True
    assert result.key == "AB:CD:EF:01:23"


def test_crack_wep_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(wep, "run_cmd", lambda args: SimpleNamespace(stdout="KEY NOT FOUND\n", returncode=0))
    monkeypatch.setattr(wep.time, "sleep", lambda s: None)

    times = iter([0, 1, 1000])
    monkeypatch.setattr(wep.time, "time", lambda: next(times))

    project = _project(tmp_path)
    result = wep.crack_wep(Path("/tmp/test.cap"), BSSID, project, timeout_s=300)

    assert result.success is False
    assert result.key is None


def _stub_orchestration(monkeypatch):
    monkeypatch.setattr(wep.device, "set_channel", lambda iface, channel: None)
    monkeypatch.setattr(wep, "start_background", lambda args: "PROC")
    stopped = []
    monkeypatch.setattr(wep, "stop_background", lambda proc: stopped.append(proc))
    monkeypatch.setattr(wep, "_timestamp", lambda: "TS")
    return stopped


def test_run_wep_attack_with_clients_uses_arp_replay(tmp_path, monkeypatch):
    stopped = _stub_orchestration(monkeypatch)
    monkeypatch.setattr(wep, "fake_auth", lambda iface, bssid, project: True)

    arp_calls = []
    monkeypatch.setattr(wep, "arp_replay_attack", lambda iface, bssid, project, arp_cap=None: arp_calls.append(arp_cap))

    frag_calls = []
    monkeypatch.setattr(wep, "fragmentation_attack", lambda *a, **k: frag_calls.append(1))

    monkeypatch.setattr(wep, "crack_wep", lambda cap_path, bssid, project: wep.CrackResult(success=True, key="AB:CD:EF:01:23"))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6", clients=[CLIENT])

    result = wep.run_wep_attack("wlan0", project, ap)

    assert result.success is True
    assert arp_calls == [None]
    assert frag_calls == []
    assert stopped == ["PROC"]


def test_run_wep_attack_no_clients_uses_fragmentation_chain(tmp_path, monkeypatch):
    _stub_orchestration(monkeypatch)
    monkeypatch.setattr(wep, "fake_auth", lambda iface, bssid, project: True)

    xor_file = Path("/tmp/frag.xor")
    monkeypatch.setattr(wep, "fragmentation_attack", lambda iface, bssid, project: xor_file)

    chopchop_calls = []
    monkeypatch.setattr(wep, "chopchop_attack", lambda *a, **k: chopchop_calls.append(1))

    forged_cap = Path("/tmp/forged.cap")
    monkeypatch.setattr(wep, "forge_arp_packet", lambda iface, xor, bssid, project: forged_cap)

    arp_calls = []
    monkeypatch.setattr(wep, "arp_replay_attack", lambda iface, bssid, project, arp_cap=None: arp_calls.append(arp_cap))

    monkeypatch.setattr(wep, "crack_wep", lambda cap_path, bssid, project: wep.CrackResult(success=True, key="AB:CD:EF:01:23"))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6", clients=[])

    result = wep.run_wep_attack("wlan0", project, ap)

    assert result.success is True
    assert chopchop_calls == []
    assert arp_calls == [forged_cap]


def test_run_wep_attack_fragmentation_falls_back_to_chopchop(tmp_path, monkeypatch):
    _stub_orchestration(monkeypatch)
    monkeypatch.setattr(wep, "fake_auth", lambda iface, bssid, project: True)
    monkeypatch.setattr(wep, "fragmentation_attack", lambda iface, bssid, project: None)

    xor_file = Path("/tmp/chop.xor")
    monkeypatch.setattr(wep, "chopchop_attack", lambda iface, bssid, project: xor_file)
    monkeypatch.setattr(wep, "forge_arp_packet", lambda iface, xor, bssid, project: Path("/tmp/forged.cap"))
    monkeypatch.setattr(wep, "arp_replay_attack", lambda iface, bssid, project, arp_cap=None: None)
    monkeypatch.setattr(wep, "crack_wep", lambda cap_path, bssid, project: wep.CrackResult(success=True, key="AB:CD:EF:01:23"))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6", clients=[])

    result = wep.run_wep_attack("wlan0", project, ap)

    assert result.success is True


def test_run_wep_attack_fails_when_fake_auth_fails(tmp_path, monkeypatch):
    stopped = _stub_orchestration(monkeypatch)
    monkeypatch.setattr(wep, "fake_auth", lambda iface, bssid, project: False)

    crack_calls = []
    monkeypatch.setattr(wep, "crack_wep", lambda *a, **k: crack_calls.append(1))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6", clients=[CLIENT])

    result = wep.run_wep_attack("wlan0", project, ap)

    assert result.success is False
    assert result.key is None
    assert crack_calls == []
    assert stopped == ["PROC"]


def test_run_wep_attack_fails_when_no_prga_obtained(tmp_path, monkeypatch):
    _stub_orchestration(monkeypatch)
    monkeypatch.setattr(wep, "fake_auth", lambda iface, bssid, project: True)
    monkeypatch.setattr(wep, "fragmentation_attack", lambda iface, bssid, project: None)
    monkeypatch.setattr(wep, "chopchop_attack", lambda iface, bssid, project: None)

    forge_calls = []
    monkeypatch.setattr(wep, "forge_arp_packet", lambda *a, **k: forge_calls.append(1))
    monkeypatch.setattr(wep, "crack_wep", lambda *a, **k: (_ for _ in ()).throw(AssertionError("should not be called")))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6", clients=[])

    result = wep.run_wep_attack("wlan0", project, ap)

    assert result.success is False
    assert forge_calls == []


def test_run_wep_attack_fails_when_forge_fails(tmp_path, monkeypatch):
    _stub_orchestration(monkeypatch)
    monkeypatch.setattr(wep, "fake_auth", lambda iface, bssid, project: True)
    monkeypatch.setattr(wep, "fragmentation_attack", lambda iface, bssid, project: Path("/tmp/frag.xor"))
    monkeypatch.setattr(wep, "forge_arp_packet", lambda iface, xor, bssid, project: None)

    arp_calls = []
    monkeypatch.setattr(wep, "arp_replay_attack", lambda *a, **k: arp_calls.append(1))

    project = _project(tmp_path)
    ap = AccessPoint(bssid=BSSID, essid="TestAP", channel="6", clients=[])

    result = wep.run_wep_attack("wlan0", project, ap)

    assert result.success is False
    assert arp_calls == []
