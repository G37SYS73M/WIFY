from pathlib import Path

from core.project import AccessPoint, Project


def test_project_creates_dirs_and_log(tmp_path: Path):
    proj = Project("TEST", base_dir=tmp_path)

    assert proj.dir == tmp_path / "TEST"
    assert proj.dir.is_dir()
    assert proj.captures_dir.is_dir()
    assert proj.log_path.exists()


def test_log_header_and_msg(tmp_path: Path, capsys):
    proj = Project("TEST", base_dir=tmp_path)

    proj.log_header("Monitor Mode")
    proj.log_msg("hello world")

    contents = proj.log_path.read_text()
    assert "Monitor Mode" in contents
    assert "hello world" in contents

    captured = capsys.readouterr()
    assert "hello world" in captured.out


def test_upsert_and_load_aps(tmp_path: Path):
    proj = Project("TEST", base_dir=tmp_path)

    ap = AccessPoint(
        bssid="AA:BB:CC:11:22:33",
        essid="TestNet",
        channel="6",
        privacy="WPA2",
        cipher="CCMP",
        auth="PSK",
        power="-50",
        clients=["DE:AD:BE:EF:00:01"],
        last_seen="15-06-26-12_00",
    )
    proj.upsert_ap(ap)

    assert proj.aps_path.exists()

    loaded = proj.load_aps()
    assert "AA:BB:CC:11:22:33" in loaded
    assert loaded["AA:BB:CC:11:22:33"].essid == "TestNet"
    assert loaded["AA:BB:CC:11:22:33"].clients == ["DE:AD:BE:EF:00:01"]


def test_upsert_overwrites_existing(tmp_path: Path):
    proj = Project("TEST", base_dir=tmp_path)

    proj.upsert_ap(AccessPoint(bssid="AA:BB:CC:11:22:33", essid="Old"))
    proj.upsert_ap(AccessPoint(bssid="AA:BB:CC:11:22:33", essid="New"))

    loaded = proj.load_aps()
    assert len(loaded) == 1
    assert loaded["AA:BB:CC:11:22:33"].essid == "New"
