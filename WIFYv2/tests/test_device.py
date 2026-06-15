import subprocess

from core import device

IW_DEV_OUTPUT = """\
phy#0
\tInterface wlan0
\t\tifindex 3
\t\ttype managed
"""

IWCONFIG_MANAGED_OUTPUT = """\
wlan0     IEEE 802.11  ESSID:off/any
          Mode:Managed  Frequency:2.412 GHz  Access Point: Not-Associated
"""

IWCONFIG_MONITOR_OUTPUT = """\
wlan0     IEEE 802.11  Mode:Monitor  Frequency:2.437 GHz  Tx-Power=20 dBm
"""

IWLIST_CHANNEL_OUTPUT = """\
wlan0     32 channels in total; available frequencies :
          Channel 01 : 2.412 GHz
          Channel 06 : 2.437 GHz
          Current Frequency:2.437 GHz (Channel 6)
"""


def _fake_run(stdout: str):
    def run(args, capture_output, text, check):
        return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")

    return run


def test_list_interfaces(monkeypatch):
    monkeypatch.setattr(device, "_run", lambda args: subprocess.CompletedProcess(args, 0, IW_DEV_OUTPUT, ""))
    assert device.list_interfaces() == ["wlan0"]


def test_get_mode_managed(monkeypatch):
    monkeypatch.setattr(device, "_run", lambda args: subprocess.CompletedProcess(args, 0, IWCONFIG_MANAGED_OUTPUT, ""))
    assert device.get_mode("wlan0") == "Managed"


def test_get_mode_monitor(monkeypatch):
    monkeypatch.setattr(device, "_run", lambda args: subprocess.CompletedProcess(args, 0, IWCONFIG_MONITOR_OUTPUT, ""))
    assert device.get_mode("wlan0") == "Monitor"


def test_get_mode_unknown(monkeypatch):
    monkeypatch.setattr(device, "_run", lambda args: subprocess.CompletedProcess(args, 0, "", ""))
    assert device.get_mode("wlan0") == "Unknown"


def test_get_channel(monkeypatch):
    monkeypatch.setattr(device, "_run", lambda args: subprocess.CompletedProcess(args, 0, IWLIST_CHANNEL_OUTPUT, ""))
    assert device.get_channel("wlan0") == "6"


def test_get_channel_unknown(monkeypatch):
    monkeypatch.setattr(device, "_run", lambda args: subprocess.CompletedProcess(args, 0, "", ""))
    assert device.get_channel("wlan0") == "Unknown"


def test_set_monitor_mode_runs_expected_commands(monkeypatch):
    calls = []
    monkeypatch.setattr(device, "_run", lambda args: calls.append(args))

    device.set_monitor_mode("wlan0")

    assert calls == [
        ["airmon-ng", "check", "kill"],
        ["ip", "link", "set", "wlan0", "down"],
        ["iw", "dev", "wlan0", "set", "type", "monitor"],
        ["ip", "link", "set", "wlan0", "up"],
    ]


def test_set_managed_mode_runs_expected_commands(monkeypatch):
    calls = []
    monkeypatch.setattr(device, "_run", lambda args: calls.append(args))

    device.set_managed_mode("wlan0")

    assert calls == [
        ["ip", "link", "set", "wlan0", "down"],
        ["iw", "dev", "wlan0", "set", "type", "managed"],
        ["ip", "link", "set", "wlan0", "up"],
        ["service", "NetworkManager", "restart"],
    ]


def test_set_channel(monkeypatch):
    calls = []
    monkeypatch.setattr(device, "_run", lambda args: calls.append(args))

    device.set_channel("wlan0", "6")

    assert calls == [["iw", "dev", "wlan0", "set", "channel", "6"]]


def test_print_device_info_no_interfaces(monkeypatch, capsys):
    monkeypatch.setattr(device, "list_interfaces", lambda: [])

    device.print_device_info()

    out = capsys.readouterr().out
    assert "None found." in out


def test_print_device_info_with_interface(monkeypatch, capsys):
    monkeypatch.setattr(device, "list_interfaces", lambda: ["wlan0"])
    monkeypatch.setattr(device, "get_mode", lambda iface: "Managed")
    monkeypatch.setattr(device, "get_channel", lambda iface: "6")

    device.print_device_info()

    out = capsys.readouterr().out
    assert "wlan0" in out
    assert "Managed" in out
    assert "6" in out
