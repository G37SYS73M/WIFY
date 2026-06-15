"""Scanning, replacing scripts/scanForNetworks.sh and scripts/scanNetwork.sh."""

import csv
from datetime import datetime
from pathlib import Path

from core import device
from core.project import AccessPoint, Project
from core.shell import run_timed

STATION_HEADER_PREFIX = "Station MAC"


def parse_airodump_csv(csv_path: Path) -> list[AccessPoint]:
    """Parses an airodump-ng CSV (AP table + blank line + station table) into AccessPoints."""
    lines = Path(csv_path).read_text(errors="replace").splitlines()

    station_idx = next(
        (i for i, line in enumerate(lines) if line.strip().startswith(STATION_HEADER_PREFIX)),
        len(lines),
    )
    ap_lines = [
        line for line in lines[:station_idx]
        if line.strip() and not line.strip().startswith("BSSID")
    ]
    station_lines = [line for line in lines[station_idx + 1:] if line.strip()]

    aps: dict[str, AccessPoint] = {}
    now = datetime.now().strftime("%d-%m-%y-%H_%M")

    for row in csv.reader(ap_lines):
        row = [field.strip() for field in row]
        if len(row) < 14 or not row[0]:
            continue
        bssid = row[0]
        aps[bssid] = AccessPoint(
            bssid=bssid,
            essid=row[13],
            channel=row[3],
            privacy=row[5],
            cipher=row[6],
            auth=row[7],
            power=row[8],
            last_seen=now,
        )

    for row in csv.reader(station_lines):
        row = [field.strip() for field in row]
        if len(row) < 6 or not row[0]:
            continue
        station_mac, bssid = row[0], row[5]
        ap = aps.get(bssid)
        if ap is not None and station_mac not in ap.clients:
            ap.clients.append(station_mac)

    return list(aps.values())


def scan_networks(iface: str, minutes: int, project: Project) -> list[AccessPoint]:
    """Runs an airodump-ng sweep of all networks and records results in the project."""
    timestamp = datetime.now().strftime("%d-%m-%y_%H-%M-%S")
    prefix = project.captures_dir / f"scan-networks-{timestamp}"
    run_timed(["airodump-ng", iface, "--output-format", "csv", "-w", str(prefix)], minutes)

    csv_file = Path(f"{prefix}-01.csv")
    if not csv_file.exists():
        return []

    aps = parse_airodump_csv(csv_file)
    for ap in aps:
        project.upsert_ap(ap)
    return aps


def scan_ap(iface: str, bssid: str, channel: str, minutes: int, project: Project) -> AccessPoint | None:
    """Runs a targeted airodump-ng capture of a single AP and records the result."""
    device.set_channel(iface, channel)

    timestamp = datetime.now().strftime("%d-%m-%y_%H-%M-%S")
    safe_bssid = bssid.replace(":", "-")
    prefix = project.captures_dir / f"scan-{safe_bssid}-{timestamp}"
    run_timed(
        ["airodump-ng", iface, "--bssid", bssid, "--channel", str(channel), "--output-format", "csv", "-w", str(prefix)],
        minutes,
    )

    csv_file = Path(f"{prefix}-01.csv")
    if not csv_file.exists():
        return None

    for ap in parse_airodump_csv(csv_file):
        if ap.bssid == bssid:
            project.upsert_ap(ap)
            return ap
    return None


def print_networks_table(aps: list[AccessPoint]) -> None:
    print(f"{'BSSID':<20}{'PWR':>6}  {'CH':>3}  {'Privacy':<10}{'Cipher':<12}{'ESSID'}")
    for ap in aps:
        print(f"{ap.bssid:<20}{ap.power:>6}  {ap.channel:>3}  {ap.privacy:<10}{ap.cipher:<12}{ap.essid}")


def print_ap_details(ap: AccessPoint) -> None:
    print(f"[*] ESSID of the AP: {ap.essid}")
    print(f"[*] BSSID of the AP: {ap.bssid}")
    print(f"[*] Channel Number of the AP: {ap.channel}")
    print(f"[*] Encryption used by the AP: {ap.privacy}")
    print(f"[*] Cipher used by the AP: {ap.cipher}")
    print(f"[*] Authentication used by the AP: {ap.auth}")
    print(f"[*] Number of Stations Connected to the AP: {len(ap.clients)}")
    print("[*] MAC Addresses of Stations Connected to AP:")
    for client in ap.clients:
        print(f"    {client}")


def print_scanned_aps(project: Project) -> None:
    aps = list(project.load_aps().values())
    if not aps:
        print("[*] No APs scanned yet.")
        return
    print_networks_table(aps)
