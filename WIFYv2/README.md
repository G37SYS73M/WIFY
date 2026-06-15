# WIFY v2.0

A semi-automated WiFi pentesting tool for security auditors, rewritten from
scratch in Python. v2.0 drops the `wifite` dependency entirely: WPA/WPA2
(PMKID + 4-way handshake) and WEP attacks are now orchestrated directly by
WIFY, on top of `aircrack-ng`, `mdk4`, `hcxtools`, and `hashcat`.

## What's new in v2.0

- Full rewrite in Python (replaces the bash scripts in `../WIFYv1`).
- Custom WPA/WPA2-Personal attack chain (`attacks/wpa.py`): PMKID capture
  via `hcxdumptool`/`hcxpcapngtool`/`hashcat`, falling back to a 4-way
  handshake capture (Scapy deauth + `airodump-ng`) cracked with
  `aircrack-ng`.
- Custom WEP attack chain (`attacks/wep.py`): fake authentication, ARP
  replay, fragmentation/chopchop + packet forging via `aireplay-ng` and
  `packetforge-ng`, cracked with `aircrack-ng`.
- Scapy-based deauth/disassoc frame injection (`packet/deauth.py`) and
  EAPOL handshake detection (`packet/handshake.py`).
- `scanned_aps.json` is the single source of truth for discovered APs;
  the menu prints a formatted table from it.
- `attacks/enterprise.py` is a placeholder for Phase 2 (WPA-Enterprise
  attacks) — not implemented yet.

## Requirements

- Run as root (raw sockets + `iw`/`airodump-ng`/`mdk4` need it).
- Install system dependencies: `./install.sh`
  (`aircrack-ng`, `mdk4`, `hcxdumptool`, `hcxtools`, `hashcat`, `tshark`,
  `reaver`, `bully`, `cowpatty`, `python3-scapy`).
- Alternatively, install the Python dependency via pip: `pip install -r requirements.txt`

## Usage

```
sudo python3 wify.py <interface_name>
```

You'll be prompted for a project name; all logs, captures, and the
scanned-AP database (`projects/<name>/scanned_aps.json`) are stored under
`projects/<name>/`.

### Menu

```
1 => Put Device in Monitor Mode
2 => Put Device in Managed Mode
3 => Scan For Access Points (APs)
4 => Scan An Access Point (AP)
5 => Show Scanned Access Points (APs)
6 => All DOS Attacks
7 => WPA Attack
8 => WEP Attack
```

Option 6 opens a DOS attack submenu (deauth, disassoc, authentication DOS,
Michael countermeasures exploitation, EAPOL injection, beacon flooding).

## Testing

```
python3 -m pytest tests/ -v
```

All non-hardware-dependent logic (validation, project/JSON storage,
airodump-ng CSV parsing, Scapy frame construction, EAPOL handshake
detection, and the WPA/WEP attack orchestration) is covered by unit tests
that run without root or wireless hardware. Hardware-dependent flows
(monitor mode, live captures, packet injection, full WPA/WEP attacks) need
to be verified on real hardware.
