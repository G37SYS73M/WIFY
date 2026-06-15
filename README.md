# WiFY

A semi-automated WiFi pentesting tool for security auditors. This tool
creates logs and attack-related files that make the process of report
writing easy.

This repository contains two versions:

- **[WIFYv2](WIFYv2/)** — the current version (2.0), a full Python rewrite
  with custom WPA/WPA2 (PMKID + handshake) and WEP attack chains, replacing
  the `wifite` dependency. Start here: `sudo python3 WIFYv2/wify.py <interface>`.
- **[WIFYv1](WIFYv1/)** — the original bash implementation (1.1), kept for
  reference.
