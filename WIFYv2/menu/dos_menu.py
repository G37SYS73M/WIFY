"""DOS attack submenu, replacing dosAttacks.sh."""

from attacks import dos
from core import colors, prompts, scan
from core.project import Project
from packet.deauth import NotInMonitorModeError

OPTIONS = """
Attack OPTIONS:
 1 => Deauthentication Attack
 2 => Disassociation Attack
 3 => Authentication DOS Attack
 4 => Michael Countermeasures Exploitation (Only For TKIP Enabled APs)
 5 => EAPOL Start and Logoff Packet Injection (Only For WPA-Enterprise)
 6 => Beacon Flooding
"""

EXIT_KEYWORD = "00"


def _prompt_target(project: Project) -> tuple[str, str, list[str]] | None:
    """Prompts for a BSSID + channel, returning (bssid, channel, known_clients) or None."""
    scan.print_scanned_aps(project)

    bssid = prompts.prompt_mac()
    if bssid is None:
        return None
    channel = prompts.prompt_channel()
    if channel is None:
        return None

    aps = project.load_aps()
    clients = aps[bssid].clients if bssid in aps else []
    return bssid, channel, clients


def _prompt_iteration_params() -> tuple[int, int]:
    iterations = prompts.prompt_number(
        "Enter times to iterate attack (Number)(Default: 5times): ", default=5
    )
    delay = prompts.prompt_number(
        "Enter delay time between each iteration (Seconds)(Default: 5sec): ", default=5
    )
    return iterations, delay


def _deauth(iface: str, project: Project) -> None:
    target = _prompt_target(project)
    if target is None:
        return
    bssid, channel, clients = target

    packets = prompts.prompt_number(
        "Enter Number of Deauth Packets Sent During the Attack (Number)(Default: 5Packets): ", default=5
    )
    iterations, delay = _prompt_iteration_params()

    project.log_header(f"Deauth Attack on {bssid}")
    dos.deauth_attack(iface, project, bssid, channel, clients, packets, iterations, delay)


def _disassoc(iface: str, project: Project) -> None:
    target = _prompt_target(project)
    if target is None:
        return
    bssid, channel, clients = target

    packets = prompts.prompt_number(
        "Enter Number of Disassociation Packets Sent During the Attack (Number)(Default: 5Packets): ", default=5
    )
    iterations, delay = _prompt_iteration_params()

    project.log_header(f"Disassociation Attack on {bssid}")
    dos.disassoc_attack(iface, project, bssid, channel, clients, packets, iterations, delay)


def _authentication_dos(iface: str, project: Project) -> None:
    target = _prompt_target(project)
    if target is None:
        return
    bssid, _channel, _clients = target

    minutes = prompts.prompt_number(
        "Enter Time to perform Authentication DOS Attack (Minutes)(Default: 5mins): ", default=5
    )
    iterations, delay = _prompt_iteration_params()

    project.log_header(f"Authentication DOS Attack on {bssid}")
    dos.authentication_dos(iface, project, bssid, minutes, iterations, delay)


def _michael_countermeasures(iface: str, project: Project) -> None:
    target = _prompt_target(project)
    if target is None:
        return
    bssid, _channel, _clients = target

    minutes = prompts.prompt_number(
        "Enter Time to perform Michael Countermeasures Exploitation Attack (Minutes)(Default: 5mins): ", default=5
    )
    iterations, delay = _prompt_iteration_params()

    project.log_header(f"Michael Countermeasures Exploitation on {bssid}")
    dos.michael_countermeasures(iface, project, bssid, minutes, iterations, delay)


def _eapol_injection(iface: str, project: Project) -> None:
    target = _prompt_target(project)
    if target is None:
        return
    bssid, _channel, _clients = target

    minutes = prompts.prompt_number(
        "Enter Time to perform EAPOL Start and Logoff Packet Injection Attack (Minutes)(Default: 5mins): ", default=5
    )
    iterations, delay = _prompt_iteration_params()

    project.log_header(f"EAPOL Start/Logoff Injection on {bssid}")
    dos.eapol_injection(iface, project, bssid, minutes, iterations, delay)


def _beacon_flood(iface: str, project: Project) -> None:
    minutes = prompts.prompt_number(
        "Enter Time to perform Beacon Flooding (Minutes)(Default: 5mins): ", default=5
    )
    project.log_header("Beacon Flooding")
    dos.beacon_flood(iface, project, minutes)


def run_dos_menu(iface: str, project: Project) -> None:
    print(OPTIONS)
    user_input = input("Enter an Attack Option (type '00' to Main Menu): ").strip()

    while user_input != EXIT_KEYWORD:
        try:
            if user_input == "1":
                _deauth(iface, project)
            elif user_input == "2":
                _disassoc(iface, project)
            elif user_input == "3":
                _authentication_dos(iface, project)
            elif user_input == "4":
                _michael_countermeasures(iface, project)
            elif user_input == "5":
                _eapol_injection(iface, project)
            elif user_input == "6":
                _beacon_flood(iface, project)
            else:
                print("\nInvalid Options!!!")
        except NotInMonitorModeError as e:
            colors.err(str(e))

        print(OPTIONS)
        user_input = input("Enter an Attack Option (type '00' to Main Menu): ").strip()
