"""Top-level interactive menu, replacing the WIFY.sh menu loop."""

from pathlib import Path

from attacks import wep, wpa
from core import colors, device, prompts, scan
from core.project import Project
from menu.dos_menu import run_dos_menu
from packet.deauth import NotInMonitorModeError

OPTIONS = """
OPTIONS:
 1 => Put Device in Monitor Mode
 2 => Put Device in Managed Mode
 3 => Scan For Access Points (APs)
 4 => Scan An Access Point (AP)
 5 => Show Scanned Access Points (APs)
 6 => All DOS Attacks
 7 => WPA Attack
 8 => WEP Attack
"""
# Option 9 reserved for Phase 2: WPA-Enterprise attacks (attacks/enterprise.py)

EXIT_KEYWORD = "exit"


def _put_in_monitor_mode(iface: str, project: Project) -> None:
    project.log_header("Monitor Mode")
    device.set_monitor_mode(iface)
    mode = device.get_mode(iface)
    project.log_msg(f"{colors.GREEN}[*] {iface} is now in {mode} mode{colors.NC}")


def _put_in_managed_mode(iface: str, project: Project) -> None:
    project.log_header("Managed Mode")
    device.set_managed_mode(iface)
    mode = device.get_mode(iface)
    project.log_msg(f"{colors.GREEN}[*] {iface} is now in {mode} mode{colors.NC}")


def _scan_for_networks(iface: str, project: Project) -> None:
    mins = prompts.prompt_number("Enter time to sniff (Minutes)(Default: 5mins): ", default=5)
    project.log_header(f"Scan For Networks ({mins}min)")
    aps = scan.scan_networks(iface, mins, project)
    if not aps:
        colors.err("No capture file was produced. The scan may have failed.")
        return
    scan.print_networks_table(aps)


def _scan_an_ap(iface: str, project: Project) -> None:
    scan.print_scanned_aps(project)

    bssid = prompts.prompt_mac()
    if bssid is None:
        return
    channel = prompts.prompt_channel()
    if channel is None:
        return
    mins = prompts.prompt_number("Enter time to scan AP (Minutes)(Default: 5mins): ", default=5)

    project.log_header(f"Scan AP {bssid}")
    ap = scan.scan_ap(iface, bssid, channel, mins, project)
    if ap is None:
        colors.err("No capture file was produced. The scan may have failed.")
        return
    scan.print_ap_details(ap)


def _wpa_attack(iface: str, project: Project) -> None:
    scan.print_scanned_aps(project)

    bssid = prompts.prompt_mac()
    if bssid is None:
        return

    ap = project.load_aps().get(bssid)
    if ap is None:
        colors.err(f"AP {bssid} has not been scanned yet. Scan it first (option 4).")
        return

    wordlist = input("Enter path to wordlist: ").strip()
    if not Path(wordlist).is_file():
        colors.err(f"Wordlist not found: {wordlist}")
        return

    project.log_header(f"WPA Attack on {bssid}")
    result = wpa.run_wpa_attack(iface, project, ap, wordlist)
    if result.success:
        colors.ok(f"Key found for {bssid}: {result.key}")
    else:
        colors.err(f"Failed to find the key for {bssid}.")


def _wep_attack(iface: str, project: Project) -> None:
    scan.print_scanned_aps(project)

    bssid = prompts.prompt_mac()
    if bssid is None:
        return

    ap = project.load_aps().get(bssid)
    if ap is None:
        colors.err(f"AP {bssid} has not been scanned yet. Scan it first (option 4).")
        return

    project.log_header(f"WEP Attack on {bssid}")
    result = wep.run_wep_attack(iface, project, ap)
    if result.success:
        colors.ok(f"Key found for {bssid}: {result.key}")
    else:
        colors.err(f"Failed to find the key for {bssid}.")


def run_menu(iface: str, project: Project) -> None:
    print(OPTIONS)
    user_input = input("Enter an option (type 'exit' to stop): ").strip()

    while user_input != EXIT_KEYWORD:
        try:
            if user_input == "1":
                _put_in_monitor_mode(iface, project)
            elif user_input == "2":
                _put_in_managed_mode(iface, project)
            elif user_input == "3":
                _scan_for_networks(iface, project)
            elif user_input == "4":
                _scan_an_ap(iface, project)
            elif user_input == "5":
                scan.print_scanned_aps(project)
            elif user_input == "6":
                run_dos_menu(iface, project)
            elif user_input == "7":
                _wpa_attack(iface, project)
            elif user_input == "8":
                _wep_attack(iface, project)
            else:
                print("\nInvalid option!!!")
        except NotInMonitorModeError as e:
            colors.err(str(e))

        print(OPTIONS)
        user_input = input("Enter an option (type 'exit' to stop): ").strip()
