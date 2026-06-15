"""ANSI color helpers, replacing the color vars/echo -e usage from scripts/common.sh."""

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
NC = "\033[0m"


def ok(msg: str) -> None:
    print(f"{GREEN}[*] {msg}{NC}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[*] {msg}{NC}")


def err(msg: str) -> None:
    print(f"{RED}[!] {msg}{NC}")
