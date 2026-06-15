"""Project/log management, replacing command.logs + ScannedAPs.csv handling."""

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class AccessPoint:
    bssid: str
    essid: str = ""
    channel: str = ""
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    power: str = ""
    clients: list[str] = field(default_factory=list)
    last_seen: str = ""


class Project:
    """A project's on-disk state: projects/<name>/{command.logs, scanned_aps.json, captures/}."""

    def __init__(self, name: str, base_dir: Path = Path("projects")):
        self.name = name
        self.dir = base_dir / name
        self.captures_dir = self.dir / "captures"
        self.log_path = self.dir / "command.logs"
        self.aps_path = self.dir / "scanned_aps.json"

        self.dir.mkdir(parents=True, exist_ok=True)
        self.captures_dir.mkdir(parents=True, exist_ok=True)
        self.log_path.touch(exist_ok=True)

    def log_header(self, label: str = "") -> None:
        """Writes a timestamped separator into command.logs."""
        ts = datetime.now().strftime("%d-%m-%y-%H_%M")
        line = f"{ts}{' - ' + label if label else ''}"
        with self.log_path.open("a") as f:
            f.write("-" * 72 + "\n")
            f.write(line + "\n")

    def log_msg(self, msg: str) -> None:
        """Prints a message and appends it to command.logs."""
        print(msg)
        with self.log_path.open("a") as f:
            f.write(msg + "\n")

    def load_aps(self) -> dict[str, AccessPoint]:
        if not self.aps_path.exists():
            return {}
        with self.aps_path.open() as f:
            raw = json.load(f)
        return {bssid: AccessPoint(**data) for bssid, data in raw.items()}

    def save_aps(self, aps: dict[str, AccessPoint]) -> None:
        with self.aps_path.open("w") as f:
            json.dump({b: asdict(a) for b, a in aps.items()}, f, indent=2)

    def upsert_ap(self, ap: AccessPoint) -> None:
        """Adds or updates a single AP record in scanned_aps.json."""
        aps = self.load_aps()
        aps[ap.bssid] = ap
        self.save_aps(aps)
