"""Subprocess helpers shared across the scanning/attack modules."""

import subprocess


def run_cmd(args: list[str], timeout: float | None = None) -> subprocess.CompletedProcess:
    """Runs `args`, capturing output. Never raises on a non-zero exit code."""
    return subprocess.run(args, capture_output=True, text=True, check=False, timeout=timeout)


def run_timed(args: list[str], minutes: int) -> subprocess.CompletedProcess:
    """Runs `args` wrapped in `timeout <minutes>m`, blocking until it finishes or times out."""
    return run_cmd(["timeout", f"{minutes}m", *args])


def start_background(args: list[str]) -> subprocess.Popen:
    """Starts `args` as a background process, discarding its output."""
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def stop_background(proc: subprocess.Popen) -> None:
    """Stops a process started with `start_background`."""
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
