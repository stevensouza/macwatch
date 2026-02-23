"""Parse nettop output for per-process traffic statistics."""

import subprocess


def collect():
    """Run nettop and return per-process traffic stats.

    Returns a dict keyed by PID:
    {
        pid: {
            "name": str,
            "bytes_in": int,
            "bytes_out": int,
            "rx_dupe": int,
            "rx_ooo": int,
            "re_tx": int,
        }
    }
    """
    try:
        # Use default format: time,,interface,state,bytes_in,bytes_out,rx_dupe,rx_ooo,re-tx,...
        # The second field is "name.PID"
        result = subprocess.run(
            ["nettop", "-L", "1", "-P", "-n", "-x"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}

    if len(lines) < 2:
        return {}

    stats = {}
    for line in lines[1:]:  # skip header
        parsed = _parse_line(line)
        if parsed:
            stats[parsed["pid"]] = parsed

    return stats


def _parse_line(line):
    """Parse a single nettop output line.

    Default format columns:
    0: time
    1: name.PID
    2: (empty - interface)
    3: (empty - state)
    4: bytes_in
    5: bytes_out
    6: rx_dupe
    7: rx_ooo
    8: re-tx
    """
    parts = line.split(",")
    if len(parts) < 9:
        return None

    # Second field is "name.PID"
    name_pid = parts[1]
    dot_idx = name_pid.rfind(".")
    if dot_idx == -1:
        return None

    name = name_pid[:dot_idx].strip()
    pid_str = name_pid[dot_idx + 1:]

    try:
        pid = int(pid_str)
    except ValueError:
        return None

    def safe_int(s):
        try:
            return int(s)
        except (ValueError, TypeError):
            return 0

    return {
        "pid": pid,
        "name": name,
        "bytes_in": safe_int(parts[4]),
        "bytes_out": safe_int(parts[5]),
        "rx_dupe": safe_int(parts[6]),
        "rx_ooo": safe_int(parts[7]),
        "re_tx": safe_int(parts[8]),
    }
