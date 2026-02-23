"""Parse lsof -i output to get all open network connections."""

import re
import subprocess


def collect():
    """Run lsof -i and return parsed connections.

    Returns a list of dicts, each representing one connection:
    {
        "app": str,
        "pid": int,
        "user": str,
        "fd": str,
        "type": str (IPv4/IPv6),
        "protocol": str (TCP/UDP),
        "local_addr": str,
        "local_port": int or None,
        "remote_addr": str or None,
        "remote_port": int or None,
        "state": str or None,
    }
    """
    try:
        result = subprocess.run(
            ["lsof", "-i", "-n", "-P"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if len(lines) < 2:
        return []

    connections = []
    for line in lines[1:]:  # skip header
        parsed = _parse_line(line)
        if parsed:
            connections.append(parsed)

    return connections


def _parse_line(line):
    """Parse a single lsof output line."""
    # lsof output is whitespace-delimited but command names can have spaces
    # Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    parts = line.split()
    if len(parts) < 9:
        return None

    # The NAME field (and potentially STATE) is at the end
    # We need to find NODE (TCP/UDP) and NAME
    # Work backwards from the end
    state = None
    name_str = parts[-1]

    # Check if last field is a state like (ESTABLISHED)
    if name_str.startswith("(") and name_str.endswith(")"):
        state = name_str[1:-1]
        name_str = parts[-2]
        node = parts[-3]
        # Everything before node_idx is COMMAND + PID + USER + FD + TYPE + DEVICE + SIZE/OFF
    else:
        node = parts[-2]

    # Find PID (first numeric field after command)
    pid = None
    pid_idx = None
    for i, p in enumerate(parts):
        if p.isdigit() and i > 0:
            pid = int(p)
            pid_idx = i
            break

    if pid is None:
        return None

    # Command is everything before PID
    app = " ".join(parts[:pid_idx])
    # Clean up escaped spaces in app name
    app = app.replace("\\x20", " ").strip()

    # User is right after PID
    user = parts[pid_idx + 1] if pid_idx + 1 < len(parts) else ""

    # FD
    fd = parts[pid_idx + 2] if pid_idx + 2 < len(parts) else ""

    # TYPE (IPv4/IPv6)
    addr_type = parts[pid_idx + 3] if pid_idx + 3 < len(parts) else ""

    # Protocol from NODE field
    protocol = node if node in ("TCP", "UDP") else ""

    # Parse NAME field: local->remote or just local
    local_addr, local_port = None, None
    remote_addr, remote_port = None, None

    if "->" in name_str:
        local_part, remote_part = name_str.split("->", 1)
        local_addr, local_port = _parse_endpoint(local_part)
        remote_addr, remote_port = _parse_endpoint(remote_part)
    else:
        local_addr, local_port = _parse_endpoint(name_str)

    return {
        "app": app,
        "pid": pid,
        "user": user,
        "fd": fd,
        "type": addr_type,
        "protocol": protocol,
        "local_addr": local_addr,
        "local_port": local_port,
        "remote_addr": remote_addr,
        "remote_port": remote_port,
        "state": state,
    }


def _parse_endpoint(endpoint_str):
    """Parse an endpoint string like '10.14.0.2:443' or '[::1]:80' or '*:*'."""
    if not endpoint_str:
        return None, None

    # Handle IPv6 in brackets: [addr]:port
    if endpoint_str.startswith("["):
        match = re.match(r'\[([^\]]+)\]:(\d+|\*)', endpoint_str)
        if match:
            addr = match.group(1)
            port_str = match.group(2)
            port = int(port_str) if port_str != "*" else None
            return addr, port

    # Handle regular addr:port (split on last colon)
    last_colon = endpoint_str.rfind(":")
    if last_colon == -1:
        return endpoint_str, None

    addr = endpoint_str[:last_colon]
    port_str = endpoint_str[last_colon + 1:]
    port = int(port_str) if port_str != "*" and port_str.isdigit() else None

    return addr, port
