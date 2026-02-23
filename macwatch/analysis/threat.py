"""Threat scoring engine for NetWatch."""

from macwatch.config import (
    STANDARD_PORTS, VPS_PROVIDERS, CLOUD_PROVIDERS, SYSTEM_DAEMONS,
    THREAT_WEIGHTS, UPLOAD_RATIO_THRESHOLD, UPLOAD_MINIMUM_BYTES,
    RETRANSMISSION_THRESHOLD, UNIQUE_IP_THRESHOLD, SCORE_LEVELS,
)


def score_app(app_data):
    """Calculate threat score for an application.

    Args:
        app_data: dict with keys:
            - app: str (app name)
            - signed: bool
            - connections: list of connection dicts
            - bytes_in: int
            - bytes_out: int
            - re_tx: int
            - unique_ips: set of remote IPs

    Returns:
        dict with "score", "level", "color", "flags" list
    """
    flags = []

    # Red: Unsigned app
    if not app_data.get("signed", True):
        flags.append({
            "type": "unsigned_app",
            "severity": "red",
            "weight": THREAT_WEIGHTS["unsigned_app"],
            "description": "Application has no valid code signature",
        })

    # Red: High upload ratio
    bytes_in = app_data.get("bytes_in", 0)
    bytes_out = app_data.get("bytes_out", 0)
    if (bytes_out > UPLOAD_MINIMUM_BYTES and bytes_in > 0
            and bytes_out > UPLOAD_RATIO_THRESHOLD * bytes_in):
        ratio = bytes_out / bytes_in if bytes_in > 0 else float("inf")
        flags.append({
            "type": "high_upload_ratio",
            "severity": "red",
            "weight": THREAT_WEIGHTS["high_upload_ratio"],
            "description": f"Upload ratio {ratio:.0f}:1 (sending {ratio:.0f}x more than receiving)",
        })

    # Check each connection
    for conn in app_data.get("connections", []):
        conn_flags = score_connection(conn, app_data)
        flags.extend(conn_flags)

    # Blue: Many unique IPs
    unique_ips = app_data.get("unique_ips", set())
    if len(unique_ips) > UNIQUE_IP_THRESHOLD:
        flags.append({
            "type": "many_unique_ips",
            "severity": "blue",
            "weight": THREAT_WEIGHTS["many_unique_ips"],
            "description": f"Connected to {len(unique_ips)} unique remote IPs",
        })

    # Blue: High retransmissions
    if app_data.get("re_tx", 0) > RETRANSMISSION_THRESHOLD:
        flags.append({
            "type": "high_retransmissions",
            "severity": "blue",
            "weight": THREAT_WEIGHTS["high_retransmissions"],
            "description": f"{app_data['re_tx']} retransmissions (network quality issue)",
        })

    total_score = sum(f["weight"] for f in flags)
    level, color = _score_to_level(total_score)

    return {
        "score": total_score,
        "level": level,
        "color": color,
        "flags": flags,
    }


def score_connection(conn, app_data):
    """Score an individual connection. Returns list of flags."""
    flags = []
    remote_port = conn.get("remote_port")
    state = conn.get("state")

    # Red: HTTP plaintext
    if remote_port == 80 and state == "ESTABLISHED":
        flags.append({
            "type": "http_plaintext",
            "severity": "red",
            "weight": THREAT_WEIGHTS["http_plaintext"],
            "description": "Plaintext HTTP — data transmitted without encryption",
            "connection": _conn_summary(conn),
        })

    # Yellow: Unusual port
    if (remote_port and remote_port not in STANDARD_PORTS
            and state == "ESTABLISHED"):
        flags.append({
            "type": "unusual_port",
            "severity": "yellow",
            "weight": THREAT_WEIGHTS["unusual_port"],
            "description": f"Non-standard port {remote_port}",
            "connection": _conn_summary(conn),
        })

    # Yellow: No reverse DNS
    if conn.get("remote_addr") and not conn.get("hostname"):
        addr = conn["remote_addr"]
        if not _is_private(addr):
            flags.append({
                "type": "no_rdns",
                "severity": "yellow",
                "weight": THREAT_WEIGHTS["no_rdns"],
                "description": f"No reverse DNS for {addr}",
                "connection": _conn_summary(conn),
            })

    # Yellow: VPS provider
    whois_org = (conn.get("whois_org") or "").lower()
    if whois_org:
        for provider in VPS_PROVIDERS:
            if provider in whois_org:
                flags.append({
                    "type": "vps_provider",
                    "severity": "yellow",
                    "weight": THREAT_WEIGHTS["vps_provider"],
                    "description": f"IP belongs to hosting provider ({conn.get('whois_org', '')})",
                    "connection": _conn_summary(conn),
                })
                break

    # Yellow: System daemon external connection
    app_name = app_data.get("app", "").lower()
    if app_name in SYSTEM_DAEMONS and conn.get("remote_addr"):
        if not _is_private(conn["remote_addr"]):
            flags.append({
                "type": "system_daemon_external",
                "severity": "yellow",
                "weight": THREAT_WEIGHTS["system_daemon_external"],
                "description": f"System daemon '{app_data['app']}' connecting externally",
                "connection": _conn_summary(conn),
            })

    # Blue: LISTEN on all interfaces
    if state == "LISTEN" and conn.get("local_addr") in ("*", "0.0.0.0", "::"):
        flags.append({
            "type": "listen_all_interfaces",
            "severity": "blue",
            "weight": THREAT_WEIGHTS["listen_all_interfaces"],
            "description": f"Listening on all interfaces (port {conn.get('local_port')})",
            "connection": _conn_summary(conn),
        })

    return flags


def _score_to_level(score):
    """Convert numeric score to level name and color."""
    if score == 0:
        return "clean", "green"
    elif score <= 2:
        return "low", "yellow"
    elif score <= 5:
        return "medium", "orange"
    else:
        return "high", "red"


def _is_private(addr):
    """Check if an address is private/local."""
    if not addr:
        return True
    return (addr.startswith("10.") or addr.startswith("192.168.")
            or addr.startswith("172.") or addr.startswith("127.")
            or addr in ("*", "::1", "localhost"))


def _conn_summary(conn):
    """Create a short summary string for a connection."""
    remote = conn.get("remote_addr", "?")
    port = conn.get("remote_port", "?")
    return f"{remote}:{port}"
