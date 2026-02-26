"""Collect process info: CPU, memory, path, code signing."""

import subprocess
import threading

# Cache codesign results (they don't change per binary)
_codesign_cache = {}
_codesign_lock = threading.Lock()


def collect_ps():
    """Run ps and return process info keyed by PID.

    Returns:
    {
        pid: {
            "cpu": float,
            "mem": float,
            "path": str,
            "lstart": str,   # e.g. "Mon Feb 16 15:44:11 2026"
            "etime": str,    # e.g. "09-20:52:44"
        }
    }
    """
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,pcpu,pmem,lstart,etime,comm"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}

    info = {}
    for line in lines[1:]:  # skip header
        # lstart is 5 tokens (e.g. "Mon Feb 16 15:44:11 2026"), then etime, then comm
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        try:
            pid = int(parts[0])
            cpu = float(parts[1])
            mem = float(parts[2])
            lstart = f"{parts[3]} {parts[4]} {parts[5]} {parts[6]} {parts[7]}"
            # parts[8] is "etime comm..." — etime never contains spaces
            rest = parts[8].split(None, 1)
            etime = rest[0] if rest else ""
            path = rest[1].strip() if len(rest) > 1 else ""
            info[pid] = {
                "cpu": cpu, "mem": mem, "path": path,
                "lstart": lstart, "etime": etime,
            }
        except (ValueError, IndexError):
            continue

    return info


def check_codesign(app_path):
    """Check code signing status for an application binary.

    Returns:
    {
        "signed": bool,
        "authority": str or None,
        "team_id": str or None,
        "identifier": str or None,
    }
    """
    if not app_path:
        return {"signed": False, "authority": None, "team_id": None, "identifier": None}

    with _codesign_lock:
        if app_path in _codesign_cache:
            return _codesign_cache[app_path]

    # Find the .app bundle from the binary path
    bundle_path = _find_app_bundle(app_path)
    target = bundle_path or app_path

    try:
        result = subprocess.run(
            ["codesign", "-dvvv", target],
            capture_output=True, text=True, timeout=5
        )
        output = result.stderr  # codesign writes to stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"signed": False, "authority": None, "team_id": None, "identifier": None}

    info = {
        "signed": ("valid on disk" in output or "Authority=" in output
                   or "Identifier=" in output or "CodeDirectory" in output),
        "authority": None,
        "team_id": None,
        "identifier": None,
    }

    for line in output.split("\n"):
        if line.startswith("Authority=") and info["authority"] is None:
            info["authority"] = line.split("=", 1)[1]
        elif line.startswith("TeamIdentifier="):
            info["team_id"] = line.split("=", 1)[1]
        elif line.startswith("Identifier="):
            info["identifier"] = line.split("=", 1)[1]

    with _codesign_lock:
        _codesign_cache[app_path] = info

    return info


def _find_app_bundle(path):
    """Extract the .app bundle path from a full binary path.

    Only matches actual macOS .app bundles (typically under /Applications
    or containing /Contents/). Avoids false matches like 'com.example.app/'.
    """
    if not path:
        return None
    # Look for .app/Contents which is the definitive .app bundle indicator
    idx = path.find(".app/Contents/")
    if idx != -1:
        return path[:idx + 4]
    if path.endswith(".app"):
        return path
    return None
