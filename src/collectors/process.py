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
                "command": "",  # populated below from ps args
                "lstart": lstart, "etime": etime,
            }
        except (ValueError, IndexError):
            continue

    # Collect full command lines (with arguments) via a separate ps call
    try:
        args_result = subprocess.run(
            ["ps", "-eo", "pid,args"],
            capture_output=True, text=True, timeout=5
        )
        for line in args_result.stdout.strip().split("\n")[1:]:
            parts = line.strip().split(None, 1)
            if len(parts) >= 2:
                try:
                    pid = int(parts[0])
                    if pid in info:
                        info[pid]["command"] = parts[1]
                except (ValueError, IndexError):
                    continue
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return info


def collect_process_detail(pid):
    """Collect comprehensive details for a single process (on-demand).

    Returns dict with extended process info including parent chain,
    working directory, thread count, open files, etc.
    """
    detail = {
        "pid": pid,
        "ppid": None,
        "parent_command": "",
        "parent_chain": [],
        "user": "",
        "cwd": "",
        "nice": None,
        "priority": None,
        "rss": 0,
        "rss_fmt": "",
        "vsz": 0,
        "vsz_fmt": "",
        "state": "",
        "pgid": None,
        "thread_count": 0,
        "open_files": [],
        "open_files_count": 0,
        "loaded_libs_count": 0,
    }

    # Extended ps info for this PID
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "ppid,pgid,uid,user,nice,pri,rss,vsz,stat"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 9:
                detail["ppid"] = int(parts[0])
                detail["pgid"] = int(parts[1])
                detail["user"] = parts[3]
                detail["nice"] = int(parts[4])
                detail["priority"] = int(parts[5])
                detail["rss"] = int(parts[6])
                detail["rss_fmt"] = _format_kb(int(parts[6]))
                detail["vsz"] = int(parts[7])
                detail["vsz_fmt"] = _format_kb(int(parts[7]))
                detail["state"] = _decode_state(parts[8])
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, IndexError):
        pass

    # Parent process chain (walk up to 4 levels)
    current_ppid = detail["ppid"]
    for _ in range(4):
        if not current_ppid or current_ppid <= 1:
            break
        try:
            result = subprocess.run(
                ["ps", "-p", str(current_ppid), "-o", "ppid,comm,args"],
                capture_output=True, text=True, timeout=3
            )
            lines = result.stdout.strip().split("\n")
            if len(lines) >= 2:
                parts = lines[1].strip().split(None, 2)
                if len(parts) >= 2:
                    name = parts[1].rsplit("/", 1)[-1]
                    cmd = parts[2] if len(parts) > 2 else name
                    detail["parent_chain"].append({
                        "pid": current_ppid,
                        "name": name,
                        "command": cmd,
                    })
                    if not detail["parent_command"]:
                        detail["parent_command"] = cmd
                    current_ppid = int(parts[0])
                else:
                    break
            else:
                break
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError, IndexError):
            break

    # Working directory via lsof
    try:
        result = subprocess.run(
            ["lsof", "-p", str(pid), "-a", "-d", "cwd", "-F", "n"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().split("\n"):
            if line.startswith("n") and len(line) > 1:
                detail["cwd"] = line[1:]
                break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Thread count via ps -M
    try:
        result = subprocess.run(
            ["ps", "-M", "-p", str(pid)],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        detail["thread_count"] = max(0, len(lines) - 1)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Open files via lsof (categorize them)
    try:
        result = subprocess.run(
            ["lsof", "-p", str(pid), "-F", "tn"],
            capture_output=True, text=True, timeout=5
        )
        files = []
        libs_count = 0
        current_type = ""
        for line in result.stdout.strip().split("\n"):
            if line.startswith("t"):
                current_type = line[1:]
            elif line.startswith("n") and len(line) > 1:
                name = line[1:]
                if name.endswith(".dylib") or "/Frameworks/" in name:
                    libs_count += 1
                elif current_type == "REG" and not name.startswith("/dev/"):
                    files.append(name)

        detail["open_files"] = files[:50]  # cap at 50 to avoid huge payloads
        detail["open_files_count"] = len(files)
        detail["loaded_libs_count"] = libs_count
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return detail


def _format_kb(kb):
    """Format kilobytes to human-readable string."""
    if kb < 1024:
        return f"{kb} KB"
    elif kb < 1024 * 1024:
        return f"{kb / 1024:.1f} MB"
    else:
        return f"{kb / (1024 * 1024):.2f} GB"


def _decode_state(stat_str):
    """Decode ps STAT column to human-readable state."""
    if not stat_str:
        return ""
    codes = {
        "R": "Running",
        "S": "Sleeping",
        "T": "Stopped",
        "U": "Uninterruptible",
        "Z": "Zombie",
        "I": "Idle",
    }
    primary = codes.get(stat_str[0], stat_str[0])
    extras = []
    for ch in stat_str[1:]:
        if ch == "s":
            extras.append("session leader")
        elif ch == "+":
            extras.append("foreground")
        elif ch == "N":
            extras.append("low priority")
        elif ch == "<":
            extras.append("high priority")
    if extras:
        return f"{primary} ({', '.join(extras)})"
    return primary


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
