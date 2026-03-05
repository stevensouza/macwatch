"""Collect system-wide resource stats: CPU, memory, disk."""

import re
import subprocess

from src.utils import format_bytes


def collect_system_stats():
    """Return system-wide CPU, memory, and disk usage.

    Returns:
    {
        "cpu_percent": float,
        "load_avg_1": float,
        "load_avg_5": float,
        "load_avg_15": float,
        "mem_total": int,
        "mem_used": int,
        "mem_percent": float,
        "mem_total_fmt": str,
        "mem_used_fmt": str,
        "disk_total": int,
        "disk_used": int,
        "disk_percent": float,
        "disk_total_fmt": str,
        "disk_used_fmt": str,
    }
    """
    stats = {
        "cpu_percent": 0.0,
        "load_avg_1": 0.0,
        "load_avg_5": 0.0,
        "load_avg_15": 0.0,
        "mem_total": 0,
        "mem_used": 0,
        "mem_percent": 0.0,
        "mem_total_fmt": "—",
        "mem_used_fmt": "—",
        "disk_total": 0,
        "disk_used": 0,
        "disk_percent": 0.0,
        "disk_total_fmt": "—",
        "disk_used_fmt": "—",
    }

    _collect_cpu(stats)
    _collect_memory(stats)
    _collect_disk(stats)

    return stats


def _collect_cpu(stats):
    """Parse `top -l 1 -n 0 -s 0` for CPU usage and load averages."""
    try:
        result = subprocess.run(
            ["top", "-l", "1", "-n", "0", "-s", "0"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.split("\n"):
            if line.startswith("CPU usage:"):
                # "CPU usage: 15.51% user, 19.73% sys, 64.75% idle"
                m = re.findall(r"([\d.]+)%\s+(user|sys|idle)", line)
                user = sys_pct = 0.0
                for val, label in m:
                    if label == "user":
                        user = float(val)
                    elif label == "sys":
                        sys_pct = float(val)
                stats["cpu_percent"] = round(user + sys_pct, 1)
            elif line.startswith("Load Avg:"):
                # "Load Avg: 3.42, 3.18, 3.05"
                parts = line.split(":")[1].strip().split(",")
                if len(parts) >= 3:
                    stats["load_avg_1"] = float(parts[0].strip())
                    stats["load_avg_5"] = float(parts[1].strip())
                    stats["load_avg_15"] = float(parts[2].strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass


def _collect_memory(stats):
    """Use sysctl + vm_stat for memory usage."""
    try:
        # Total physical RAM
        result = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],
            capture_output=True, text=True, timeout=5
        )
        total = int(result.stdout.strip())
        stats["mem_total"] = total
        stats["mem_total_fmt"] = format_bytes(total)

        # Page breakdown from vm_stat
        result = subprocess.run(
            ["vm_stat"],
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout

        # Parse page size from first line
        page_size = 4096
        m = re.search(r"page size of (\d+) bytes", output)
        if m:
            page_size = int(m.group(1))

        pages = {}
        for line in output.split("\n"):
            m = re.match(r'^(.+?):\s+([\d]+)\.', line)
            if m:
                key = m.group(1).strip().lower()
                pages[key] = int(m.group(2))

        # Used = (active + wired + speculative + compressor) * page_size
        active = pages.get("pages active", 0)
        wired = pages.get("pages wired down", 0)
        speculative = pages.get("pages speculative", 0)
        compressor = pages.get("pages occupied by compressor", 0)
        used = (active + wired + speculative + compressor) * page_size

        stats["mem_used"] = used
        stats["mem_used_fmt"] = format_bytes(used)
        stats["mem_percent"] = round(used / total * 100, 1) if total else 0.0

    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass


def _collect_disk(stats):
    """Parse `df -k /` for root volume usage."""
    try:
        result = subprocess.run(
            ["df", "-k", "/"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.strip().split("\n")
        if len(lines) >= 2:
            parts = lines[1].split()
            if len(parts) >= 4:
                # df -k reports in 1K blocks
                total = int(parts[1]) * 1024
                used = int(parts[2]) * 1024
                stats["disk_total"] = total
                stats["disk_used"] = used
                stats["disk_percent"] = round(used / total * 100, 1) if total else 0.0
                stats["disk_total_fmt"] = format_bytes(total)
                stats["disk_used_fmt"] = format_bytes(used)
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass
