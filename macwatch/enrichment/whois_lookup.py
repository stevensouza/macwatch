"""Whois lookups with caching."""

import re
import subprocess
import threading
import time

from macwatch.config import WHOIS_CACHE_TTL

_cache = {}
_lock = threading.Lock()


def lookup(ip):
    """Look up whois info for an IP. Returns dict with org, country, etc."""
    if not ip or ip in ("*", "127.0.0.1", "::1") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return {"org": "Private", "country": "", "city": "", "cidr": "", "netname": ""}

    with _lock:
        if ip in _cache:
            info, timestamp = _cache[ip]
            if time.time() - timestamp < WHOIS_CACHE_TTL:
                return info

    info = _run_whois(ip)

    with _lock:
        _cache[ip] = (info, time.time())

    return info


def _run_whois(ip):
    """Run whois command and parse the output."""
    try:
        result = subprocess.run(
            ["whois", ip],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"org": "", "country": "", "city": "", "cidr": "", "netname": ""}

    info = {"org": "", "country": "", "city": "", "cidr": "", "netname": ""}

    for line in output.split("\n"):
        line_lower = line.lower().strip()
        if not line_lower or line_lower.startswith("#") or line_lower.startswith("%"):
            continue

        # Organization name (various formats)
        if not info["org"]:
            if line_lower.startswith("orgname:"):
                info["org"] = line.split(":", 1)[1].strip()
            elif line_lower.startswith("org-name:"):
                info["org"] = line.split(":", 1)[1].strip()
            elif line_lower.startswith("descr:"):
                info["org"] = line.split(":", 1)[1].strip()

        # Country
        if not info["country"] and line_lower.startswith("country:"):
            info["country"] = line.split(":", 1)[1].strip().upper()

        # City
        if not info["city"] and line_lower.startswith("city:"):
            info["city"] = line.split(":", 1)[1].strip()

        # CIDR
        if not info["cidr"] and line_lower.startswith("cidr:"):
            info["cidr"] = line.split(":", 1)[1].strip()

        # Network name
        if not info["netname"]:
            if line_lower.startswith("netname:"):
                info["netname"] = line.split(":", 1)[1].strip()

    return info


def get_cache_info():
    """Return cache stats."""
    with _lock:
        return {"size": len(_cache), "ttl": WHOIS_CACHE_TTL}


def clear_cache():
    """Clear the whois cache."""
    with _lock:
        _cache.clear()
