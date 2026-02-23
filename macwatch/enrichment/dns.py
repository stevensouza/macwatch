"""Reverse DNS lookups with caching."""

import socket
import threading
import time

from macwatch.config import DNS_CACHE_TTL

_cache = {}
_lock = threading.Lock()


def reverse_lookup(ip):
    """Look up the hostname for an IP address. Returns hostname or None."""
    if not ip or ip in ("*", "127.0.0.1", "::1"):
        return ip

    with _lock:
        if ip in _cache:
            hostname, timestamp = _cache[ip]
            if time.time() - timestamp < DNS_CACHE_TTL:
                return hostname

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        hostname = None

    with _lock:
        _cache[ip] = (hostname, time.time())

    return hostname


def get_cache_info():
    """Return cache stats."""
    with _lock:
        return {"size": len(_cache), "ttl": DNS_CACHE_TTL}


def clear_cache():
    """Clear the DNS cache."""
    with _lock:
        _cache.clear()
