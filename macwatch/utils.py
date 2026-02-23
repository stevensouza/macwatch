"""Utility functions for NetWatch."""


def format_bytes(num_bytes):
    """Format byte count to human-readable string with appropriate units."""
    if num_bytes is None:
        return "—"
    num_bytes = int(num_bytes)
    if num_bytes < 1024:
        return f"{num_bytes} B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f} KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"


def port_label(port):
    """Return a human-readable label for common ports."""
    from macwatch.config import STANDARD_PORTS
    return STANDARD_PORTS.get(port, "")
