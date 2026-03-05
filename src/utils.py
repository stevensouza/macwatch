"""Utility functions for NetWatch."""

import os

# Interpreter binary names — when the process binary is one of these,
# we extract the actual script/module name from the command line.
_INTERPRETERS = {
    "python", "python2", "python3",
    *(f"python3.{v}" for v in range(8, 20)),
    "java", "node", "nodejs",
    "ruby", "perl", "php",
    "bash", "sh", "zsh", "fish",
    "Rscript", "dotnet", "mono",
}

# Java flags that consume the next token as a value (not the main class).
_JAVA_VALUE_FLAGS = {"-cp", "-classpath", "-p", "--module-path", "-d"}

# Extensions to strip from displayed script names.
_STRIP_EXTENSIONS = {".py", ".js", ".ts", ".rb", ".pl", ".php", ".sh", ".jar"}


def friendly_process_name(binary_name, command):
    """Return a human-friendly display name for a process.

    For interpreted languages (python, java, node, etc.), extracts the
    script or module name from the full command line.  Native binaries
    are returned unchanged.

    Returns (display_name, is_renamed) — is_renamed is True when the
    display_name differs from binary_name.
    """
    base = os.path.basename(binary_name) if binary_name else ""
    if not base or base not in _INTERPRETERS or not command:
        return binary_name, False

    tokens = command.split()
    if len(tokens) < 2:
        return binary_name, False

    # Special handling for python -m <module>
    if base.startswith("python") and "-m" in tokens:
        idx = tokens.index("-m")
        if idx + 1 < len(tokens):
            module = tokens[idx + 1]
            # e.g. "flask" or "mypackage.submod" → last segment
            name = module.rsplit(".", 1)[-1]
            return name, name != base

    # Special handling for java -jar <file> and java <classname>
    if base == "java":
        return _parse_java_command(tokens, base)

    # General: find first non-flag argument after the interpreter
    return _parse_script_command(tokens, base)


def _parse_java_command(tokens, base):
    """Extract display name from a java command line."""
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok == "-jar" and i + 1 < len(tokens):
            jar = os.path.basename(tokens[i + 1])
            return jar, jar != base
        if tok in _JAVA_VALUE_FLAGS and i + 1 < len(tokens):
            i += 2  # skip flag and its value
            continue
        if tok.startswith("-"):
            i += 1
            continue
        # First non-flag token — could be a class name like com.example.MyApp
        if "." in tok and not tok.endswith(tuple(_STRIP_EXTENSIONS)):
            name = tok.rsplit(".", 1)[-1]
            return name, name != base
        name = os.path.basename(tok)
        return name, name != base
    return base, False


def _parse_script_command(tokens, base):
    """Extract display name from a script interpreter command line."""
    for tok in tokens[1:]:
        if tok.startswith("-"):
            continue
        name = os.path.basename(tok)
        return name, name != base
    return base, False


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
    from src.config import STANDARD_PORTS
    return STANDARD_PORTS.get(port, "")
