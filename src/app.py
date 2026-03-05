"""MacWatch Flask application — main entry point."""

import json
import os
import signal
import threading
from collections import defaultdict

from flask import Flask, jsonify, render_template, request

from src.collectors import lsof, nettop, process, system
from src.enrichment import dns, whois_lookup
from src.analysis import threat, alert_info, ai_analyzer
from src.utils import format_bytes, port_label, friendly_process_name
from src.config import (
    HOST, PORT, STANDARD_PORTS, AI_DEFAULT_PROVIDER, TOP_PROCESSES_COUNT,
    SYSTEM_CPU_HIGH, SYSTEM_CPU_CRITICAL,
    SYSTEM_MEMORY_HIGH, SYSTEM_MEMORY_CRITICAL,
    SYSTEM_DISK_HIGH, SYSTEM_DISK_CRITICAL,
)

app = Flask(__name__)

# Track previously seen hosts per app for new-connection alerts
_seen_hosts = defaultdict(set)
_seen_hosts_lock = threading.Lock()

# Cache known PIDs for kill validation (avoids re-collecting data)
_known_pids = set()
_known_pids_lock = threading.Lock()


def _build_dashboard_data(full_processes=False):
    """Collect all data and build the full dashboard payload."""
    # Collect raw data
    connections = lsof.collect()
    traffic_stats = nettop.collect()
    ps_info = process.collect_ps()

    # Group connections by app (using PID as key to distinguish same-name apps)
    apps = defaultdict(lambda: {
        "app": "",
        "pid": 0,
        "connections": [],
        "bytes_in": 0,
        "bytes_out": 0,
        "re_tx": 0,
        "rx_dupe": 0,
        "rx_ooo": 0,
        "cpu": 0.0,
        "mem": 0.0,
        "path": "",
        "signed": True,
        "sign_authority": "",
        "unique_ips": set(),
    })

    for conn in connections:
        # Skip connections with no remote endpoint and no state (e.g., UDP
        # sockets with only a local address) — they add no useful info.
        if not conn.get("remote_addr") and not conn.get("remote_port") and not conn.get("state"):
            continue

        pid = conn["pid"]
        app_key = f"{conn['app']}:{pid}"
        app_data = apps[app_key]
        app_data["app"] = conn["app"]
        app_data["pid"] = pid

        # Enrich with DNS (skip for private/local IPs)
        remote_addr = conn.get("remote_addr")
        if remote_addr and not _is_private(remote_addr):
            hostname = dns.reverse_lookup(remote_addr)
            conn["hostname"] = hostname
            app_data["unique_ips"].add(remote_addr)

            # Lazy whois (only for display, not blocking)
            whois_info = whois_lookup.lookup(remote_addr)
            conn["whois_org"] = whois_info.get("org", "")
            conn["whois_country"] = whois_info.get("country", "")
        else:
            conn["hostname"] = remote_addr
            conn["whois_org"] = "Private" if remote_addr else ""
            conn["whois_country"] = ""

        conn["port_label"] = port_label(conn.get("remote_port", 0) or 0)
        app_data["connections"].append(conn)

    # Merge traffic stats and process info
    for app_key, app_data in apps.items():
        pid = app_data["pid"]
        if pid in traffic_stats:
            ts = traffic_stats[pid]
            app_data["bytes_in"] = ts["bytes_in"]
            app_data["bytes_out"] = ts["bytes_out"]
            app_data["re_tx"] = ts["re_tx"]
            app_data["rx_dupe"] = ts["rx_dupe"]
            app_data["rx_ooo"] = ts["rx_ooo"]

        if pid in ps_info:
            pi = ps_info[pid]
            app_data["cpu"] = pi["cpu"]
            app_data["mem"] = pi["mem"]
            app_data["path"] = pi["path"]
            app_data["command"] = pi.get("command", "")
            app_data["lstart"] = pi.get("lstart", "")
            app_data["etime"] = pi.get("etime", "")
            display_name, _ = friendly_process_name(
                app_data["app"], pi.get("command", ""))
            app_data["display_name"] = display_name
            codesign_info = process.check_codesign(pi["path"])
            app_data["signed"] = codesign_info["signed"]
            app_data["sign_authority"] = codesign_info.get("authority", "")
            app_data["codesign_info"] = codesign_info

    # Score each app
    app_list = []
    all_alerts = []

    for app_key, app_data in apps.items():
        threat_result = threat.score_app(app_data)
        app_data["threat"] = threat_result

        # Check for new connections
        new_connections = _check_new_connections(app_data)

        # Build serializable app dict
        codesign = app_data.get("codesign_info", {})
        app_dict = {
            "app": app_data["app"],
            "display_name": app_data.get("display_name", app_data["app"]),
            "pid": app_data["pid"],
            "connection_count": len(app_data["connections"]),
            "bytes_in": app_data["bytes_in"],
            "bytes_in_fmt": format_bytes(app_data["bytes_in"]),
            "bytes_out": app_data["bytes_out"],
            "bytes_out_fmt": format_bytes(app_data["bytes_out"]),
            "re_tx": app_data["re_tx"],
            "cpu": app_data["cpu"],
            "mem": app_data["mem"],
            "path": app_data["path"],
            "command": app_data.get("command", ""),
            "lstart": app_data.get("lstart", ""),
            "etime": app_data.get("etime", ""),
            "signed": app_data["signed"],
            "sign_authority": app_data["sign_authority"],
            "team_id": codesign.get("team_id", ""),
            "identifier": codesign.get("identifier", ""),
            "threat_score": threat_result["score"],
            "threat_level": threat_result["level"],
            "threat_color": threat_result["color"],
            "threat_flags": threat_result["flags"],
            "connections": [
                {
                    "remote_host": c.get("hostname") or "(no rDNS)",
                    "remote_addr": c.get("remote_addr", ""),
                    "remote_port": c.get("remote_port"),
                    "port_label": c.get("port_label", ""),
                    "local_addr": c.get("local_addr", ""),
                    "local_port": c.get("local_port"),
                    "protocol": c.get("protocol", ""),
                    "state": c.get("state", ""),
                    "type": c.get("type", ""),
                    "whois_org": c.get("whois_org", ""),
                    "whois_country": c.get("whois_country", ""),
                    "flags": _connection_flags(c, threat_result),
                }
                for c in app_data["connections"]
            ],
            "new_connections": new_connections,
        }
        app_list.append(app_dict)

        # Build alerts from flags
        for flag in threat_result["flags"]:
            all_alerts.append({
                "app": app_data["app"],
                "pid": app_data["pid"],
                "severity": flag["severity"],
                "type": flag["type"],
                "category": flag.get("category", "network"),
                "description": flag["description"],
                "connection": flag.get("connection", ""),
            })

        # Add new connection alerts
        for nc in new_connections:
            all_alerts.append({
                "app": app_data["app"],
                "pid": app_data["pid"],
                "severity": "info",
                "type": "new_connection",
                "category": "network",
                "description": f"New connection to {nc}",
                "connection": nc,
            })

    # Generate system-wide resource alerts
    sys_stats = system.collect_system_stats()
    _add_system_alerts(all_alerts, sys_stats)

    # Sort apps by threat score (highest first), then by name
    app_list.sort(key=lambda a: (-a["threat_score"], a["app"].lower()))

    # Sort alerts by severity
    severity_order = {"red": 0, "yellow": 1, "blue": 2, "info": 3}
    all_alerts.sort(key=lambda a: severity_order.get(a["severity"], 4))

    # Summary stats
    total_bytes_in = sum(a["bytes_in"] for a in app_list)
    total_bytes_out = sum(a["bytes_out"] for a in app_list)
    total_connections = sum(a["connection_count"] for a in app_list)

    # Build top processes by CPU (all processes, not just network-connected)
    network_pids = {a["pid"] for a in app_list}
    top_procs_raw = [
        {"pid": pid, **info}
        for pid, info in ps_info.items()
        if info["cpu"] > 0.0 and pid > 0
    ]
    top_procs_raw.sort(key=lambda p: p["cpu"], reverse=True)
    if not full_processes:
        top_procs_raw = top_procs_raw[:TOP_PROCESSES_COUNT]

    # Update known PIDs — include all visible PIDs (network + top processes)
    with _known_pids_lock:
        _known_pids.clear()
        _known_pids.update(a["pid"] for a in app_list)
        _known_pids.update(p["pid"] for p in top_procs_raw)

    top_processes = []
    for p in top_procs_raw:
        name = os.path.basename(p["path"]) if p["path"] else str(p["pid"])
        display, _ = friendly_process_name(name, p.get("command", ""))
        top_processes.append({
            "pid": p["pid"],
            "name": name,
            "display_name": display,
            "cpu": p["cpu"],
            "mem": p["mem"],
            "command": p.get("command", ""),
            "path": p.get("path", ""),
            "has_network": p["pid"] in network_pids,
        })

    return {
        "apps": app_list,
        "alerts": all_alerts,
        "top_processes": top_processes,
        "summary": {
            "app_count": len(app_list),
            "connection_count": total_connections,
            "bytes_in": total_bytes_in,
            "bytes_in_fmt": format_bytes(total_bytes_in),
            "bytes_out": total_bytes_out,
            "bytes_out_fmt": format_bytes(total_bytes_out),
            "alert_count": len(all_alerts),
            "red_count": sum(1 for a in all_alerts if a["severity"] == "red"),
            "yellow_count": sum(1 for a in all_alerts if a["severity"] == "yellow"),
            "blue_count": sum(1 for a in all_alerts if a["severity"] == "blue"),
            "network_count": sum(1 for a in all_alerts if a.get("category") == "network"),
            "cpu_count": sum(1 for a in all_alerts if a.get("category") == "cpu"),
            "memory_count": sum(1 for a in all_alerts if a.get("category") == "memory"),
            "disk_count": sum(1 for a in all_alerts if a.get("category") == "disk"),
        },
    }


def _add_system_alerts(alerts, sys_stats):
    """Generate system-wide resource alerts from system stats."""
    cpu = sys_stats.get("cpu_percent", 0)
    mem = sys_stats.get("mem_percent", 0)
    disk = sys_stats.get("disk_percent", 0)

    if cpu >= SYSTEM_CPU_CRITICAL:
        alerts.append({
            "app": "System",
            "pid": 0,
            "severity": "red",
            "type": "system_cpu_critical",
            "category": "cpu",
            "description": f"System CPU at {cpu:.1f}%",
            "connection": "",
        })
    elif cpu >= SYSTEM_CPU_HIGH:
        alerts.append({
            "app": "System",
            "pid": 0,
            "severity": "yellow",
            "type": "system_cpu_high",
            "category": "cpu",
            "description": f"System CPU at {cpu:.1f}%",
            "connection": "",
        })

    mem_used = sys_stats.get("mem_used_fmt", "")
    mem_total = sys_stats.get("mem_total_fmt", "")
    if mem >= SYSTEM_MEMORY_CRITICAL:
        alerts.append({
            "app": "System",
            "pid": 0,
            "severity": "red",
            "type": "system_memory_critical",
            "category": "memory",
            "description": f"System memory at {mem:.1f}% ({mem_used} / {mem_total})",
            "connection": "",
        })
    elif mem >= SYSTEM_MEMORY_HIGH:
        alerts.append({
            "app": "System",
            "pid": 0,
            "severity": "yellow",
            "type": "system_memory_high",
            "category": "memory",
            "description": f"System memory at {mem:.1f}% ({mem_used} / {mem_total})",
            "connection": "",
        })

    disk_used = sys_stats.get("disk_used_fmt", "")
    disk_total = sys_stats.get("disk_total_fmt", "")
    if disk >= SYSTEM_DISK_CRITICAL:
        alerts.append({
            "app": "System",
            "pid": 0,
            "severity": "red",
            "type": "system_disk_critical",
            "category": "disk",
            "description": f"Disk usage at {disk:.1f}% ({disk_used} / {disk_total})",
            "connection": "",
        })
    elif disk >= SYSTEM_DISK_HIGH:
        alerts.append({
            "app": "System",
            "pid": 0,
            "severity": "yellow",
            "type": "system_disk_high",
            "category": "disk",
            "description": f"Disk usage at {disk:.1f}% ({disk_used} / {disk_total})",
            "connection": "",
        })


def _check_new_connections(app_data):
    """Check for new connections to previously unseen hosts."""
    app_name = app_data["app"]
    new_hosts = []

    with _seen_hosts_lock:
        for conn in app_data["connections"]:
            remote = conn.get("remote_addr")
            if remote and not _is_private(remote):
                host_key = f"{remote}:{conn.get('remote_port', '')}"
                if host_key not in _seen_hosts[app_name]:
                    _seen_hosts[app_name].add(host_key)
                    new_hosts.append(host_key)

    return new_hosts


def _connection_flags(conn, threat_result):
    """Get flag info for a specific connection."""
    conn_summary = f"{conn.get('remote_addr', '?')}:{conn.get('remote_port', '?')}"
    return [
        f for f in threat_result["flags"]
        if f.get("connection") == conn_summary
    ]


def _is_private(addr):
    """Check if an address is private/local."""
    if not addr:
        return True
    return (addr.startswith("10.") or addr.startswith("192.168.")
            or addr.startswith("172.") or addr.startswith("127.")
            or addr in ("*", "::1", "localhost"))


# --- Routes ---

@app.route("/")
def dashboard():
    initial_data = _build_dashboard_data()
    system_stats = system.collect_system_stats()
    return render_template("dashboard.html",
                           initial_data=json.dumps(initial_data),
                           system_data=json.dumps(system_stats),
                           active_tab="dashboard")


@app.route("/processes")
def processes_page():
    """Render the processes page."""
    return render_template("processes.html", active_tab="processes")


@app.route("/network")
def network_page():
    """Render the network page."""
    initial_data = _build_dashboard_data()
    return render_template("network.html",
                           initial_data=json.dumps(initial_data),
                           active_tab="network")


@app.route("/api/connections")
def api_connections():
    full = request.args.get("full_processes") == "1"
    data = _build_dashboard_data(full_processes=full)
    return jsonify(data)


@app.route("/api/system")
def api_system():
    """Return system-wide resource stats."""
    return jsonify(system.collect_system_stats())


@app.route("/api/whois/<ip>")
def api_whois(ip):
    info = whois_lookup.lookup(ip)
    return jsonify(info)


@app.route("/api/cache")
def api_cache():
    return jsonify({
        "dns": dns.get_cache_info(),
        "whois": whois_lookup.get_cache_info(),
    })


@app.route("/api/process/<int:pid>")
def api_process_detail(pid):
    """Return comprehensive details for a single process."""
    with _known_pids_lock:
        if pid not in _known_pids:
            return jsonify({"error": "PID not found in active processes"}), 404
    detail = process.collect_process_detail(pid)
    return jsonify(detail)


@app.route("/api/kill/<int:pid>", methods=["POST"])
def api_kill(pid):
    """Kill a process by PID. Only allows killing PIDs seen in the last refresh."""
    with _known_pids_lock:
        if pid not in _known_pids:
            return jsonify({"error": "PID not found in active processes"}), 404
    try:
        os.kill(pid, signal.SIGTERM)
        return jsonify({"status": "ok", "pid": pid, "signal": "SIGTERM"})
    except ProcessLookupError:
        return jsonify({"error": "Process not found"}), 404
    except PermissionError:
        return jsonify({"error": "Permission denied — try running MacWatch with sudo"}), 403


@app.route("/alerts")
def alerts_page():
    """Render the alerts page."""
    return render_template("alerts.html", active_tab="alerts")


@app.route("/analysis")
def analysis_page():
    """Render the AI analysis page."""
    return render_template("analysis.html", active_tab="analysis")


@app.route("/api/alert-info")
def api_alert_info():
    """Return educational info for all alert types."""
    return jsonify(alert_info.get_all_alert_info())


@app.route("/api/ai-config")
def api_ai_config():
    """Return AI provider configuration status (without exposing keys)."""
    return jsonify({
        "providers": ai_analyzer.get_available_providers(),
        "default": AI_DEFAULT_PROVIDER,
    })


@app.route("/api/ai-analyze", methods=["POST"])
def api_ai_analyze():
    """Run AI analysis on current MacWatch data."""
    req_data = request.get_json(silent=True) or {}
    provider_name = req_data.get("provider", AI_DEFAULT_PROVIDER)

    try:
        provider = ai_analyzer.get_provider(provider_name)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if not provider.is_configured():
        env_var_hints = {
            "claude": "ANTHROPIC_API_KEY",
            "claude-web": "CLAUDE_SESSION_KEY and CLAUDE_ORG_ID",
            "openai": "OPENAI_API_KEY",
            "gemini": "GOOGLE_AI_API_KEY",
            "ollama": "(no key needed — ensure Ollama is running locally)",
        }
        hint = env_var_hints.get(provider_name, "the appropriate API key")
        return jsonify({
            "error": f"{provider.provider_name()} is not configured. "
                     f"Set the {hint} environment variable and restart MacWatch.",
            "error_type": "not_configured",
        }), 400

    try:
        # Collect current data
        dashboard_data = _build_dashboard_data()

        # Build prompt and call AI provider
        prompt = ai_analyzer.build_analysis_prompt(dashboard_data)

        result = provider.analyze(prompt)
        result["provider"] = provider.provider_name()
        return jsonify(result)
    except Exception as e:
        error_message = str(e)
        if isinstance(e, PermissionError):
            return jsonify({
                "error": str(e),
                "error_type": "auth_error",
            }), 401
        elif isinstance(e, ConnectionError) or "Cannot reach Ollama" in error_message:
            return jsonify({
                "error": error_message,
                "error_type": "not_configured",
            }), 503
        elif "AuthenticationError" in type(e).__name__ or "401" in error_message:
            return jsonify({
                "error": "Invalid API key. Check your environment variable and restart MacWatch.",
                "error_type": "auth_error",
            }), 401
        elif "RateLimitError" in type(e).__name__ or "429" in error_message:
            return jsonify({
                "error": "AI provider rate limit reached. Please wait a moment and try again.",
                "error_type": "rate_limit",
            }), 429
        elif "timeout" in error_message.lower() or "Timeout" in type(e).__name__:
            return jsonify({
                "error": "AI provider did not respond in time. Please try again.",
                "error_type": "timeout",
            }), 504
        else:
            return jsonify({
                "error": f"AI analysis failed: {error_message}",
                "error_type": "unknown",
            }), 500


@app.route("/help")
def help_page():
    return render_template("help.html")


def run():
    """Start the MacWatch server."""
    print(f"\n  MacWatch — Mac System Health Dashboard")
    print(f"  Dashboard: http://{HOST}:{PORT}")
    print(f"  Press Ctrl+C to stop\n")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
