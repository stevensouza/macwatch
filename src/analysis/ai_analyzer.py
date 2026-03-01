"""AI-powered analysis of MacWatch data."""

import json
import os
import urllib.request
import urllib.error
from abc import ABC, abstractmethod


class AIProvider(ABC):
    """Base class for AI analysis providers."""

    @abstractmethod
    def analyze(self, prompt):
        """Send analysis prompt to AI and return structured response."""
        ...

    @abstractmethod
    def is_configured(self):
        """Check if this provider has the necessary configuration."""
        ...

    @abstractmethod
    def provider_name(self):
        """Human-readable provider name."""
        ...


class ClaudeProvider(AIProvider):
    """Anthropic Claude API provider."""

    MODEL = "claude-sonnet-4-5"
    MAX_TOKENS = 4096

    def provider_name(self):
        return "Claude (Anthropic)"

    def is_configured(self):
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def analyze(self, prompt):
        import anthropic

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=self.MODEL,
            max_tokens=self.MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )

        raw_text = message.content[0].text
        return _parse_ai_response(raw_text)


class OllamaProvider(AIProvider):
    """Ollama local AI provider — no API key needed."""

    MODEL = "llama3.1"
    OLLAMA_URL = "http://localhost:11434"

    def provider_name(self):
        return "Ollama (Local)"

    def is_configured(self):
        """Check if Ollama is reachable."""
        try:
            req = urllib.request.Request(f"{self.OLLAMA_URL}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    def analyze(self, prompt):
        payload = json.dumps({
            "model": self.MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.OLLAMA_URL}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot reach Ollama at {self.OLLAMA_URL}. "
                "Is Ollama running? Start it with: ollama serve"
            ) from e

        raw_text = data.get("message", {}).get("content", "")
        if not raw_text:
            raise ValueError("Ollama returned an empty response. "
                           f"Is the model '{self.MODEL}' pulled? Run: ollama pull {self.MODEL}")
        return _parse_ai_response(raw_text)


# Provider registry — extend by adding new classes and entries here
PROVIDERS = {
    "ollama": OllamaProvider,
    "claude": ClaudeProvider,
}


def get_provider(name="claude"):
    """Get an AI provider instance by name."""
    provider_class = PROVIDERS.get(name)
    if not provider_class:
        available = ", ".join(PROVIDERS.keys())
        raise ValueError(f"Unknown AI provider: {name}. Available: {available}")
    return provider_class()


def get_available_providers():
    """Return list of available providers with their configuration status."""
    result = []
    for name, cls in PROVIDERS.items():
        instance = cls()
        result.append({
            "id": name,
            "name": instance.provider_name(),
            "configured": instance.is_configured(),
        })
    return result


def build_analysis_prompt(data):
    """Construct the full analysis prompt from MacWatch dashboard data."""
    summary = data.get("summary", {})
    apps = data.get("apps", [])
    alerts = data.get("alerts", [])

    # Build app details section
    app_details = []
    for app in apps:
        app_section = (
            f"  App: {app['app']} (PID {app['pid']})\n"
            f"    Connections: {app['connection_count']}\n"
            f"    Traffic: In={app['bytes_in_fmt']}, Out={app['bytes_out_fmt']}\n"
            f"    CPU: {app['cpu']:.1f}%, Memory: {app['mem']:.1f}%\n"
            f"    Code Signed: {'Yes (' + (app.get('sign_authority') or 'Unknown') + ')' if app.get('signed') else 'NO — UNSIGNED'}\n"
            f"    Threat Score: {app['threat_score']} ({app['threat_level']})\n"
            f"    Path: {app.get('path', 'unknown')}"
        )
        if app.get("threat_flags"):
            flags_text = "\n".join(
                f"      [{f['severity'].upper()}] {f['description']}"
                for f in app["threat_flags"]
            )
            app_section += f"\n    Flags:\n{flags_text}"

        # Include top connections (limit to 10 per app for prompt size)
        if app.get("connections"):
            conn_lines = []
            for c in app["connections"][:10]:
                conn_lines.append(
                    f"      {c.get('remote_host', '?')} ({c.get('remote_addr', '?')}:{c.get('remote_port', '?')}) "
                    f"{c.get('protocol', '')} {c.get('state', '')} "
                    f"Org={c.get('whois_org', '?')} CC={c.get('whois_country', '?')}"
                )
            if len(app["connections"]) > 10:
                conn_lines.append(
                    f"      ... and {len(app['connections']) - 10} more connections"
                )
            app_section += "\n    Connections:\n" + "\n".join(conn_lines)

        app_details.append(app_section)

    # Build alerts section
    alert_lines = []
    for alert in alerts:
        alert_lines.append(
            f"  [{alert['severity'].upper()}] {alert['app']}: {alert['description']}"
        )

    prompt = f"""You are a macOS system health analyst reviewing data collected by MacWatch, a local monitoring tool. Your job is to assess this machine from THREE perspectives: security, performance, and general system health.

MacWatch collects:
- Open network connections from all running applications (via lsof)
- Per-process traffic statistics: bytes in/out, retransmissions (via nettop)
- Process details: CPU, memory, path, code signing status, uptime
- DNS reverse lookups and WHOIS data for remote IPs
- Threat scoring based on heuristic rules (unsigned apps, unusual ports, plaintext HTTP, high upload ratios, etc.)

This data is from a single snapshot of a macOS machine. Traffic numbers are cumulative since each process started, not per-refresh.

IMPORTANT CONTEXT:
- MacWatch itself runs on localhost:8077 and will appear in the data — ignore it.
- Many flags are expected for legitimate software (browsers connect to many IPs, dev tools use unusual ports, etc.)
- Focus on genuinely unusual patterns, not routine flags.

== SYSTEM SUMMARY ==
Active Apps: {summary.get('app_count', 0)}
Total Connections: {summary.get('connection_count', 0)}
Traffic In: {summary.get('bytes_in_fmt', '0 B')}
Traffic Out: {summary.get('bytes_out_fmt', '0 B')}
Alerts: {summary.get('alert_count', 0)} (Red: {summary.get('red_count', 0)}, Yellow: {summary.get('yellow_count', 0)}, Blue: {summary.get('blue_count', 0)})

== APPLICATIONS ==
{chr(10).join(app_details) if app_details else "  No applications with network activity."}

== ALERTS ==
{chr(10).join(alert_lines) if alert_lines else "  No alerts."}

== YOUR TASK ==
Analyze this data from three perspectives and provide:

1. **VERDICT**: State either "CONCERNS" or "NO CONCERNS" at the top.
   - "CONCERNS" = you found something that warrants the user's attention (security, performance, or health)
   - "NO CONCERNS" = everything looks like normal macOS activity

2. **SUMMARY**: A 2-3 sentence overall assessment of the system's health.

3. **RECOMMENDATIONS**: Actionable suggestions for security, performance, and general system hygiene.

4. **FINDINGS**: List the most important observations grouped by category. For each finding:
   - Category: SECURITY, PERFORMANCE, or HEALTH
   - Severity: HIGH, MEDIUM, or LOW
   - What you found
   - What the user should do about it

   **Security** — Look for: suspicious network connections, unsigned apps, unusual traffic patterns, connections to unexpected countries/IPs, high upload ratios, plaintext HTTP, etc.

   **Performance** — Look for: processes with high CPU usage, excessive memory consumption, high retransmission rates (network quality), apps with unusually many connections, large cumulative traffic that might indicate leaks or runaway processes.

   **System Health** — Look for: processes listening on all interfaces that shouldn't be, duplicate processes that seem unnecessary, apps connecting to unexpected services, anything that looks misconfigured or out of the ordinary for a healthy macOS system.

Keep your response concise and actionable. Focus on what matters — do not list every single flag if most are routine. A browser having many connections or using non-standard CDN ports is normal. Look for the anomalies.

Format your response in clear sections with the headers VERDICT, SUMMARY, RECOMMENDATIONS, and FINDINGS (in that exact order)."""

    return prompt


def _parse_ai_response(raw_text):
    """Parse the AI response text into a structured dict."""
    result = {
        "verdict": "no_concerns",
        "summary": "",
        "findings": [],
        "recommendations": "",
        "raw_response": raw_text,
    }

    # Extract verdict
    text_upper = raw_text.upper()
    if "NO CONCERNS" in text_upper:
        result["verdict"] = "no_concerns"
    elif "CONCERNS" in text_upper:
        result["verdict"] = "concerns"

    # Extract sections by header
    sections = {}
    current_section = None
    current_lines = []

    for line in raw_text.split("\n"):
        stripped = line.strip()
        header_check = stripped.upper().replace("*", "").replace("#", "").strip()
        if header_check.startswith("VERDICT"):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = "verdict_text"
            current_lines = []
        elif header_check.startswith("SUMMARY"):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = "summary"
            current_lines = []
        elif header_check.startswith("FINDING"):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = "findings"
            current_lines = []
        elif header_check.startswith("RECOMMENDATION"):
            if current_section:
                sections[current_section] = "\n".join(current_lines).strip()
            current_section = "recommendations"
            current_lines = []
        else:
            current_lines.append(line)

    if current_section:
        sections[current_section] = "\n".join(current_lines).strip()

    result["summary"] = sections.get("summary", "")
    result["recommendations"] = sections.get("recommendations", "")

    # Reconstruct raw_response with sections in the desired order:
    # VERDICT, SUMMARY, RECOMMENDATIONS, FINDINGS
    ordered_parts = []
    for key, header in [
        ("verdict_text", "VERDICT"),
        ("summary", "SUMMARY"),
        ("recommendations", "RECOMMENDATIONS"),
        ("findings", "FINDINGS"),
    ]:
        if sections.get(key):
            ordered_parts.append(f"## {header}\n\n{sections[key]}")
    if ordered_parts:
        result["raw_response"] = "\n\n".join(ordered_parts)

    return result
