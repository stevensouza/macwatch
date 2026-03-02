"""AI-powered analysis of MacWatch data."""

import json
import os
import uuid
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

    MODEL = "claude-sonnet-4-6"
    MAX_TOKENS = 4096

    def provider_name(self):
        return "Claude (API)"

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


class ClaudeWebProvider(AIProvider):
    """Claude via claude.ai web API — uses Pro/Max subscription tokens."""

    API_BASE = "https://claude.ai/api/organizations"
    MODEL = "claude-sonnet-4-6"
    TIMEOUT = 120

    def provider_name(self):
        return "Claude (Web/Subscription)"

    def is_configured(self):
        return bool(os.environ.get("CLAUDE_SESSION_KEY")) and bool(
            os.environ.get("CLAUDE_ORG_ID")
        )

    def analyze(self, prompt):
        org_id = os.environ["CLAUDE_ORG_ID"]
        session_key = os.environ["CLAUDE_SESSION_KEY"]
        cookie = f"sessionKey={session_key}"

        conv_uuid = str(uuid.uuid4())
        self._create_conversation(org_id, cookie, conv_uuid)

        try:
            raw_text = self._send_message(org_id, cookie, conv_uuid, prompt)
        finally:
            self._delete_conversation(org_id, cookie, conv_uuid)

        if not raw_text:
            raise ValueError(
                "Claude Web returned an empty response. "
                "Your session key may be expired — get a fresh one from claude.ai."
            )

        return _parse_ai_response(raw_text)

    def _create_conversation(self, org_id, cookie, conv_uuid):
        """Create a temporary conversation on claude.ai."""
        url = f"{self.API_BASE}/{org_id}/chat_conversations"
        body = json.dumps({
            "uuid": conv_uuid,
            "name": "",
            "include_conversation_preferences": True,
            "is_temporary": True,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Cookie": cookie,
                "User-Agent": "MacWatch/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status not in (200, 201):
                    raise ConnectionError(
                        f"Create conversation failed: HTTP {resp.status}"
                    )
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise PermissionError(
                    "Claude Web session expired or invalid. "
                    "Update CLAUDE_SESSION_KEY with a fresh value from claude.ai."
                ) from e
            raise ConnectionError(
                f"Create conversation failed: HTTP {e.code}"
            ) from e
        except urllib.error.URLError as e:
            raise ConnectionError(f"Cannot reach claude.ai: {e.reason}") from e

    def _send_message(self, org_id, cookie, conv_uuid, prompt):
        """Send a message and parse the SSE stream to collect the full response."""
        url = f"{self.API_BASE}/{org_id}/chat_conversations/{conv_uuid}/completion"
        body = json.dumps({
            "prompt": prompt,
            "parent_message_uuid": "00000000-0000-4000-8000-000000000000",
            "model": self.MODEL,
            "timezone": "UTC",
            "attachments": [],
            "files": [],
            "tools": [],
            "rendering_mode": "messages",
            "sync_sources": [],
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "Cookie": cookie,
                "User-Agent": "MacWatch/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                raw_data = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise PermissionError(
                    "Claude Web session expired or invalid. "
                    "Update CLAUDE_SESSION_KEY with a fresh value from claude.ai."
                ) from e
            body_text = ""
            try:
                body_text = e.read().decode("utf-8")[:200]
            except Exception:
                pass
            raise ConnectionError(
                f"Claude Web completion failed: HTTP {e.code}: {body_text}"
            ) from e
        except urllib.error.URLError as e:
            raise ConnectionError(f"Cannot reach claude.ai: {e.reason}") from e

        return self._parse_sse(raw_data)

    def _parse_sse(self, raw_data):
        """Parse SSE event stream and extract text from content_block_delta events."""
        response_text = ""
        current_event = ""

        for line in raw_data.split("\n"):
            trimmed = line.strip()

            if trimmed.startswith("event:"):
                current_event = trimmed[len("event:"):].strip()
            elif trimmed.startswith("data:"):
                payload = trimmed[len("data:"):].strip()
                if payload and current_event == "content_block_delta":
                    try:
                        obj = json.loads(payload)
                        response_text += obj.get("delta", {}).get("text", "")
                    except (json.JSONDecodeError, KeyError):
                        pass
                elif payload and current_event == "error":
                    try:
                        obj = json.loads(payload)
                        msg = obj.get("error") or obj.get("message") or str(obj)
                        raise RuntimeError(f"Claude Web stream error: {msg}")
                    except json.JSONDecodeError:
                        raise RuntimeError(f"Claude Web stream error: {payload}")

        return response_text

    def _delete_conversation(self, org_id, cookie, conv_uuid):
        """Delete the temporary conversation (best-effort cleanup)."""
        url = f"{self.API_BASE}/{org_id}/chat_conversations/{conv_uuid}"
        req = urllib.request.Request(
            url,
            headers={"Cookie": cookie, "User-Agent": "MacWatch/1.0"},
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception:
            pass  # Best-effort — don't fail if cleanup fails


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
    "claude-web": ClaudeWebProvider,
}


def get_provider(name="ollama"):
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
You are writing a professional system audit report. Analyze this data from three perspectives — security, performance, and system health — and show your work. The reader should be able to see what you reviewed and what your conclusions were for each area, even when everything looks normal.

Provide the following sections:

1. **VERDICT**: State either "CONCERNS" or "NO CONCERNS" at the top.
   - "CONCERNS" = you found something that warrants the user's attention
   - "NO CONCERNS" = everything looks like normal macOS activity

2. **SUMMARY**: A 2-3 sentence overall assessment of the system's health.

3. **RECOMMENDATIONS**: Actionable suggestions for security, performance, and general system hygiene. If the system looks healthy, suggest preventive best practices.

4. **FINDINGS**: This is the core of your audit. Cover ALL three categories below, even when things look normal. For each category, state what you reviewed and your conclusion. Use a mix of severity levels:
   - **HIGH/MEDIUM** for actual concerns requiring attention
   - **LOW** for minor observations worth noting
   - **INFO** for things you reviewed that look healthy — these confirm the audit was thorough

   **Security** — Review: code signing status of all apps, network connection destinations (countries, orgs), use of encryption (HTTPS vs HTTP), upload/download ratios, connections to VPS/hosting providers, unsigned binaries, and any unusual patterns. Reference the threat scores and flags MacWatch assigned to each app — confirm whether you agree with them or if any are over/under-flagged. State what you found.

   **Performance** — Review: CPU usage across all processes (note the highest consumers and the total), memory usage (note the top consumers), network retransmission rates (indicator of connection quality), number of connections per app, and cumulative traffic volumes. State specific numbers from the data.

   **System Health** — Review: processes listening on network interfaces (and whether they should be), code signing coverage, number of running apps vs connections, any duplicate or unexpected processes, and overall system posture. State what you found.

5. **AUDIT SCOPE**: End with a one-line summary of what was reviewed: how many apps, connections, and alerts were in the dataset.  Also reference the alerts section — confirm whether the alerts MacWatch raised are valid and if anything was missed.

A browser having many connections or using CDN ports is normal — don't flag routine behavior. But DO mention what you reviewed and that it looked normal, so the reader knows it wasn't overlooked.

Format your response in clear sections with the headers VERDICT, SUMMARY, RECOMMENDATIONS, and FINDINGS (in that exact order).

IMPORTANT FORMATTING RULES:
- Do NOT use markdown tables (no pipe | characters). Use bullet lists instead.
- Within FINDINGS, use exactly "### Security", "### Performance", and "### System Health" as sub-section headers. You MUST include the ### prefix — bare text like "Security" will not render as a header. Do NOT use #### — only ### is supported.
- For FINDINGS, each bullet MUST include a short bolded topic label after the severity. This lets readers scan quickly. Format:
  - **[CATEGORY] [SEVERITY]: [Topic Label]** — Description with specific numbers from the data. Conclusion or action.
  - The topic label should be 1-3 words identifying what the finding is about.
  - Examples:
    - **PERFORMANCE INFO: CPU Usage** — CPU usage is low across all processes. Highest consumer is Brave at 1.2%%, total system under 5%%. No pressure.
    - **PERFORMANCE MEDIUM: Idle Memory** — Ollama is consuming 25%% of memory while idle at 0%% CPU. Consider stopping it to free RAM.
    - **SECURITY INFO: Code Signing** — All commercial apps are properly signed. No tampered binaries detected.
    - **SECURITY MEDIUM: Open Listener** — Java is listening on 0.0.0.0:8080, exposing it to the local network. Confirm this is intentional.
- For RECOMMENDATIONS, also use a short bolded topic label at the start of each item:
  - **Network quality** — Investigate the high retransmission counts...
- Use **bold**, *italic*, bullet lists (- item), and ### headers only.
- Keep formatting simple — the rendering engine supports basic markdown only."""

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

    # Reconstruct raw_response with remaining sections (VERDICT and SUMMARY
    # are displayed as separate UI elements, so exclude them here)
    ordered_parts = []
    for key, header in [
        ("recommendations", "RECOMMENDATIONS"),
        ("findings", "FINDINGS"),
    ]:
        if sections.get(key):
            ordered_parts.append(f"## {header}\n\n{sections[key]}")
    if ordered_parts:
        result["raw_response"] = "\n\n".join(ordered_parts)

    return result
