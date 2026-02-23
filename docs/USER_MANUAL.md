# NetWatch User Manual

**Version 1.0**

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [The Dashboard](#2-the-dashboard)
3. [Application Cards](#3-application-cards)
4. [Connection Details](#4-connection-details)
5. [Threat Scores and Flags](#5-threat-scores-and-flags)
6. [Alerts](#6-alerts)
7. [Network Health Panel](#7-network-health-panel)
8. [Search and Filtering](#8-search-and-filtering)
9. [Settings](#9-settings)
10. [Data Export](#10-data-export)
11. [Keyboard Shortcuts](#11-keyboard-shortcuts)
12. [Troubleshooting](#12-troubleshooting)
13. [FAQ](#13-faq)
14. [Glossary](#14-glossary)

---

## 1. Getting Started

### Installation

```bash
git clone <repo-url>
cd netwatch
pip install -r requirements.txt
python -m netwatch
```

Open your browser to **http://localhost:8077**.

### First Run

When NetWatch starts, it immediately begins scanning your Mac's network connections. Within a few seconds, you'll see the dashboard populated with all active connections grouped by application.

```
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   12 Apps       │ │ 84 Connections   │ │  ↓ 47.3 MB in   │ │  ↑ 12.1 MB out  │
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
```

The dashboard auto-refreshes every 5 seconds by default. You'll see the "Last refreshed" timestamp update at the bottom of the page.

### Running with Elevated Permissions

By default, NetWatch shows connections belonging to your user account. To see all processes (including those owned by root and other system users):

```bash
sudo python -m netwatch
```

This is optional. Most useful information is visible without sudo.

---

## 2. The Dashboard

The main dashboard is divided into four sections:

### Summary Bar

Four cards showing totals at a glance:

```
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   12 Apps       │ │ 84 Connections   │ │  ↓ 47.3 MB in   │ │  ↑ 12.1 MB out  │
│   with active   │ │   open now       │ │    received      │ │    sent          │
│   connections   │ │                  │ │                  │ │                  │
└─────────────────┘ └─────────────────┘ └─────────────────┘ └─────────────────┘
```

- **Apps**: Number of applications with at least one open network connection
- **Connections**: Total count of all open network sockets across all apps
- **Traffic In**: Total bytes received by all apps (auto-scales: B, KB, MB, GB)
- **Traffic Out**: Total bytes sent by all apps (auto-scales: B, KB, MB, GB)

### Alerts Panel

Below the summary bar, a collapsible panel shows flagged activity:

```
┌── ALERTS ─────────────────────────────────────────────────── [Collapse] ─┐
│ 🔴  mystery-daemon is UNSIGNED and uploading 890 KB (73x more received)  │
│ 🟡  3 connections have no reverse DNS                                    │
│ 🔵  Surfshark VPN has routed 10.8 GB of traffic this session            │
└──────────────────────────────────────────────────────────────────────────┘
```

Alerts are sorted by severity: red first, then yellow, then blue. Click any alert to jump to the relevant application or connection.

### Application Cards

The main content area lists each application with its connections. See [Section 3](#3-application-cards) for details.

### Status Bar

The bottom bar shows:
- Last refresh timestamp
- Refresh interval selector (1s, 2s, 5s, 10s, 30s, manual)
- Pause/resume button
- Current filter state
- Navigation links (Health, Settings, Help, Export)

---

## 3. Application Cards

Each application with network activity is displayed as a collapsible card.

### Card Header

```
▼ Brave Browser
  47 connections │ ↓ 5.2 MB ↑ 1.3 MB │ CPU 0.8% MEM 0.4% │ ✅ Signed   ✅ 0
```

Reading left to right:

| Element | Meaning |
|---------|---------|
| ▼ / ▶ | Click to expand/collapse the connection table |
| App Name | Human-readable application name |
| N connections | Number of open network connections |
| ↓ X MB | Total bytes received by this app |
| ↑ X MB | Total bytes sent by this app |
| CPU X% | Current CPU usage of this process |
| MEM X% | Current memory usage of this process |
| ✅ Signed / ❌ Unsigned | Whether the app has a valid code signature |
| Score badge | Threat score with color: ✅ 0 (green), ⚠️ 2 (yellow), 🔴 6 (red) |

### Connection Table

When expanded, each connection is shown in a row:

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ Remote Host          IP               Port  Proto State        Org      CC Flags│
│────────────────────────────────────────────────────────────────────────────────│
│ github.com           140.82.114.25     443  TCP   ESTABLISHED  GitHub   US  ✅  │
│ (no rDNS)            91.203.5.12       443  TCP   ESTABLISHED  —        —   🟡  │
│ 45.33.98.17          45.33.98.17        80  TCP   ESTABLISHED  Linode   US  🔴  │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Column descriptions:**

| Column | Description |
|--------|-------------|
| **Remote Host** | The resolved hostname for the remote IP. If DNS lookup fails, shows "(no rDNS)" |
| **IP** | The actual IP address of the remote server |
| **Port** | Remote port number. Common ports are labeled: 443=HTTPS, 80=HTTP, 22=SSH, 53=DNS |
| **Proto** | Protocol: TCP or UDP |
| **State** | TCP connection state: ESTABLISHED (active), LISTEN (waiting), CLOSE_WAIT, TIME_WAIT |
| **Org** | Organization that owns the IP, from whois lookup |
| **CC** | Two-letter country code where the IP is registered |
| **Flags** | Threat flag: ✅ (clean), 🟡 (caution), 🔴 (danger) |

### Listening-Only Section

Apps that are only listening for incoming connections (not connecting outbound) are shown separately at the bottom:

```
── Listening Only (no active connections) ──────────────────────────────────
▶ ollama         LISTEN :11434 (localhost only)  │ ✅ Signed     ✅ 0
▶ Python         LISTEN :5001  (localhost only)  │ ✅ Signed     ✅ 0
```

The "(localhost only)" label means the app only accepts connections from your own machine. If it listens on 0.0.0.0, it accepts connections from any device on your network (flagged as informational).

---

## 4. Connection Details

Click any connection row to open the detail popover. This shows comprehensive information about a single connection.

```
╔═══════════════════════════════════════════════════════════════════╗
║  Connection Detail                                        [✕]   ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                 ║
║  CONNECTION                                                     ║
║  ┌────────────────────────────────────────────────────────────┐  ║
║  │ App:       Brave Browser (PID 10053)                      │  ║
║  │ Remote:    140.82.114.25:443                              │  ║
║  │ Protocol:  TCP (HTTPS)                                    │  ║
║  │ State:     ESTABLISHED                                    │  ║
║  └────────────────────────────────────────────────────────────┘  ║
║                                                                 ║
║  DNS                                                            ║
║  ┌────────────────────────────────────────────────────────────┐  ║
║  │ Reverse DNS: lb-140-82-114-25-iad.github.com              │  ║
║  └────────────────────────────────────────────────────────────┘  ║
║                                                                 ║
║  WHOIS                                                          ║
║  ┌────────────────────────────────────────────────────────────┐  ║
║  │ Organization: GitHub, Inc.                                │  ║
║  │ Network:      GITHU (140.82.112.0/20)                     │  ║
║  │ Address:      88 Colin P Kelly Jr Street                  │  ║
║  │ City:         San Francisco, CA                           │  ║
║  │ Country:      US                                          │  ║
║  └────────────────────────────────────────────────────────────┘  ║
║                                                                 ║
║  TRAFFIC                                                        ║
║  ┌────────────────────────────────────────────────────────────┐  ║
║  │ Bytes In:   124.5 KB                                      │  ║
║  │ Bytes Out:  8.2 KB                                        │  ║
║  │ Ratio:      15:1 (download-heavy — normal for browsing)   │  ║
║  │                                                           │  ║
║  │ Throughput (last 30s):                                    │  ║
║  │ In:  ▁▂▃▅▇▅▃▂▁▁▂▃▅▃▂▁  avg 4.2 KB/s                    │  ║
║  │ Out: ▁▁▁▂▃▂▁▁▁▁▁▁▂▂▁▁  avg 0.3 KB/s                    │  ║
║  └────────────────────────────────────────────────────────────┘  ║
║                                                                 ║
║  THREAT ASSESSMENT                                              ║
║  ┌────────────────────────────────────────────────────────────┐  ║
║  │ Score: 0 ✅                                               │  ║
║  │ • Port 443 (HTTPS) — encrypted                           │  ║
║  │ • Known organization (GitHub, Inc.)                       │  ║
║  │ • Valid reverse DNS                                       │  ║
║  │ • App is signed (Brave Software, Inc.)                    │  ║
║  └────────────────────────────────────────────────────────────┘  ║
║                                                                 ║
╚═══════════════════════════════════════════════════════════════════╝
```

### Sections in the Detail View

**CONNECTION** — Basic connection info: app, PID, local/remote addresses, protocol, state, interface.

**DNS** — Reverse DNS hostname, lookup time, cache status.

**WHOIS** — Organization name, registered network, physical address, country. This data is cached for 24 hours since IP ownership rarely changes.

**TRAFFIC** — Bytes in/out for this connection, upload/download ratio, and a sparkline showing throughput over the last 30 seconds.

**TCP DETAILS** — Retransmissions, average round-trip time (RTT), maximum segment size (MSS), send/receive buffer utilization, queue depths.

**THREAT ASSESSMENT** — The threat score for this specific connection with an explanation of each factor considered.

**OTHER CONNECTIONS** — Lists any other connections (from any app) to the same remote IP.

---

## 5. Threat Scores and Flags

NetWatch assigns each application a threat score based on heuristic analysis of its connections. This is not a security verdict — it's an indicator of "things worth looking at."

### Score Levels

| Score | Level | Color | What to Do |
|-------|-------|-------|------------|
| 0 | Clean | Green ✅ | Nothing — connections look normal |
| 1-2 | Low | Yellow ⚠️ | Glance at the flags. Usually benign. |
| 3-5 | Medium | Orange 🟠 | Review the connections. Multiple minor concerns. |
| 6+ | High | Red 🔴 | Investigate. Multiple serious indicators present. |

### Red Flags (+3 points each)

**Unsigned Application**
The app has no valid macOS code signature. All apps distributed through the App Store or by identified developers have code signatures. An unsigned app making network connections is the most significant red flag.

**Plaintext HTTP Connection (Port 80)**
Data is being sent without encryption. Any passwords, tokens, or personal information in this connection can be read by anyone on the network path.

**High Upload Ratio**
The app is sending significantly more data than it receives (configurable threshold, default: 10x). This pattern can indicate data exfiltration — your data being uploaded to an external server. Normal web browsing is download-heavy.

### Yellow Flags (+2 points each)

**Unusual Port**
The connection uses a port not in the standard set (443, 80, 22, 53, etc.). Command-and-control servers, crypto miners, and backdoors often use non-standard ports. However, many legitimate services also use non-standard ports.

**No Reverse DNS**
The IP address has no hostname record. Legitimate services almost always configure reverse DNS for their servers. Missing rDNS often indicates temporary or disposable infrastructure.

**VPS/Hosting Provider**
The IP belongs to a known hosting provider (DigitalOcean, Hetzner, Linode, OVH, Vultr). Real companies usually own their IP ranges directly. Attackers typically rent cheap virtual servers. However, many legitimate startups and services also use these providers.

**System Daemon External Connection**
A macOS system process is connecting to an external IP that doesn't belong to Apple. System daemons should generally only communicate with Apple's servers.

### Blue Flags (+1 point each)

**High Retransmissions** — Network quality issue. Could indicate congestion, interference, or in rare cases, connection tampering.

**Receive Queue Backup** — The app isn't reading its incoming data. Could mean the app is hung or overwhelmed.

**Many Unique IPs** — The app is connected to more than 20 different servers. Could indicate scanning behavior, though browsers legitimately connect to many servers.

**LISTEN on 0.0.0.0** — The app is accepting incoming connections from any device on your network, not just localhost.

### Customizing Scores

All flag weights and thresholds can be adjusted in Settings. You can also add apps, domains, and ports to safe lists to suppress specific alerts.

---

## 6. Alerts

The alerts panel provides a prioritized list of items needing attention.

### Alert Severities

```
🔴  Red — Immediate attention. Potentially dangerous activity detected.
🟡  Yellow — Worth investigating. Unusual but not necessarily dangerous.
🔵  Blue — Informational. Notable activity that's likely benign.
🆕  New — A new connection was detected to a previously unseen host.
```

### Alert Examples

```
┌── ALERTS ───────────────────────────────────────────────────────────────┐
│ 🔴  mystery-daemon is UNSIGNED and uploading 890 KB (73x > received)   │
│ 🔴  mystery-daemon connecting on non-standard port 8443                │
│ 🟡  3 connections have no reverse DNS                                  │
│ 🟡  com.apple.WebKit connecting to VPS provider (DigitalOcean)        │
│ 🔵  Surfshark VPN has routed 10.8 GB of traffic                       │
│ 🆕  Signal opened new connection to Amazon CloudFront                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### New Connection Alerts

NetWatch tracks which hosts each app connects to. When an app opens a connection to a host it hasn't previously contacted (during the current session), a "new connection" alert is generated. This is especially useful for catching:

- An app that suddenly starts communicating with a new server
- A background process that activates at unusual times
- A previously idle app beginning network activity

---

## 7. Network Health Panel

Access via the "Network Health" button at the bottom of the dashboard (keyboard shortcut: `2`).

### WiFi Quality

```
┌──────────────────────────────────────────────────────────────────────┐
│ SSID:            MyNetwork                                          │
│ Security:        WPA3 Personal                                      │
│ Channel:         149 (5 GHz, 80 MHz width)                          │
│ Signal (RSSI):   -52 dBm  ████████████████░░░░  Good               │
│ Noise Floor:     -90 dBm                                            │
│ SNR:             38 dB    ████████████████████░  Excellent          │
│ TX Rate:         867 Mbps                                            │
└──────────────────────────────────────────────────────────────────────┘
```

**Reading WiFi signal:**
- RSSI (signal strength): -30 dBm = excellent, -50 dBm = good, -70 dBm = fair, -80 dBm = poor
- SNR (signal-to-noise ratio): >40 dB = excellent, >25 dB = good, >15 dB = fair, <15 dB = poor
- TX Rate: Your current data rate. Higher is better. Affected by signal quality and distance.

### Interface Statistics

Shows each network interface with bytes transferred, error counts, and link speed. Useful for identifying:
- Which interface carries your traffic (WiFi vs Ethernet vs VPN)
- Whether errors are occurring at the hardware level
- VPN tunnel throughput

### TCP Stack Health

System-wide TCP statistics including retransmission rate, connection drops, RSTs, and bad checksums. A healthy network shows:
- Retransmit rate < 1%
- Zero bad checksums
- Few connection drops relative to total connections

### Charts

- **Connection Distribution**: Pie chart showing breakdown by TCP state
- **Top Talkers**: Bar chart of apps ranked by total bytes transferred

---

## 8. Search and Filtering

### Search Box

Type in the search box (keyboard shortcut: `/`) to filter across all fields:
- App name: `brave`, `signal`, `claude`
- Hostname: `github.com`, `protonmail`
- IP address: `140.82.114`, `192.168`
- Organization: `google`, `amazon`
- Port number: `443`, `8080`

### Filter Dropdowns

**State filter**: Show connections in a specific TCP state
- All (default)
- ESTABLISHED — active connections
- LISTEN — apps waiting for incoming connections
- CLOSE_WAIT — connections being closed
- TIME_WAIT — recently closed connections

**Threat filter**: Filter by threat level
- All (default)
- Red only — only show apps with score 6+
- Yellow + Red — score 1+
- Hide green — hide score 0

### Toggles

- **Show localhost**: Toggle visibility of connections to 127.0.0.1 (default: hidden)
- **Group by app**: Toggle between grouped view and flat connection list

### Sort Options

- App name (alphabetical)
- Connection count (most connections first)
- Bytes in (most downloaded first)
- Bytes out (most uploaded first)
- Threat score (highest risk first, default)

---

## 9. Settings

Access via the gear icon or keyboard shortcut `3`.

### Key Settings

**Refresh interval** — How often the dashboard updates. Options: 1s, 2s, 5s (default), 10s, 30s, manual. Faster refresh means more accurate data but higher CPU usage.

**Threat score weights** — Adjust the point value for each flag type. Set to 0 to disable a specific flag.

**Safe lists** — Add apps, domains, IPs, or ports that should never trigger alerts:
- Safe apps by bundle ID: `com.brave.Browser`, `com.apple.*`
- Safe domains: `*.github.com`, `*.anthropic.com`
- Safe IPs/CIDRs: `160.79.104.0/24`
- Safe ports: `8443`, `9090`

**Cache settings** — Control how long DNS and whois data is cached before re-querying.

**Display settings** — Toggle localhost visibility, system daemons, LISTEN-only apps, and auto-expand behavior.

---

## 10. Data Export

Click "Export" at the bottom of the dashboard to download connection data.

### Formats

- **JSON** — Full structured data including all enrichment (DNS, whois, threat scores)
- **CSV** — Flat table suitable for spreadsheet analysis

### Export Options

- Include/exclude whois data
- Include/exclude DNS resolution data
- Include/exclude threat analysis data

---

## 11. Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `r` | Refresh now |
| `p` | Pause/resume auto-refresh |
| `/` | Focus search box |
| `Esc` | Close popover / clear search |
| `e` | Expand all app groups |
| `c` | Collapse all app groups |
| `1` | Show main dashboard |
| `2` | Show network health |
| `3` | Show settings |
| `?` | Toggle help |
| `j` | Navigate to next app group |
| `k` | Navigate to previous app group |
| `Enter` | Expand/collapse selected app group |

---

## 12. Troubleshooting

### "No connections found"

- Ensure you have an active internet connection
- Check that `lsof -i` works in Terminal
- Some firewall apps may block lsof from seeing connections

### Slow refresh

- Whois lookups can be slow on first load. Data is cached after the first query.
- Reduce the number of concurrent DNS lookups in settings
- Increase refresh interval to 10s or 30s

### Missing applications

- By default, NetWatch only sees your user's processes. Use `sudo python -m netwatch` for full visibility.
- Some apps use system processes for networking (e.g., WebKit) rather than their own PID

### "Permission denied" errors

- `lsof` and `nettop` may require elevated permissions for some data
- Run with sudo for complete access
- CoreWLAN (WiFi info) may require Location Services permission

### High CPU usage

- Increase refresh interval (Settings → Refresh → 10s or 30s)
- Disable auto-expand for apps with alerts
- Reduce max connections per app display

### DNS lookups showing wrong hostnames

- Reverse DNS doesn't always match the service name. For example, `lb-140-82-114-25-iad.github.com` is a load balancer hostname for GitHub.
- CDN providers (CloudFront, Cloudflare, Fastly) serve many different websites from the same IPs
- Clear the DNS cache in Settings if you suspect stale entries

---

## 13. FAQ

**Q: Does NetWatch send my data anywhere?**
A: No. NetWatch runs entirely on your Mac. The web dashboard is served on localhost (127.0.0.1:8077). No data leaves your machine. Whois and DNS lookups go directly to public servers — these are standard network queries that reveal only the IP you're looking up, not your browsing data.

**Q: Why do some IPs show "(no rDNS)"?**
A: Not all IP addresses have reverse DNS records. This is common for cloud infrastructure. For example, Anthropic's servers (160.79.104.10) don't have reverse DNS configured. This doesn't necessarily mean the connection is suspicious — the whois lookup will still identify the organization.

**Q: Why is my VPN showing gigabytes of traffic?**
A: If you use a VPN (like Surfshark), all your internet traffic is routed through it. The byte count reflects your total internet usage tunneled through the VPN, not suspicious activity. This is normal.

**Q: Can I see connections from other users on my Mac?**
A: By default, NetWatch shows connections for your user account. Run with `sudo` for visibility into all processes, including root and system services.

**Q: How accurate is the threat scoring?**
A: Threat scores are heuristic indicators, not definitive security verdicts. A red score means "this deserves investigation," not "this is malware." Many legitimate applications trigger yellow flags (e.g., connecting to VPS providers, using non-standard ports). Always use your judgment and investigate flagged items before taking action.

**Q: Can NetWatch block connections?**
A: No. NetWatch is a monitoring-only tool. To block connections, use macOS built-in firewall (System Settings > Network > Firewall) or a dedicated tool like Little Snitch or Lulu.

**Q: Why does a browser show so many connections?**
A: Modern web pages load resources from many different servers — CDNs, analytics, fonts, APIs, ads. A browser with 40-50 connections is completely normal. The connections are typically short-lived for loading page resources.

**Q: What's the difference between ESTABLISHED and LISTEN?**
A: ESTABLISHED means an active, two-way connection between your Mac and a remote server. LISTEN means an app is waiting for incoming connections on a port — it's a server, not a client. For example, a local development server (like ollama on port 11434) will show as LISTEN.

**Q: Why do I see connections to Apple servers from system processes?**
A: macOS regularly communicates with Apple for push notifications (apsd), time sync, certificate checks, iCloud, and other system services. These are normal.

---

## 14. Glossary

| Term | Definition |
|------|-----------|
| **ESTABLISHED** | TCP connection that is fully open and actively transferring data |
| **LISTEN** | A socket waiting for incoming connection requests on a specific port |
| **CLOSE_WAIT** | The remote end closed the connection; the local app hasn't finished closing yet |
| **TIME_WAIT** | Connection recently closed; waiting for any stray packets to arrive before final cleanup |
| **TCP** | Transmission Control Protocol — reliable, ordered delivery (used by HTTP, SSH, etc.) |
| **UDP** | User Datagram Protocol — fast but unreliable delivery (used by DNS, video streaming, QUIC) |
| **rDNS** | Reverse DNS — looking up a hostname from an IP address (the opposite of normal DNS) |
| **whois** | Protocol for querying who owns an IP address or domain name |
| **CIDR** | Classless Inter-Domain Routing — notation for IP address ranges (e.g., 140.82.112.0/20) |
| **MSS** | Maximum Segment Size — the largest TCP payload per packet |
| **RTT** | Round-Trip Time — the time for a packet to travel to the server and back (latency) |
| **RSSI** | Received Signal Strength Indicator — WiFi signal strength in dBm |
| **SNR** | Signal-to-Noise Ratio — difference between WiFi signal and noise floor |
| **PID** | Process ID — unique number identifying a running process on your Mac |
| **Code signing** | macOS mechanism where developers cryptographically sign their apps to prove authenticity |
| **VPS** | Virtual Private Server — a rented virtual machine at a hosting provider |
| **C2** | Command and Control — a server used by malware to receive instructions from an attacker |
| **MITM** | Man-in-the-Middle — an attack where network traffic is secretly intercepted and possibly altered |
| **SSE** | Server-Sent Events — a web technology for pushing real-time updates from server to browser |
| **Recv-Q** | Receive Queue — bytes waiting to be read by the application |
| **Send-Q** | Send Queue — bytes waiting to be sent over the network |
