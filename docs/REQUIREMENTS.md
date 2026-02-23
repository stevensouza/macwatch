# NetWatch — macOS Network Connection Viewer
## Requirements Document

**Version:** 1.0
**Date:** 2026-02-22
**Status:** Draft

---

## 1. Overview

NetWatch is a local web-based dashboard for macOS that provides real-time visibility into which applications have open network connections, what they're connecting to, and whether any of that activity is suspicious.

### 1.1 Problem Statement

macOS users have no simple, unified way to see what their applications are doing on the network. Existing tools (`lsof`, `netstat`, `nettop`) are powerful but fragmented, require terminal expertise, and produce raw output that's hard to interpret. Commercial tools like Little Snitch are expensive and opaque. NetWatch fills this gap with a free, transparent, open-source solution.

### 1.2 Goals

- Show all active network connections grouped by application
- Resolve IP addresses to human-readable domain names and organizations
- Provide traffic statistics (bytes in/out) per application
- Flag suspicious or unusual network activity with color-coded threat scores
- Present everything in a clean, auto-refreshing web dashboard
- Require no special permissions beyond what `lsof` and `nettop` need (user-level access)

### 1.3 Non-Goals (v1)

- Blocking or modifying network traffic (this is a viewer, not a firewall)
- Apple entitlement-gated APIs (NEFilterDataProvider, Endpoint Security)
- Mobile/iOS support
- Multi-user or remote access

---

## 2. Data Sources

### 2.1 Primary Sources (CLI Tools)

| Source | Command | Data Provided | Refresh Rate |
|--------|---------|---------------|--------------|
| **lsof** | `lsof -i -n -P` | App name, PID, protocol, local/remote address:port, connection state, IPv4/IPv6 | Every refresh cycle |
| **nettop** | `nettop -L 1 -P -n -x` | Bytes in/out, packets, rx_dupe, rx_ooo, re-tx per process | Every refresh cycle |
| **Reverse DNS** | `socket.getfqdn()` / `socket.gethostbyaddr()` | Hostname for IP addresses | Cached, refreshed on new IPs |
| **whois** | `whois <ip>` | Organization name, country, city, CIDR, network name | Cached, refreshed rarely |
| **codesign** | `codesign -dvvv <app_path>` | Signing authority, team ID, certificate chain, bundle ID | Cached per app binary |
| **ps** | `ps -eo pid,pcpu,pmem,comm` | CPU %, memory %, full binary path | Every refresh cycle |
| **netstat** | `netstat -an` | Recv-Q, Send-Q queue depths | Every refresh cycle |

### 2.2 macOS Native APIs (No Entitlement Required)

| API | Data Provided | Use Case |
|-----|---------------|----------|
| **libproc/proc_pidinfo** | Per-socket buffer utilization, TCP MSS, socket error codes | Connection health detail |
| **sysctl net.inet.tcp.stats** | System-wide TCP retransmits, drops, RSTs, bad checksums | Global network health panel |
| **sysctl IFMIB_IFDATA** | 64-bit byte counters per interface | Accurate interface throughput |
| **CoreWLAN (CWInterface)** | WiFi RSSI (dBm), noise floor, channel width, transmit rate, security type | WiFi quality indicator |
| **NWPathMonitor** | Expensive connection flag, Low Data Mode, interface type | Connection context |
| **SCDynamicStore** | DNS resolvers, DHCP lease, default gateway, VPN state | Network configuration panel |
| **IOKit IONetworkStats** | Driver-level errors, collisions, multicast, link speed/duplex | Interface health |

### 2.3 Future APIs (Require Apple Entitlement)

| API | Data Provided | Value |
|-----|---------------|-------|
| **NEFilterDataProvider** | Original DNS hostname per flow, kernel-verified code signing identity | See "app connected to api.stripe.com" not just an IP |
| **NEDNSProxyProvider** | All DNS queries tied to originating app | Which app looked up what domain |
| **Endpoint Security** | Cryptographic code-signing identity per socket connection | Unforgeable app trust |

---

## 3. Feature Specifications

### 3.1 Dashboard — Main View

The primary view showing all applications with active network connections.

#### 3.1.1 Summary Bar

Four stat cards at the top of the page:

| Card | Value | Source |
|------|-------|--------|
| Active Apps | Count of unique apps with connections | lsof |
| Total Connections | Count of all open connections | lsof |
| Traffic In | Sum of bytes_in across all apps (auto-scaled: KB/MB/GB) | nettop |
| Traffic Out | Sum of bytes_out across all apps (auto-scaled: KB/MB/GB) | nettop |

#### 3.1.2 Alerts Panel

A collapsible panel below the summary bar showing flagged items, sorted by severity:

- Red alerts at the top
- Yellow alerts in the middle
- Blue (informational) at the bottom
- Each alert shows: severity icon, app name, description, and a link to the relevant connection

#### 3.1.3 Application Groups

Each application is displayed as a collapsible card:

**Header row contains:**
- Expand/collapse toggle (▼/▶)
- App name (human-readable)
- Connection count
- Threat score badge (color-coded: green/yellow/red)
- Bytes in / bytes out (auto-scaled units)
- CPU % and Memory %
- Code signing status icon (✅ signed / ⚠️ unsigned)

**Expanded content contains a table with columns:**
- Remote Host (resolved DNS name, or "no rDNS" if lookup fails)
- IP Address
- Port (with protocol label: 443→HTTPS, 80→HTTP, 22→SSH, etc.)
- Protocol (TCP/UDP)
- State (ESTABLISHED, LISTEN, CLOSE_WAIT, TIME_WAIT, etc.)
- Organization (from whois — e.g., "GitHub, Inc.")
- Country (flag emoji + country code)
- Flags (threat flag badges)

**Clicking an IP or hostname opens a detail popover with:**
- Full whois information (organization, address, CIDR, network name)
- Reverse DNS hostname
- Geographic location
- All connections to this IP across all apps
- Historical connection data (if available)

#### 3.1.4 Sorting and Filtering

- **Search box**: Filter by app name, hostname, IP, organization, or port
- **State filter**: Dropdown — All, ESTABLISHED, LISTEN, CLOSE_WAIT, TIME_WAIT
- **Threat filter**: Show All, Red Only, Yellow+Red, Hide Green
- **Localhost toggle**: Show/hide localhost-only connections (default: hidden)
- **Sort by**: App name, connection count, bytes in, bytes out, threat score

#### 3.1.5 Auto-Refresh

- Default refresh interval: 5 seconds
- Configurable: 1s, 2s, 5s, 10s, 30s, manual
- Visual indicator showing last refresh time
- Pause/resume button

### 3.2 Connection Detail View

Accessed by clicking a connection row. Shows:

- Full lsof details (FD, device, node type)
- Socket buffer utilization (from libproc if available)
- TCP-specific: MSS, retransmit count, RTT average
- Historical bytes in/out over time (sparkline chart)
- Whois full output
- Reverse DNS chain

### 3.3 Network Health Panel

A secondary view showing system-wide network statistics:

- **WiFi Quality** (from CoreWLAN): RSSI, noise floor, channel, transmit rate, security type
- **Interface Stats** (from IOKit/sysctl): Per-interface bytes, packets, errors, drops, link speed
- **TCP Stack Health** (from sysctl): Retransmit rate, connection drops, RSTs, bad checksums
- **Connection Distribution**: Pie chart of connections by state
- **Top Talkers**: Bar chart of apps by bytes transferred

### 3.4 Settings View

- Refresh interval
- Threat score thresholds (customizable weights)
- Whois cache TTL
- DNS cache TTL
- Known-safe apps list (suppress alerts)
- Known-safe IPs/domains list
- Port whitelist for "unusual port" detection
- Export data (JSON/CSV)

### 3.5 Online Help

- Accessible via "?" icon in the header
- Contains ASCII screen mockups showing each feature
- Explains threat scoring methodology
- Describes each data source and what it means
- Troubleshooting section
- Keyboard shortcuts

---

## 4. Threat Detection & Scoring

### 4.1 Threat Flags

#### Red Flags (score: +3 each)

| Flag | Detection Method | Rationale |
|------|-----------------|-----------|
| Unsigned application | `codesign` check fails or no Developer ID | Malware is typically unsigned |
| HTTP (plaintext) connection | Remote port = 80 | Data transmitted unencrypted |
| Extremely high upload ratio | bytes_out > 10× bytes_in and bytes_out > 1 MB | Potential data exfiltration |

#### Yellow Flags (score: +2 each)

| Flag | Detection Method | Rationale |
|------|-----------------|-----------|
| Unusual port | Port not in standard set (see §4.3) | C2 servers, crypto miners use odd ports |
| No reverse DNS | `host` / `gethostbyaddr` returns NXDOMAIN | Legitimate services usually have rDNS |
| VPS/hosting provider IP | whois org matches known hosting providers | Attackers rent cheap VPS; real companies own their IPs |
| System daemon with external connection | Process name is a known system daemon + remote IP is not Apple/local | System processes shouldn't phone home to random IPs |

#### Blue Flags (score: +1 each)

| Flag | Detection Method | Rationale |
|------|-----------------|-----------|
| High retransmissions | re-tx from nettop > threshold | Network quality issue or possible MITM |
| Recv-Q backing up | netstat Recv-Q > 0 | App not reading data — hung or compromised |
| Many unique remote IPs | > 20 distinct IPs for a single app | Could indicate scanning behavior |
| IPv6 connection | lsof shows AF_INET6 | Informational — some monitoring tools miss IPv6 |
| LISTEN on 0.0.0.0 | lsof shows `*:port` LISTEN | Accepting connections from entire network |

#### Informational (score: 0)

| Flag | Detection Method | Rationale |
|------|-----------------|-----------|
| VPN traffic | Known VPN app with high byte counts | Normal but worth noting |
| Multiple connections to same host | > 5 connections to same IP per app | Usually connection pooling — normal |

### 4.2 Threat Score Calculation

Per-application threat score = sum of all flag scores across all connections.

| Score | Level | Color | Badge |
|-------|-------|-------|-------|
| 0 | Clean | Green | ✅ |
| 1–2 | Low | Yellow | ⚠️ |
| 3–5 | Medium | Orange | 🟠 |
| 6+ | High | Red | 🔴 |

### 4.3 Standard Port List

Connections to these ports are considered "normal" and don't trigger the unusual-port flag:

| Port | Protocol | Service |
|------|----------|---------|
| 22 | TCP | SSH |
| 53 | TCP/UDP | DNS |
| 80 | TCP | HTTP (flagged separately as plaintext) |
| 443 | TCP/UDP | HTTPS / QUIC |
| 465 | TCP | SMTPS |
| 587 | TCP | SMTP Submission |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 3478 | UDP | STUN/TURN (WebRTC) |
| 5228 | TCP | Google Cloud Messaging |
| 5353 | UDP | mDNS |
| 8080 | TCP | HTTP Alternate |
| 8443 | TCP | HTTPS Alternate |

### 4.4 Known Hosting/VPS Providers

Whois organization names that trigger the "VPS provider" yellow flag:

- DigitalOcean, LLC
- Linode / Akamai Connected Cloud
- OVH SAS / OVHcloud
- Hetzner Online GmbH
- Vultr Holdings LLC
- Amazon.com, Inc. (AWS — context-dependent)
- Google Cloud (context-dependent)
- Microsoft Azure (context-dependent)

Note: Major cloud providers (AWS, GCP, Azure) are flagged at lower severity since many legitimate services use them.

### 4.5 New Connection Alerts

The system tracks connection state over time and alerts when:
- An app opens a connection to a **new** remote host it hasn't connected to before (in the current session)
- An app that was previously idle starts making connections
- A new app appears that wasn't previously seen making network connections

---

## 5. Architecture

### 5.1 Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Backend | Python 3.10+ | Rich subprocess/parsing libraries, no compilation needed |
| Web framework | Flask | Lightweight, minimal dependencies |
| Frontend | HTML + CSS + Vanilla JavaScript | No build step, minimal complexity |
| Data refresh | Server-Sent Events (SSE) or polling | Real-time updates without WebSocket complexity |
| DNS cache | In-memory dict with TTL | Avoid repeated lookups |
| Whois cache | In-memory dict with TTL | Whois lookups are slow |
| Codesign cache | In-memory dict (permanent per session) | Binary signatures don't change |

### 5.2 Backend Modules

```
netwatch/
├── app.py                  # Flask application, routes, SSE endpoint
├── collectors/
│   ├── lsof.py             # Parse lsof -i output
│   ├── nettop.py           # Parse nettop output
│   ├── netstat.py          # Parse netstat output
│   ├── process.py          # Parse ps output + codesign checks
│   └── system.py           # sysctl, CoreWLAN, IOKit stats
├── enrichment/
│   ├── dns.py              # Reverse DNS with caching
│   ├── whois.py            # Whois lookups with caching
│   └── geo.py              # Geographic info extraction from whois
├── analysis/
│   ├── threat.py           # Threat scoring engine
│   ├── flags.py            # Flag definitions and detection rules
│   └── alerts.py           # New connection detection, alert generation
├── models/
│   ├── connection.py       # Connection data model
│   ├── application.py      # Application data model
│   └── alert.py            # Alert data model
├── static/
│   ├── css/
│   │   └── style.css       # Dashboard styles
│   ├── js/
│   │   └── dashboard.js    # Auto-refresh, expand/collapse, filtering
│   └── help/
│       └── index.html      # Online help with ASCII screens
├── templates/
│   ├── dashboard.html      # Main dashboard template
│   ├── detail.html         # Connection detail view
│   ├── health.html         # Network health panel
│   ├── settings.html       # Settings view
│   └── help.html           # Help view
├── config.py               # Default settings, port lists, VPS providers
└── utils.py                # Byte formatting, helpers
```

### 5.3 Data Flow

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   lsof -i   │     │   nettop     │     │  netstat -an │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       ▼                   ▼                   ▼
┌──────────────────────────────────────────────────────┐
│                  Collectors Layer                      │
│  Parse raw CLI output into structured Python objects  │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│                 Enrichment Layer                       │
│  DNS reverse lookup ← cached                          │
│  Whois lookup ← cached                                │
│  Codesign check ← cached                              │
│  Process info (CPU/mem) ← live                        │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│                  Analysis Layer                        │
│  Apply threat flags per connection                    │
│  Calculate threat score per application               │
│  Detect new connections → generate alerts             │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│                   Flask Backend                        │
│  /api/connections → JSON (all data)                   │
│  /api/alerts → JSON (active alerts)                   │
│  /api/health → JSON (system network stats)            │
│  /api/whois/<ip> → JSON (full whois for detail view)  │
│  / → dashboard.html                                   │
└──────────────────────┬───────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────┐
│                  Web Frontend                          │
│  Polls /api/connections every N seconds               │
│  Renders grouped app cards with threat badges         │
│  Expand/collapse, search, filter, sort                │
│  Click-through to detail popovers                     │
└──────────────────────────────────────────────────────┘
```

### 5.4 Caching Strategy

| Data | Cache TTL | Reason |
|------|-----------|--------|
| Reverse DNS | 10 minutes | DNS records change infrequently |
| Whois | 24 hours | Organization ownership rarely changes |
| Codesign | Session lifetime | Binary signatures are static |
| lsof/nettop/netstat | No cache (live) | Must be current |
| Process info | No cache (live) | CPU/mem change constantly |

### 5.5 Performance Considerations

- `lsof -i -n -P` (with `-n` to skip DNS, `-P` to skip port names) runs in ~100ms
- `nettop -L 1` runs in ~500ms
- DNS reverse lookups are async and cached to avoid blocking
- Whois lookups are triggered on-demand (when user clicks) or lazy-loaded in background
- Target: dashboard fully rendered within 1 second of refresh

---

## 6. API Endpoints

| Method | Path | Description | Response |
|--------|------|-------------|----------|
| GET | `/` | Main dashboard | HTML |
| GET | `/health` | Network health panel | HTML |
| GET | `/settings` | Settings page | HTML |
| GET | `/help` | Online help | HTML |
| GET | `/api/connections` | All connections grouped by app | JSON |
| GET | `/api/alerts` | Active alerts | JSON |
| GET | `/api/health` | System network stats | JSON |
| GET | `/api/whois/<ip>` | Full whois for an IP | JSON |
| GET | `/api/process/<pid>` | Process detail (codesign, path) | JSON |
| POST | `/api/settings` | Update settings | JSON |
| GET | `/api/export?format=json` | Export all data | JSON |
| GET | `/api/export?format=csv` | Export all data | CSV |

---

## 7. UI Screens

See `ASCII_SCREENS.md` for detailed ASCII mockups of each screen.

### 7.1 Screen List

1. **Main Dashboard** — Summary bar, alerts panel, application groups with connection tables
2. **Connection Detail Popover** — Full info for a single connection (whois, DNS, history)
3. **Network Health Panel** — WiFi quality, interface stats, TCP health, charts
4. **Alerts Panel (expanded)** — Full list of all alerts with filtering
5. **Settings** — Configuration options
6. **Online Help** — Usage guide with ASCII screen mockups

---

## 8. Installation & Requirements

### 8.1 System Requirements

- macOS 12 (Monterey) or later
- Python 3.10+
- No root access required (lsof/nettop work at user level for user-owned processes)
- Optional: `sudo` for full visibility into all processes

### 8.2 Python Dependencies

- Flask (web framework)
- No other external dependencies — all data comes from macOS CLI tools and Python stdlib

### 8.3 Installation

```bash
git clone <repo-url>
cd netwatch
pip install -r requirements.txt
python -m netwatch
# Opens browser to http://localhost:8077
```

---

## 9. Future Enhancements (v2+)

| Feature | Description | Requires |
|---------|-------------|----------|
| DNS query logging | See which apps look up which domains | NEDNSProxyProvider (Apple entitlement) |
| Original hostname per flow | See "api.stripe.com" not just an IP | NEFilterDataProvider (Apple entitlement) |
| Kernel-level app identity | Unforgeable process identity | Endpoint Security (Apple entitlement) |
| GeoIP mapping | Visual map of connection destinations | MaxMind GeoLite2 database |
| Historical trends | Store connection data over time, show graphs | SQLite or similar |
| Menu bar widget | Quick glance at connection count and alerts | PyObjC or Swift companion app |
| Notification Center | Push alerts for red flags to macOS notifications | PyObjC |
| Process tree view | Show parent/child relationships between networked processes | proc_pidinfo |
| Packet capture | Deep inspection of suspicious connections | BPF / libpcap (requires root) |
| Rate limiting detection | Detect throttling by ISP or service | Statistical analysis of throughput over time |

---

## 10. Glossary

| Term | Definition |
|------|-----------|
| **ESTABLISHED** | TCP connection fully open and active |
| **LISTEN** | App waiting for incoming connections on a port |
| **CLOSE_WAIT** | Remote side closed, local app hasn't finished closing |
| **TIME_WAIT** | Connection closed, waiting for stale packets to expire |
| **rDNS** | Reverse DNS — looking up a hostname from an IP address |
| **whois** | Protocol for querying ownership of IP addresses and domains |
| **MSS** | Maximum Segment Size — largest TCP payload per packet |
| **RTT** | Round-Trip Time — latency of a connection |
| **CIDR** | Classless Inter-Domain Routing — IP address range notation |
| **C2** | Command and Control — server used by malware to receive instructions |
| **MITM** | Man-in-the-Middle — attack where traffic is intercepted |
| **codesign** | macOS mechanism for verifying app authenticity via cryptographic signatures |
| **SSE** | Server-Sent Events — one-way server-to-browser push over HTTP |
