"""Educational context for each alert type in MacWatch."""

ALERT_INFO = {
    "unsigned_app": {
        "title": "Unsigned Application",
        "severity": "red",
        "weight": 3,
        "what": (
            "This application has no valid Apple code signature. Code signing is a "
            "cryptographic mechanism where Apple or a registered developer attests "
            "that the binary has not been tampered with since it was built."
        ),
        "why": (
            "Unsigned apps cannot be verified as coming from a known developer. "
            "Malware almost always lacks a valid signature. An unsigned app making "
            "network connections could be exfiltrating data or participating in a "
            "botnet."
        ),
        "typical": (
            "Common for: homebrew-installed CLI tools (python3, node, curl built "
            "from source), open-source utilities, developer scripts, and apps "
            "downloaded outside the Mac App Store. Many legitimate tools are unsigned."
        ),
        "action": (
            "If you recognize this app and installed it yourself, it is likely fine. "
            "If you do not recognize it, investigate the binary path shown in the "
            "process detail. Consider checking its hash on VirusTotal."
        ),
    },
    "http_plaintext": {
        "title": "Plaintext HTTP Connection",
        "severity": "red",
        "weight": 3,
        "what": (
            "This app is communicating over port 80 (HTTP) without TLS encryption. "
            "Any data sent or received -- including credentials, cookies, and page "
            "content -- travels in cleartext and can be intercepted by anyone on the "
            "same network."
        ),
        "why": (
            "Plaintext HTTP is a serious privacy and security risk. Attackers on the "
            "same Wi-Fi network (coffee shops, airports) can read and modify this "
            "traffic using trivial tools (a technique called man-in-the-middle)."
        ),
        "typical": (
            "Some apps still use HTTP for non-sensitive requests like captive portal "
            "detection, software update checks, or local-network device communication. "
            "macOS itself uses HTTP to check for captive portals."
        ),
        "action": (
            "Check if the remote host is a local device (router, printer) or a "
            "well-known service. If this is an app transmitting personal data over "
            "HTTP, consider switching to an alternative that uses HTTPS."
        ),
    },
    "high_upload_ratio": {
        "title": "High Upload Ratio",
        "severity": "red",
        "weight": 3,
        "what": (
            "This app is sending significantly more data than it is receiving. The "
            "upload-to-download ratio exceeds the configured threshold, which is "
            "unusual for most consumer applications."
        ),
        "why": (
            "Most apps download more than they upload (web browsing, streaming, "
            "updates). A high upload ratio can indicate data exfiltration, file "
            "sharing, or a compromised machine sending data to an attacker."
        ),
        "typical": (
            "Common for: cloud backup services (Backblaze, Time Machine to NAS), "
            "file sync tools (Dropbox uploading new files), video conferencing "
            "(sending your camera feed), and torrent clients seeding."
        ),
        "action": (
            "Check what app this is. If it is a known backup or sync tool, the ratio "
            "is expected. If it is an unfamiliar process uploading large amounts of "
            "data, investigate immediately."
        ),
    },
    "unusual_port": {
        "title": "Non-Standard Port",
        "severity": "yellow",
        "weight": 2,
        "what": (
            "This connection uses a port number outside the standard set (HTTP/80, "
            "HTTPS/443, SSH/22, DNS/53, etc.). Non-standard ports are less "
            "predictable and harder to monitor."
        ),
        "why": (
            "While many legitimate services use non-standard ports, malware and "
            "command-and-control channels also use unusual ports to evade firewall "
            "rules and detection. The port number alone is not conclusive."
        ),
        "typical": (
            "Common for: development servers (3000, 5000, 8080), gaming services, "
            "VPN tunnels, database connections, and many cloud APIs that run on "
            "custom ports. Ephemeral/high ports (49000+) are normal for outbound "
            "connections as the OS assigns them dynamically."
        ),
        "action": (
            "Look at the remote host and organization. If the port belongs to a "
            "recognized service (e.g., a game server or development tool), it is "
            "normal. If the combination of unknown port + unknown host + unsigned "
            "app occurs, investigate further."
        ),
    },
    "no_rdns": {
        "title": "No Reverse DNS",
        "severity": "yellow",
        "weight": 2,
        "what": (
            "The remote IP address has no reverse DNS (PTR) record. Reverse DNS maps "
            "an IP back to a hostname, and its absence means the IP owner has not "
            "configured this record."
        ),
        "why": (
            "Most major services (Google, Apple, Amazon) configure reverse DNS for "
            "their IP ranges. The absence of rDNS can indicate a hastily provisioned "
            "server, a VPS being used for temporary purposes, or infrastructure that "
            "does not follow best practices."
        ),
        "typical": (
            "Very common for: CDN edge nodes (Fastly, Cloudflare), some cloud "
            "provider IPs (AWS, GCP), small hosting companies, and residential ISP "
            "connections. The 151.101.x.x range (Fastly) often lacks rDNS but serves "
            "major sites like Reddit and GitHub. Lack of rDNS alone is a weak signal."
        ),
        "action": (
            "Check the WHOIS organization for the IP. If it belongs to a known "
            "provider (Akamai, Cloudflare, Fastly, AWS), the missing rDNS is "
            "cosmetic. If the org is also unknown, combine this with other flags to "
            "assess risk."
        ),
    },
    "vps_provider": {
        "title": "VPS/Hosting Provider",
        "severity": "yellow",
        "weight": 2,
        "what": (
            "The remote IP belongs to a hosting or VPS (Virtual Private Server) "
            "provider such as DigitalOcean, Linode, Hetzner, or Vultr. These are "
            "infrastructure-as-a-service companies where anyone can rent a server."
        ),
        "why": (
            "While many legitimate services run on VPS providers, these are also "
            "popular for hosting command-and-control servers, phishing pages, and "
            "data collection endpoints because they are cheap, anonymous, and "
            "disposable."
        ),
        "typical": (
            "Common for: indie web services, small SaaS products, personal projects, "
            "CI/CD infrastructure, and developer tools. Many legitimate APIs run on "
            "DigitalOcean or Linode."
        ),
        "action": (
            "Check what app is connecting and whether you recognize the service. If "
            "a system daemon or unfamiliar app is connecting to a VPS with no rDNS, "
            "that combination warrants investigation."
        ),
    },
    "system_daemon_external": {
        "title": "System Daemon External Connection",
        "severity": "yellow",
        "weight": 2,
        "what": (
            "A built-in macOS system daemon (like mDNSResponder, airportd, or "
            "symptomsd) is making a connection to an external (non-private) IP "
            "address."
        ),
        "why": (
            "System daemons are expected to communicate locally or with Apple "
            "servers. External connections to non-Apple IPs could indicate DNS "
            "hijacking, network misconfiguration, or in rare cases, exploitation of "
            "a system service."
        ),
        "typical": (
            "Common for: mDNSResponder connecting to DNS servers, symptomsd checking "
            "Apple analytics endpoints, trustd verifying certificates with Apple OCSP "
            "servers. These are usually benign Apple telemetry."
        ),
        "action": (
            "Check the remote IP's WHOIS organization. If it resolves to Apple or "
            "your ISP's DNS servers, this is normal. If it is connecting to an "
            "unknown third-party server, investigate your DNS configuration."
        ),
    },
    "high_retransmissions": {
        "title": "High Retransmissions",
        "severity": "blue",
        "weight": 1,
        "what": (
            "This app has a high number of TCP retransmissions, meaning packets had "
            "to be re-sent because they were lost or corrupted in transit."
        ),
        "why": (
            "High retransmissions indicate network quality issues -- packet loss, "
            "congestion, or a flaky connection. While not a direct security threat, "
            "they can indicate a degraded or tampered network path."
        ),
        "typical": (
            "Common when: on spotty Wi-Fi, connected to a distant server, the "
            "network is congested, or a VPN adds overhead. Restarting Wi-Fi or "
            "moving closer to the router often helps."
        ),
        "action": (
            "This is a network quality indicator, not a security alert. If "
            "performance is fine, you can ignore it. If you are experiencing "
            "slowness, check your network connection quality."
        ),
    },
    "many_unique_ips": {
        "title": "Many Unique Remote IPs",
        "severity": "blue",
        "weight": 1,
        "what": (
            "This app is connected to 20 or more distinct remote IP addresses "
            "simultaneously. This is higher than typical for most applications."
        ),
        "why": (
            "While CDN-heavy apps naturally connect to many IPs, an unusually high "
            "count could indicate port scanning, distributed communication patterns, "
            "or peer-to-peer networking."
        ),
        "typical": (
            "Common for: web browsers (each tab may connect to multiple CDN nodes), "
            "torrent clients, Slack/Discord (connecting to media CDNs), and apps "
            "using distributed architectures."
        ),
        "action": (
            "For web browsers and communication apps, many unique IPs is expected. "
            "For a simple utility or unfamiliar app, a high IP count is worth a "
            "closer look at what those connections are."
        ),
    },
    "listen_all_interfaces": {
        "title": "Listening on All Interfaces",
        "severity": "blue",
        "weight": 1,
        "what": (
            "This app is listening for incoming connections on 0.0.0.0 (all network "
            "interfaces) rather than just localhost (127.0.0.1). This means other "
            "devices on your network could potentially connect to it."
        ),
        "why": (
            "Listening on all interfaces exposes the service to your local network. "
            "If your machine is on a public or shared network, other users could "
            "attempt to connect to this service."
        ),
        "typical": (
            "Common for: development servers (webpack, React dev server, Spring "
            "Boot), local databases (PostgreSQL, Redis), file sharing services, and "
            "AirDrop/Handoff related services on macOS."
        ),
        "action": (
            "If this is a development server, ensure you are on a trusted network. "
            "If you do not recognize the process, check what service it provides "
            "and whether it should be network-accessible."
        ),
    },
    "new_connection": {
        "title": "New Connection Detected",
        "severity": "info",
        "weight": 0,
        "what": (
            "This is the first time MacWatch has seen this app connect to this "
            "particular host since monitoring started."
        ),
        "why": (
            "New connections are tracked to help you notice when apps start "
            "communicating with servers they have not contacted before. This can "
            "help detect changes in app behavior over time."
        ),
        "typical": (
            "New connections appear frequently during normal use -- opening a new "
            "website, starting an app, or an app updating its content. Most are "
            "completely benign."
        ),
        "action": (
            "No action needed unless the new connection is to an unexpected or "
            "suspicious host. This is purely informational to help you track changes."
        ),
    },
}


def get_alert_info(alert_type):
    """Return educational info for a specific alert type, or a default."""
    return ALERT_INFO.get(alert_type, {
        "title": alert_type.replace("_", " ").title(),
        "severity": "blue",
        "weight": 0,
        "what": "No additional information available for this alert type.",
        "why": "",
        "typical": "",
        "action": "",
    })


def get_all_alert_info():
    """Return the complete alert info dictionary."""
    return ALERT_INFO
