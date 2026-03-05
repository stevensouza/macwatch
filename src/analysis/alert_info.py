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
    "high_cpu": {
        "title": "High CPU Usage",
        "severity": "yellow",
        "weight": 0,
        "category": "cpu",
        "what": (
            "This process is consuming more than 80% of your CPU. Sustained high "
            "CPU usage can slow down your entire system and drain battery life on "
            "laptops."
        ),
        "why": (
            "High CPU usage is normal during intensive tasks like compiling code, "
            "rendering video, or running simulations. However, unexplained CPU spikes "
            "from unfamiliar processes could indicate malware (crypto miners), runaway "
            "loops, or software bugs."
        ),
        "typical": (
            "Common for: compilers (gcc, clang, javac), video editors, browsers with "
            "heavy tabs, Spotlight indexing (mds_stores), software updates, and "
            "virtualization (Docker, VMs)."
        ),
        "action": (
            "If you recognize the process and it is performing expected work, no action "
            "needed. If the high usage persists unexpectedly, consider restarting the "
            "application. Use the process detail to check its command line and parent "
            "process for clues."
        ),
    },
    "high_memory": {
        "title": "High Memory Usage",
        "severity": "yellow",
        "weight": 0,
        "category": "memory",
        "what": (
            "This process is using more than 15% of your total system memory. Large "
            "memory consumers can force macOS to swap to disk, significantly slowing "
            "down your system."
        ),
        "why": (
            "Memory-intensive processes reduce available RAM for other applications. "
            "When physical memory runs out, macOS compresses pages and swaps to disk, "
            "causing noticeable slowdowns. A single process consuming excessive memory "
            "may indicate a memory leak."
        ),
        "typical": (
            "Common for: web browsers (especially with many tabs), IDEs (Xcode, "
            "IntelliJ), Docker containers, Electron apps (Slack, VS Code), and "
            "database servers."
        ),
        "action": (
            "Check if the memory usage is expected for the workload. If a process's "
            "memory keeps growing over time, it may have a memory leak — restarting "
            "it will reclaim the memory."
        ),
    },
    "system_cpu_critical": {
        "title": "Critical System CPU Load",
        "severity": "red",
        "weight": 0,
        "category": "cpu",
        "what": (
            "Overall system CPU usage exceeds 90%. Your Mac is under heavy load and "
            "may feel sluggish or unresponsive."
        ),
        "why": (
            "At this level, all CPU cores are nearly saturated. User interface "
            "responsiveness drops, applications may hang, and background tasks "
            "compete for limited resources. Battery drain on laptops will be "
            "significantly increased."
        ),
        "typical": (
            "Normal during: software compilation, video encoding, large file "
            "compression, system updates, or running multiple resource-intensive "
            "applications simultaneously."
        ),
        "action": (
            "Check the Processes tab to identify which applications are consuming the "
            "most CPU. Close unnecessary applications or wait for intensive tasks to "
            "complete. If no obvious cause is found, look for runaway processes."
        ),
    },
    "system_cpu_high": {
        "title": "High System CPU Load",
        "severity": "yellow",
        "weight": 0,
        "category": "cpu",
        "what": (
            "Overall system CPU usage exceeds 75%. Your Mac is working hard but should "
            "still be responsive."
        ),
        "why": (
            "Elevated CPU usage means more than three quarters of your processing power "
            "is in use. The system should still feel responsive, but adding more "
            "demanding tasks may cause slowdowns."
        ),
        "typical": (
            "Common during active work with multiple applications, background updates, "
            "or moderate workloads like web browsing with many tabs."
        ),
        "action": (
            "Usually no action needed. Check the Processes tab if you notice slowdowns "
            "to identify the biggest CPU consumers."
        ),
    },
    "system_memory_critical": {
        "title": "Critical Memory Pressure",
        "severity": "red",
        "weight": 0,
        "category": "memory",
        "what": (
            "System memory usage exceeds 90%. macOS is likely swapping heavily to disk, "
            "which significantly degrades performance."
        ),
        "why": (
            "When physical memory is nearly exhausted, macOS must compress memory pages "
            "and write them to disk (swap). Disk I/O is orders of magnitude slower than "
            "RAM, causing noticeable lag, slow app launches, and spinning beach balls."
        ),
        "typical": (
            "Common when: running many applications simultaneously, working with large "
            "files (video editing, large spreadsheets), or running virtual machines."
        ),
        "action": (
            "Close applications you are not actively using. Check the Processes tab to "
            "find the largest memory consumers. If this is chronic, your workload may "
            "require more RAM."
        ),
    },
    "system_memory_high": {
        "title": "High Memory Usage",
        "severity": "yellow",
        "weight": 0,
        "category": "memory",
        "what": (
            "System memory usage exceeds 80%. Your Mac still has some memory headroom "
            "but is approaching the point where performance may degrade."
        ),
        "why": (
            "At this level, macOS may start compressing memory pages to free up space. "
            "Adding more applications or opening large files could push the system into "
            "active swapping."
        ),
        "typical": (
            "Normal for typical multitasking with browsers, IDEs, and communication "
            "apps open simultaneously."
        ),
        "action": (
            "Keep an eye on memory usage. If you plan to open resource-intensive "
            "applications, consider closing some existing ones first."
        ),
    },
    "system_disk_critical": {
        "title": "Critical Disk Space",
        "severity": "red",
        "weight": 0,
        "category": "disk",
        "what": (
            "Root volume disk usage exceeds 95%. Your Mac is critically low on disk "
            "space, which can cause system instability."
        ),
        "why": (
            "macOS needs free disk space for virtual memory (swap files), temporary "
            "files, system updates, and application caches. When disk space runs out, "
            "applications may crash, the system may become unbootable, and data loss "
            "can occur."
        ),
        "typical": (
            "This is never normal and should always be addressed. Common causes: large "
            "media files, overgrown caches, old Time Machine snapshots, or accumulated "
            "downloads."
        ),
        "action": (
            "Free up disk space immediately. Check Storage in System Settings, empty "
            "the Trash, clear browser caches, remove unused applications, and consider "
            "moving large files to external storage."
        ),
    },
    "system_disk_high": {
        "title": "High Disk Usage",
        "severity": "yellow",
        "weight": 0,
        "category": "disk",
        "what": (
            "Root volume disk usage exceeds 85%. While not immediately critical, you "
            "are running low on free space."
        ),
        "why": (
            "Leaving less than 15% free space can impact system performance and prevent "
            "macOS from performing updates. Some applications need substantial temporary "
            "space for operations like video editing or software compilation."
        ),
        "typical": (
            "Common on Macs with smaller SSDs (256 GB or 512 GB) when working with "
            "large projects or media files."
        ),
        "action": (
            "Consider cleaning up unnecessary files. Check Storage in System Settings "
            "for recommendations. Plan to free space before it becomes critical."
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
