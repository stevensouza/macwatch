"""Configuration defaults for NetWatch."""

# Server
HOST = "127.0.0.1"
PORT = 8077

# Refresh
DEFAULT_REFRESH_INTERVAL = 120  # seconds

# Standard ports (connections to these don't trigger "unusual port" flag)
STANDARD_PORTS = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3478: "STUN",
    5228: "GCM",
    5353: "mDNS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Known VPS/hosting providers (whois org name substrings)
VPS_PROVIDERS = [
    "digitalocean",
    "linode",
    "akamai connected cloud",
    "ovh",
    "ovhcloud",
    "hetzner",
    "vultr",
    "choopa",
]

# Major cloud providers (flagged at lower severity)
CLOUD_PROVIDERS = [
    "amazon",
    "aws",
    "google cloud",
    "google llc",
    "microsoft",
    "azure",
]

# Known system daemons
SYSTEM_DAEMONS = [
    "mdnsresponder",
    "airportd",
    "symptomsd",
    "sharingd",
    "identityserviced",
    "wifid",
    "configd",
    "trustd",
    "netbiosd",
    "nesessionmanager",
]

# Threat scoring weights
THREAT_WEIGHTS = {
    "unsigned_app": 3,
    "http_plaintext": 3,
    "high_upload_ratio": 3,
    "unusual_port": 2,
    "no_rdns": 2,
    "vps_provider": 2,
    "system_daemon_external": 2,
    "high_retransmissions": 1,
    "recv_q_backup": 1,
    "many_unique_ips": 1,
    "listen_all_interfaces": 1,
}

# Thresholds
UPLOAD_RATIO_THRESHOLD = 10  # flag when out > N * in
UPLOAD_MINIMUM_BYTES = 1_000_000  # ignore ratio below 1 MB
RETRANSMISSION_THRESHOLD = 1000
UNIQUE_IP_THRESHOLD = 20

# Per-app resource thresholds
APP_CPU_THRESHOLD = 80.0         # yellow: single app > 80% CPU
APP_MEMORY_THRESHOLD = 15.0      # yellow: single app > 15% system RAM

# System-wide resource thresholds
SYSTEM_CPU_HIGH = 75.0           # yellow
SYSTEM_CPU_CRITICAL = 90.0       # red
SYSTEM_MEMORY_HIGH = 80.0        # yellow
SYSTEM_MEMORY_CRITICAL = 90.0    # red
SYSTEM_DISK_HIGH = 85.0          # yellow
SYSTEM_DISK_CRITICAL = 95.0      # red

# Top Processes
TOP_PROCESSES_COUNT = 15

# Cache TTLs (seconds)
DNS_CACHE_TTL = 600  # 10 minutes
WHOIS_CACHE_TTL = 86400  # 24 hours

# AI Analysis
AI_DEFAULT_PROVIDER = "ollama"
AI_REQUEST_TIMEOUT = 120  # seconds (Ollama local models may be slower)

# Score level thresholds
SCORE_LEVELS = {
    "clean": (0, 0),
    "low": (1, 2),
    "medium": (3, 5),
    "high": (6, float("inf")),
}
