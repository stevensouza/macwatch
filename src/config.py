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

# Cache TTLs (seconds)
DNS_CACHE_TTL = 600  # 10 minutes
WHOIS_CACHE_TTL = 86400  # 24 hours

# Score level thresholds
SCORE_LEVELS = {
    "clean": (0, 0),
    "low": (1, 2),
    "medium": (3, 5),
    "high": (6, float("inf")),
}
