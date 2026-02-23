# MacWatch

A macOS system health monitoring dashboard. MacWatch gives you a real-time view of your Mac's network connections, CPU usage, memory pressure, disk activity, and more — all in a local web dashboard with zero cloud dependencies.

## Features

- **Network monitoring** — see which apps have open connections, where they connect, traffic stats, and threat assessment
- **System health** — CPU usage, load averages, memory breakdown, and top processes
- **Health scores** — 0–100 scores per subsystem with color-coded indicators
- **Threat scoring** — 10 flag types flagging suspicious network behavior

## Quick Start

```bash
pip install flask
python -m macwatch
```

Then open [http://127.0.0.1:8077](http://127.0.0.1:8077)

## Requirements

- macOS (uses `lsof`, `nettop`, `ps`, `vm_stat`, `top`, `sysctl`)
- Python 3.10+
- Flask (`pip install flask`)

## Architecture

```
macwatch/
├── app.py              # Flask routes and data orchestration
├── config.py           # Constants and thresholds
├── utils.py            # Shared helpers
├── collectors/         # Data collection (lsof, nettop, ps, system stats)
├── enrichment/         # DNS reverse lookup, WHOIS
├── analysis/           # Threat scoring, health scoring
├── templates/          # HTML pages
└── static/             # CSS and JavaScript
```

## Privacy

MacWatch runs entirely locally. No data is sent anywhere. All analysis uses macOS built-in tools (`lsof`, `nettop`, `whois`, etc.).
