# MacWatch Phase 1 Implementation Plan

Expand MacWatch from a network-only monitor into a full system health dashboard with top tab bar navigation, health scoring, and CPU & Memory metrics.

---

## Scope

1. Top tab bar navigation: Overview | Network | CPU & Memory
2. Overview tab — highlights/summary from all subsystems with health scores
3. CPU & Memory tab — detailed CPU and memory metrics
4. Health scoring system (0–100 per subsystem)

---

## 1. Top Tab Bar Navigation

Add a tab bar between the header and `<main>` in `src/templates/dashboard.html`:

```html
<nav class="tab-bar" id="tab-bar">
  <button class="tab active" data-section="overview">Overview</button>
  <button class="tab" data-section="network">Network</button>
  <button class="tab" data-section="cpu-memory">CPU & Memory</button>
</nav>
```

**CSS additions in `src/static/css/style.css`:**
- `.tab-bar` — horizontal flex bar, glassmorphism style matching header/footer
- `.tab` — pill-shaped buttons, teal accent on active, smooth transitions
- Health score dot badges on tabs (small colored circle next to tab label)

**JS changes in `src/static/js/dashboard.js`:**
- `activeSection` state variable (default: `'overview'`)
- `switchSection(name)` — hides all `.section-panel` divs, shows the active one, updates tab `.active` class
- Each section has its own fetch function and refresh timer
- When switching away from a section, pause its polling; resume when switching back
- The Network section reuses all existing rendering code unchanged

**Layout:** `<main>` gets wrapped section panels:

```html
<main>
  <div class="section-panel" id="section-overview">...</div>
  <div class="section-panel" id="section-network">
    <!-- existing summary-bar, alerts-panel, app-list moved here -->
  </div>
  <div class="section-panel" id="section-cpu-memory">...</div>
</main>
```

---

## 2. New Collectors

### `src/collectors/system.py` (new file)

Three functions following the existing collector pattern (subprocess with timeout, try/except, return safe defaults):

**`collect_cpu()`** — runs `top -l 1 -n 0 -s 0`
- Returns: `{user_pct, sys_pct, idle_pct, load_1m, load_5m, load_15m, process_count, thread_count}`

**`collect_memory()`** — runs `vm_stat` + `sysctl hw.memsize` + `sysctl vm.swapusage`
- Returns: `{total_bytes, used_bytes, free_bytes, active_bytes, inactive_bytes, wired_bytes, compressed_bytes, swap_total, swap_used, swap_free, pressure_level}`
- Page size: use `sysctl vm.pagesize` (16384 on Apple Silicon)

**`collect_system_info()`** — runs `sysctl machdep.cpu.brand_string`, `sw_vers`, `sysctl kern.boottime`
- Returns: `{cpu_model, os_version, os_build, uptime_seconds, uptime_formatted, logical_cpus}`
- Called once on startup and cached (static info)

### `src/collectors/process.py` (modify existing)

Expand `collect_ps()` to also return `rss` (resident memory in KB):
- Change command to `ps -eo pid,pcpu,pmem,rss,comm`
- Add `rss` field to returned dict per process

---

## 3. Health Scoring — `src/analysis/health.py` (new file)

```python
def score_cpu(cpu_data) -> dict:       # {score: 0-100, level: str, color: str}
def score_memory(mem_data) -> dict:    # {score: 0-100, level: str, color: str}
def score_network(summary) -> dict:    # {score: 0-100, level: str, color: str}
def overall_score(scores) -> dict:     # weighted average
def score_to_level(score) -> tuple:    # (level_name, css_color)
```

Score-to-color: 80–100=green, 60–79=yellow, 40–59=orange, 0–39=red

- **CPU score:** Based on idle% (60% weight) and load average normalized to core count (40% weight)
- **Memory score:** `100 - (used/total * 100)`, with penalty if swap is heavily used
- **Network score:** Inverse of threat severity — `100 - (red_count * 15 + yellow_count * 5)`

---

## 4. New API Routes — `src/app.py`

```
GET /api/system    → {cpu: {...}, memory: {...}, system_info: {...}, top_processes: [...]}
GET /api/overview  → {health_scores: {cpu: {}, memory: {}, network: {}}, highlights: [...]}
```

- `/api/system` calls `system.collect_cpu()`, `system.collect_memory()`, returns top-10 processes from `process.collect_ps()`
- `/api/overview` calls both `/api/system` data and network summary, computes health scores
- TTL caching: CPU/memory cached for 3s, system_info cached permanently (1 hour)
- The existing `/api/connections` endpoint stays **completely unchanged**

---

## 5. Config Additions — `src/config.py`

```python
# Cache TTLs for new endpoints
SYSTEM_CACHE_TTL = 3          # CPU/memory refresh
SYSTEM_INFO_CACHE_TTL = 3600  # Static info (1 hour)

# Health score thresholds
HEALTH_GREEN = 80
HEALTH_YELLOW = 60
HEALTH_ORANGE = 40

# CPU thresholds
CPU_LOAD_WARNING = 0.75
CPU_LOAD_CRITICAL = 1.0

# Memory thresholds
MEMORY_PRESSURE_WARNING = 0.80
MEMORY_PRESSURE_CRITICAL = 0.92
```

---

## 6. Frontend — Overview Tab

The Overview is the "highlights" tab showing the most important info at a glance:

**Health score cards row** (similar to existing summary-bar):
- CPU card: score badge + current usage% + load average
- Memory card: score badge + used/total + pressure indicator
- Network card: score badge + connection count + alert count
- Overall score: large number with color

**System info block:** CPU model, macOS version, uptime, total RAM

**Highlights list** (auto-generated):
- "Memory pressure is high (87% used)"
- "3 apps have elevated threat scores"
- "CPU load average is 4.2 (above 75% of 8 cores)"
- "All systems normal" when everything is green

---

## 7. Frontend — CPU & Memory Tab

**CPU section:**
- Three horizontal gauge bars: User% / System% / Idle%
- Load averages: three numbers (1m / 5m / 15m)
- Top 10 processes table: Process Name | PID | CPU% | MEM% | RSS

**Memory section:**
- Stacked horizontal bar: Wired | Active | Inactive | Compressed | Free
- Key stats grid: Total, Used, Free, Compressed, Swap Used/Total
- Color thresholds matching health scores

Both sections reuse the existing glassmorphism card styling.

---

## 8. Utils Additions — `src/utils.py`

```python
def format_duration(seconds):  # "6d 16h 32m"
def format_percent(value):     # "87.3%"
```

Also move `_is_private()` from `app.py` to `utils.py` (currently duplicated in `app.py` and `threat.py`).

---

## File Summary

### New files

| File | Purpose |
|------|---------|
| `src/collectors/system.py` | CPU, memory, system info collectors |
| `src/analysis/health.py` | Health scoring (0–100) per subsystem |

### Modified files

| File | Changes |
|------|---------|
| `src/templates/dashboard.html` | Add tab bar, section panels |
| `src/static/css/style.css` | Tab bar, gauge bars, health cards, section panels |
| `src/static/js/dashboard.js` | Section switching, new renderers, per-section polling |
| `src/app.py` | 2 new routes (`/api/system`, `/api/overview`), TTL caching |
| `src/config.py` | New cache TTLs, health thresholds |
| `src/utils.py` | `format_duration()`, `format_percent()`, move `_is_private()` |
| `src/collectors/process.py` | Add `rss` to `collect_ps()` |
| `src/templates/help.html` | Update for new sections |

---

## Future Phases (not in this phase)

- **Disk tab:** `collectors/disk.py` — `iostat` for I/O throughput, `df -Pk` for storage volumes
- **Battery tab:** `collectors/battery.py` — `pmset` + `ioreg AppleSmartBattery`
- **Time-series storage:** SQLite to persist metrics across runs
- **AI analysis:** Pass collected metrics as JSON to a local Ollama model; swappable API backends (Ollama, OpenAI, Anthropic)
