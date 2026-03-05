/* MacWatch — Dashboard Overview */

// --- Initialization ---

document.addEventListener('DOMContentLoaded', () => {
    if (window.__INITIAL_DATA__ && window.__SYSTEM_DATA__) {
        currentData = window.__INITIAL_DATA__;
        renderOverview(currentData, window.__SYSTEM_DATA__);
        updateRefreshTime();
    } else {
        refresh();
    }
    startAutoRefresh();
    setupRefreshIntervalListener();
    setupBaseKeyboardShortcuts();
});

// --- Data Fetching ---

async function refresh() {
    try {
        const [connResp, sysResp] = await Promise.all([
            fetch('/api/connections'),
            fetch('/api/system')
        ]);
        currentData = await connResp.json();
        const sysData = await sysResp.json();
        renderOverview(currentData, sysData);
        updateRefreshTime();
    } catch (err) {
        console.error('Refresh failed:', err);
    }
}

// --- Rendering ---

function renderOverview(data, sys) {
    renderSystemCards(sys);
    renderTopCPU(data.top_processes);
    renderTopNetwork(data.apps);
    renderAlertSummary(data.alerts, data.summary);
    updateAlertTabBadge(data.alerts, data.summary);
}

function renderSystemCards(sys) {
    // CPU
    document.getElementById('ov-cpu-value').textContent = sys.cpu_percent + '%';
    document.getElementById('ov-cpu-bar').style.width = Math.min(sys.cpu_percent, 100) + '%';
    document.getElementById('ov-cpu-bar').className = 'gauge-fill ' +
        (sys.cpu_percent > 80 ? 'gauge-red' : sys.cpu_percent > 50 ? 'gauge-yellow' : 'gauge-green');
    document.getElementById('ov-load').textContent =
        `Load: ${sys.load_avg_1.toFixed(2)} / ${sys.load_avg_5.toFixed(2)} / ${sys.load_avg_15.toFixed(2)}`;

    // Memory
    document.getElementById('ov-mem-value').textContent = sys.mem_percent + '%';
    document.getElementById('ov-mem-bar').style.width = Math.min(sys.mem_percent, 100) + '%';
    document.getElementById('ov-mem-bar').className = 'gauge-fill ' +
        (sys.mem_percent > 85 ? 'gauge-red' : sys.mem_percent > 70 ? 'gauge-yellow' : 'gauge-green');
    document.getElementById('ov-mem-detail').textContent = `${sys.mem_used_fmt} / ${sys.mem_total_fmt}`;

    // Disk
    document.getElementById('ov-disk-value').textContent = sys.disk_percent + '%';
    document.getElementById('ov-disk-bar').style.width = Math.min(sys.disk_percent, 100) + '%';
    document.getElementById('ov-disk-bar').className = 'gauge-fill ' +
        (sys.disk_percent > 90 ? 'gauge-red' : sys.disk_percent > 75 ? 'gauge-yellow' : 'gauge-green');
    document.getElementById('ov-disk-detail').textContent = `${sys.disk_used_fmt} / ${sys.disk_total_fmt}`;
}

function renderTopCPU(topProcesses) {
    const container = document.getElementById('ov-top-cpu');
    if (!container || !topProcesses) return;

    const top5 = topProcesses.slice(0, 5);
    if (top5.length === 0) {
        container.innerHTML = '<div class="top-procs-empty">No active processes</div>';
        return;
    }

    const rows = renderProcessTableRows(top5, { showRank: true, maxCommand: 40 });
    container.innerHTML = `<table class="top-procs-table compact">
        <thead><tr>
            <th>#</th>
            <th>Process</th>
            <th>PID</th>
            <th>CPU</th>
            <th>MEM</th>
            <th>Command</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

function renderTopNetwork(apps) {
    const container = document.getElementById('ov-top-network');
    if (!container || !apps) return;

    // Sort by total traffic (in + out) descending, take top 5
    const sorted = [...apps].sort((a, b) =>
        (b.bytes_in + b.bytes_out) - (a.bytes_in + a.bytes_out)
    ).slice(0, 5);

    if (sorted.length === 0) {
        container.innerHTML = '<div class="top-procs-empty">No network-connected apps</div>';
        return;
    }

    const rows = sorted.map((app, i) => {
        const displayName = app.display_name || app.app;
        const threatClass = app.threat_color;
        return `<tr>
            <td class="top-proc-rank">${i + 1}</td>
            <td class="top-proc-name">${esc(displayName)}</td>
            <td class="ov-net-conns">${app.connection_count}</td>
            <td class="ov-net-in">
                <svg viewBox="0 0 12 12" fill="none" width="10" height="10"><path d="M6 2v8M3 7l3 3 3-3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                ${app.bytes_in_fmt}
            </td>
            <td class="ov-net-out">
                <svg viewBox="0 0 12 12" fill="none" width="10" height="10"><path d="M6 10V2M3 5l3-3 3 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                ${app.bytes_out_fmt}
            </td>
            <td><span class="threat-badge ${threatClass}" style="font-size:0.7rem">${app.threat_score}</span></td>
        </tr>`;
    }).join('');

    container.innerHTML = `<table class="top-procs-table compact">
        <thead><tr>
            <th>#</th>
            <th>App</th>
            <th data-tooltip="Open network connections">Conn</th>
            <th>Traffic In</th>
            <th>Traffic Out</th>
            <th>Threat</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

function renderAlertSummary(alerts, summary) {
    const container = document.getElementById('ov-alert-summary');
    if (!container) return;

    const totalAlerts = (summary.red_count || 0) + (summary.yellow_count || 0) + (summary.blue_count || 0);

    if (totalAlerts === 0) {
        container.innerHTML = `<div class="ov-alert-clear">
            <span class="conn-flag flag-green"></span>
            All clear — no alerts detected
        </div>`;
        return;
    }

    // Find worst severity per category
    const catSeverity = {};
    const sevOrder = { red: 0, yellow: 1, blue: 2, info: 3 };
    alerts.forEach(a => {
        const cat = a.category || 'network';
        const cur = catSeverity[cat];
        if (!cur || sevOrder[a.severity] < sevOrder[cur]) {
            catSeverity[cat] = a.severity;
        }
    });

    const categories = [
        { key: 'network', label: 'Network', count: summary.network_count || 0 },
        { key: 'cpu', label: 'CPU', count: summary.cpu_count || 0 },
        { key: 'memory', label: 'Memory', count: summary.memory_count || 0 },
        { key: 'disk', label: 'Disk', count: summary.disk_count || 0 },
    ];

    let html = '<div class="ov-alert-bars">';
    for (const cat of categories) {
        if (cat.count === 0) continue;
        const sev = catSeverity[cat.key] || 'blue';
        html += `<div class="ov-alert-bar ov-alert-${sev}">
            <span class="alert-severity-dot sev-${sev}"></span>
            <span class="ov-alert-label">${cat.label}</span>
            <span class="ov-alert-count">${cat.count}</span>
        </div>`;
    }
    html += '</div>';

    container.innerHTML = html;
}
