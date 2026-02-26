/* MacWatch Dashboard */

let refreshInterval = 30000;
let refreshTimer = null;
let paused = false;
let expandedApps = new Set();
let currentData = null;

// --- Tooltip definitions ---
const TOOLTIPS = {
    // Column headers
    'Remote Host': 'The resolved domain name of the remote server (via reverse DNS lookup). Shows "(no rDNS)" if the IP has no hostname record.',
    'IP': 'The IP address of the remote server this app is communicating with.',
    'Port': 'The network port on the remote server. Common ports: 443 = HTTPS (encrypted web), 80 = HTTP (unencrypted), 22 = SSH, 53 = DNS.',
    'Proto': 'The transport protocol. TCP = reliable ordered delivery (web, email). UDP = fast but unordered (video, DNS, gaming).',
    'State': 'The TCP connection state. ESTABLISHED = actively connected. LISTEN = waiting for incoming connections. CLOSE_WAIT = remote side disconnected.',
    'Org': 'The organization that owns this IP address, determined via WHOIS lookup. Helps identify who your apps are talking to.',
    'CC': 'Two-letter country code where the IP address is registered.',
    'Status': 'Threat assessment for this connection based on port, DNS, signing, and traffic pattern analysis.',

    // App meta
    'conn': 'Current open network sockets for this application (snapshot at each refresh).',
    'traffic_in': '↓ Total bytes received (downloaded) by this app — cumulative since the process started, not per-refresh.',
    'traffic_out': '↑ Total bytes sent (uploaded) by this app — cumulative since the process started, not per-refresh.',
    'cpu': 'CPU usage — instantaneous snapshot at the time of each refresh, not an average.',
    'mem': 'Memory (RAM) usage — instantaneous snapshot at the time of each refresh.',

    // Threat scores
    'threat_green': 'Threat Score: 0 (Clean). All connections look normal. No suspicious indicators detected.',
    'threat_yellow': 'Threat Score: Low. Minor concerns detected, usually benign. Worth a glance.',
    'threat_orange': 'Threat Score: Medium. Multiple concerns detected. Recommended to investigate.',
    'threat_red': 'Threat Score: High. Significant risk indicators found. You should investigate this application.',

    // Sign badges
    'signed': 'This app has a valid Apple code signature, confirming it was distributed by an identified developer.',
    'unsigned': 'WARNING: This app has no valid code signature. It cannot be verified as legitimate software.',
};

// --- Initialization ---

document.addEventListener('DOMContentLoaded', () => {
    if (window.__INITIAL_DATA__) {
        currentData = window.__INITIAL_DATA__;
        renderDashboard(currentData);
        document.getElementById('last-refresh').textContent =
            'Updated ' + new Date().toLocaleTimeString();
    } else {
        refresh();
    }
    startAutoRefresh();
    setupKeyboardShortcuts();
    setupFilterListeners();
});

// --- Data Fetching ---

async function refresh() {
    try {
        const resp = await fetch('/api/connections');
        currentData = await resp.json();
        renderDashboard(currentData);
        document.getElementById('last-refresh').textContent =
            'Updated ' + new Date().toLocaleTimeString();
    } catch (err) {
        console.error('Refresh failed:', err);
    }
}

// --- Rendering ---

function renderDashboard(data) {
    renderSummary(data.summary);
    renderAlerts(data.alerts);
    renderApps(data.apps);
}

function renderSummary(summary) {
    document.getElementById('app-count').textContent = summary.app_count;
    document.getElementById('conn-count').textContent = summary.connection_count;
    document.getElementById('bytes-in').textContent = summary.bytes_in_fmt;
    document.getElementById('bytes-out').textContent = summary.bytes_out_fmt;
}

function renderAlerts(alerts) {
    const counts = document.getElementById('alert-counts');
    const body = document.getElementById('alerts-body');

    if (alerts.length === 0) {
        counts.textContent = '';
        body.innerHTML = '<div class="alert-all-clear"><span class="conn-flag flag-green"></span> All connections look normal</div>';
        return;
    }

    const red = alerts.filter(a => a.severity === 'red').length;
    const yellow = alerts.filter(a => a.severity === 'yellow').length;
    const blue = alerts.filter(a => a.severity === 'blue').length;
    const parts = [];
    if (red) parts.push(`${red} critical`);
    if (yellow) parts.push(`${yellow} warning`);
    if (blue) parts.push(`${blue} info`);
    counts.textContent = '(' + parts.join(', ') + ')';

    body.innerHTML = alerts.map(alert => {
        return `<div class="alert-item">
            <span class="alert-severity sev-${alert.severity}" data-tooltip="${alertSeverityTooltip(alert.severity)}"></span>
            <span class="alert-text"><span class="alert-app">${esc(alert.app)}</span> ${esc(alert.description)}</span>
        </div>`;
    }).join('');
}

function alertSeverityTooltip(severity) {
    switch (severity) {
        case 'red': return 'Critical: Potentially dangerous activity that needs immediate attention';
        case 'yellow': return 'Warning: Unusual activity worth investigating';
        case 'blue': return 'Informational: Notable but likely benign activity';
        case 'info': return 'New: A connection to a previously unseen host was detected';
        default: return '';
    }
}

function renderApps(apps) {
    const container = document.getElementById('app-list');
    const search = document.getElementById('search').value.toLowerCase();
    const stateFilter = document.getElementById('state-filter').value;
    const threatFilter = document.getElementById('threat-filter').value;
    const showLocalhost = document.getElementById('show-localhost').checked;

    const filtered = apps.filter(app => {
        if (search) {
            const searchable = [
                app.app,
                ...app.connections.map(c => c.remote_host),
                ...app.connections.map(c => c.remote_addr),
                ...app.connections.map(c => c.whois_org),
                ...app.connections.map(c => String(c.remote_port)),
            ].join(' ').toLowerCase();
            if (!searchable.includes(search)) return false;
        }

        if (threatFilter === 'red' && app.threat_color !== 'red') return false;
        if (threatFilter === 'yellow' && !['red', 'yellow', 'orange'].includes(app.threat_color)) return false;
        if (threatFilter === 'hidegreen' && app.threat_color === 'green') return false;

        return true;
    });

    container.innerHTML = filtered.map((app, i) => {
        const appKey = `${app.app}:${app.pid}`;
        const isExpanded = expandedApps.has(appKey);

        let conns = app.connections;
        if (stateFilter) {
            conns = conns.filter(c => c.state === stateFilter);
        }
        if (!showLocalhost) {
            conns = conns.filter(c => {
                const addr = c.remote_addr || c.local_addr || '';
                return !addr.startsWith('127.') && addr !== '::1' && addr !== 'localhost';
            });
        }

        const signClass = app.signed ? 'signed' : 'unsigned';
        const signIcon = app.signed ? svgCheck() : svgX();
        const signLabel = app.signed ? (app.sign_authority || 'Signed') : 'Unsigned';
        const signTooltip = app.signed ? TOOLTIPS.signed + ' Signed by: ' + (app.sign_authority || 'Unknown') : TOOLTIPS.unsigned;

        const threatTooltip = TOOLTIPS['threat_' + app.threat_color] || '';

        return `<div class="app-card threat-${app.threat_color}" style="animation-delay: ${Math.min(i * 0.03, 0.3)}s">
            <div class="app-header" onclick="toggleApp('${escAttr(appKey)}')">
                <span class="app-toggle ${isExpanded ? 'expanded' : ''}">
                    <svg viewBox="0 0 20 20" fill="none"><path d="M7 4l6 6-6 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </span>
                <span class="app-name">${esc(app.app)}</span>
                <div class="app-meta">
                    <span class="app-meta-item" data-tooltip="${TOOLTIPS.conn}">
                        ${app.connection_count} conn
                    </span>
                    <span class="app-meta-item meta-in" data-tooltip="${TOOLTIPS.traffic_in}">
                        <svg viewBox="0 0 12 12" fill="none"><path d="M6 2v8M3 7l3 3 3-3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        ${app.bytes_in_fmt}
                    </span>
                    <span class="app-meta-item meta-out" data-tooltip="${TOOLTIPS.traffic_out}">
                        <svg viewBox="0 0 12 12" fill="none"><path d="M6 10V2M3 5l3-3 3 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        ${app.bytes_out_fmt}
                    </span>
                    <span class="app-meta-item" data-tooltip="${TOOLTIPS.cpu}">
                        <span class="meta-label">CPU</span> ${app.cpu.toFixed(1)}%
                    </span>
                    <span class="app-meta-item" data-tooltip="${TOOLTIPS.mem}">
                        <span class="meta-label">MEM</span> ${app.mem.toFixed(1)}%
                    </span>
                    <span class="sign-badge ${signClass}" data-tooltip="${escAttr(signTooltip)}">
                        ${signIcon} ${app.signed ? 'Signed' : 'Unsigned'}
                    </span>
                </div>
                <span class="threat-badge ${app.threat_color}" data-tooltip="${escAttr(threatTooltip)}">
                    ${app.threat_score}
                </span>
                <button class="app-info-btn" onclick="event.stopPropagation(); showProcessDetail(this)" data-app='${escAttr(JSON.stringify(app))}' data-tooltip="View process details">
                    <svg viewBox="0 0 16 16" fill="none" width="14" height="14"><circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.2"/><path d="M8 7v4M8 5.5v.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
                </button>
            </div>
            <div class="conn-table-wrapper ${isExpanded ? 'expanded' : ''}">
                ${renderConnTable(conns, app)}
            </div>
        </div>`;
    }).join('');
}

function renderConnTable(conns, app) {
    if (conns.length === 0) {
        return '<div class="conn-empty">No matching connections</div>';
    }

    const rows = conns.map(c => {
        const hostClass = c.remote_host === '(no rDNS)' ? 'conn-no-rdns' : 'conn-host';
        const portLabel = c.port_label ? `<span class="conn-port-label">${esc(c.port_label)}</span>` : '';
        const stateClass = (c.state || '').toLowerCase().replace('_', '-');
        const flagClass = connectionFlagClass(c.flags);
        const flagTooltip = connectionFlagTooltip(c.flags);

        return `<tr onclick="showConnectionDetail(${JSON.stringify(esc(JSON.stringify(c))).slice(1, -1)}, '${escAttr(app.app)}', ${app.pid})">
            <td class="${hostClass}">${esc(c.remote_host || '-')}</td>
            <td>${esc(c.remote_addr || '-')}</td>
            <td>${c.remote_port || '-'}${portLabel}</td>
            <td>${esc(c.protocol)}</td>
            <td><span class="conn-state ${stateClass}">${esc(c.state || '-')}</span></td>
            <td>${esc(c.whois_org || '-')}</td>
            <td>${esc(c.whois_country || '-')}</td>
            <td><span class="conn-flag ${flagClass}" data-tooltip="${escAttr(flagTooltip)}"></span></td>
        </tr>`;
    }).join('');

    return `<table class="conn-table">
        <thead><tr>
            <th data-tooltip="${escAttr(TOOLTIPS['Remote Host'])}">Remote Host</th>
            <th data-tooltip="${escAttr(TOOLTIPS['IP'])}">IP</th>
            <th data-tooltip="${escAttr(TOOLTIPS['Port'])}">Port</th>
            <th data-tooltip="${escAttr(TOOLTIPS['Proto'])}">Proto</th>
            <th data-tooltip="${escAttr(TOOLTIPS['State'])}">State</th>
            <th data-tooltip="${escAttr(TOOLTIPS['Org'])}">Org</th>
            <th data-tooltip="${escAttr(TOOLTIPS['CC'])}">CC</th>
            <th data-tooltip="${escAttr(TOOLTIPS['Status'])}">Status</th>
        </tr></thead>
        <tbody>${rows}</tbody>
    </table>`;
}

// --- Connection Detail Modal ---

function showConnectionDetail(connJson, appName, pid) {
    const conn = JSON.parse(connJson);
    const modal = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');

    const flagsHtml = (conn.flags && conn.flags.length > 0)
        ? conn.flags.map(f => `<div class="modal-flag">
            <span class="modal-flag-weight ${f.severity}">+${f.weight}</span>
            <span>${esc(f.description)}</span>
        </div>`).join('')
        : '<div class="modal-all-clear"><span class="conn-flag flag-green"></span> No flags - connection looks normal</div>';

    content.innerHTML = `
        <h3>Connection Detail</h3>

        <div class="modal-section">
            <h4>Connection</h4>
            <div class="detail-grid">
                <span class="detail-label">App</span>
                <span class="detail-value">${esc(appName)} <span style="color:var(--text-muted)">(PID ${pid})</span></span>
                <span class="detail-label">Local</span>
                <span class="detail-value">${esc(conn.local_addr || '?')}:${conn.local_port || '?'}</span>
                <span class="detail-label">Remote</span>
                <span class="detail-value">${esc(conn.remote_addr || '?')}:${conn.remote_port || '?'}</span>
                <span class="detail-label">Protocol</span>
                <span class="detail-value">${esc(conn.protocol)} ${conn.port_label ? '<span style="color:var(--text-muted)">(' + esc(conn.port_label) + ')</span>' : ''}</span>
                <span class="detail-label">State</span>
                <span class="detail-value">${esc(conn.state || '-')}</span>
                <span class="detail-label">Address Type</span>
                <span class="detail-value">${esc(conn.type || '-')}</span>
            </div>
        </div>

        <div class="modal-section">
            <h4>DNS</h4>
            <div class="detail-grid">
                <span class="detail-label">Reverse DNS</span>
                <span class="detail-value" style="${conn.remote_host === '(no rDNS)' ? 'color:var(--text-muted);font-style:italic' : ''}">${esc(conn.remote_host || '(no rDNS)')}</span>
            </div>
        </div>

        <div class="modal-section">
            <h4>WHOIS</h4>
            <div class="detail-grid">
                <span class="detail-label">Organization</span>
                <span class="detail-value">${esc(conn.whois_org || '-')}</span>
                <span class="detail-label">Country</span>
                <span class="detail-value">${esc(conn.whois_country || '-')}</span>
            </div>
            ${conn.remote_addr ? `<a href="#" class="modal-link" onclick="loadFullWhois('${esc(conn.remote_addr)}'); return false;">
                Load full WHOIS data
                <svg viewBox="0 0 12 12" fill="none" width="12" height="12"><path d="M4 8l4-4M4 4h4v4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
            </a>` : ''}
        </div>

        <div class="modal-section" id="full-whois"></div>

        <div class="modal-section">
            <h4>Threat Assessment</h4>
            ${flagsHtml}
        </div>
    `;

    modal.classList.add('visible');
}

async function loadFullWhois(ip) {
    const container = document.getElementById('full-whois');
    container.innerHTML = '<h4>Full WHOIS</h4><div style="color: var(--text-muted); font-size: 0.82rem;">Loading...</div>';

    try {
        const resp = await fetch(`/api/whois/${ip}`);
        const data = await resp.json();
        container.innerHTML = `<h4>Full WHOIS</h4>
            <div class="detail-grid">
                <span class="detail-label">Organization</span>
                <span class="detail-value">${esc(data.org || '-')}</span>
                <span class="detail-label">Network</span>
                <span class="detail-value">${esc(data.netname || '-')} ${data.cidr ? '<span style="color:var(--text-muted)">(' + esc(data.cidr) + ')</span>' : ''}</span>
                <span class="detail-label">Country</span>
                <span class="detail-value">${esc(data.country || '-')}</span>
                <span class="detail-label">City</span>
                <span class="detail-value">${esc(data.city || '-')}</span>
            </div>`;
    } catch (err) {
        container.innerHTML = '<h4>Full WHOIS</h4><div style="color: var(--red); font-size: 0.82rem;">Failed to load</div>';
    }
}

function closeModal() {
    document.getElementById('modal-overlay').classList.remove('visible');
}

// --- Process Detail Modal ---

function showProcessDetail(btn) {
    const app = JSON.parse(btn.getAttribute('data-app'));
    const modal = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');

    const signClass = app.signed ? 'signed' : 'unsigned';
    const signLabel = app.signed ? 'Valid' : 'Not signed';

    const flagsHtml = (app.threat_flags && app.threat_flags.length > 0)
        ? app.threat_flags.map(f => `<div class="modal-flag">
            <span class="modal-flag-weight ${f.severity}">+${f.weight}</span>
            <span>${esc(f.description)}</span>
        </div>`).join('')
        : '<div class="modal-all-clear"><span class="conn-flag flag-green"></span> No threat flags</div>';

    content.innerHTML = `
        <h3>Process Detail: ${esc(app.app)}</h3>

        <div class="modal-section">
            <h4>Process</h4>
            <div class="detail-grid">
                <span class="detail-label">PID</span>
                <span class="detail-value">${app.pid}</span>
                <span class="detail-label">Binary Path</span>
                <span class="detail-value" style="word-break:break-all">${esc(app.path || 'Unknown')}</span>
                <span class="detail-label">Started</span>
                <span class="detail-value">${esc(app.lstart || 'Unknown')}</span>
                <span class="detail-label">Uptime</span>
                <span class="detail-value">${esc(app.etime || 'Unknown')}</span>
                <span class="detail-label">CPU</span>
                <span class="detail-value">${app.cpu.toFixed(1)}%</span>
                <span class="detail-label">Memory</span>
                <span class="detail-value">${app.mem.toFixed(1)}%</span>
            </div>
        </div>

        <div class="modal-section">
            <h4>Code Signing</h4>
            <div class="detail-grid">
                <span class="detail-label">Status</span>
                <span class="detail-value"><span class="sign-badge ${signClass}">${signLabel}</span></span>
                <span class="detail-label">Authority</span>
                <span class="detail-value">${esc(app.sign_authority || '-')}</span>
                <span class="detail-label">Team ID</span>
                <span class="detail-value">${esc(app.team_id || '-')}</span>
                <span class="detail-label">Identifier</span>
                <span class="detail-value">${esc(app.identifier || '-')}</span>
            </div>
        </div>

        <div class="modal-section">
            <h4>Network</h4>
            <div class="detail-grid">
                <span class="detail-label">Connections</span>
                <span class="detail-value">${app.connection_count}</span>
                <span class="detail-label">Traffic In</span>
                <span class="detail-value">${app.bytes_in_fmt}</span>
                <span class="detail-label">Traffic Out</span>
                <span class="detail-value">${app.bytes_out_fmt}</span>
            </div>
        </div>

        <div class="modal-section">
            <h4>Threat Assessment</h4>
            <div class="detail-grid">
                <span class="detail-label">Score</span>
                <span class="detail-value"><span class="threat-badge ${app.threat_color}">${app.threat_score}</span></span>
                <span class="detail-label">Level</span>
                <span class="detail-value">${esc(app.threat_level)}</span>
            </div>
            ${flagsHtml}
        </div>

        <div class="modal-section modal-actions">
            <button class="kill-btn" onclick="confirmKill(${app.pid}, '${escAttr(app.app)}')">
                <svg viewBox="0 0 16 16" fill="none" width="14" height="14"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                Terminate Process
            </button>
        </div>
    `;

    modal.classList.add('visible');
}

function confirmKill(pid, appName) {
    const confirmed = confirm(
        `Are you sure you want to terminate "${appName}" (PID ${pid})?\n\n` +
        `This sends SIGTERM which allows the process to clean up and exit gracefully.`
    );
    if (confirmed) {
        killProcess(pid);
    }
}

async function killProcess(pid) {
    try {
        const resp = await fetch(`/api/kill/${pid}`, { method: 'POST' });
        const result = await resp.json();
        if (resp.ok) {
            closeModal();
            setTimeout(refresh, 1000);
        } else {
            alert(`Failed to terminate process: ${result.error}`);
        }
    } catch (err) {
        alert(`Error: ${err.message}`);
    }
}

// --- App Expand/Collapse ---

function toggleApp(appKey) {
    if (expandedApps.has(appKey)) {
        expandedApps.delete(appKey);
    } else {
        expandedApps.add(appKey);
    }
    if (currentData) renderApps(currentData.apps);
}

function expandAll() {
    if (!currentData) return;
    currentData.apps.forEach(a => expandedApps.add(`${a.app}:${a.pid}`));
    renderApps(currentData.apps);
}

function collapseAll() {
    expandedApps.clear();
    if (currentData) renderApps(currentData.apps);
}

// --- Alerts ---

function toggleAlerts() {
    const body = document.getElementById('alerts-body');
    const icon = document.getElementById('alerts-toggle');
    body.classList.toggle('collapsed');
    icon.classList.toggle('collapsed');
}

// --- Auto-Refresh ---

function startAutoRefresh() {
    if (refreshTimer) clearInterval(refreshTimer);
    if (refreshInterval > 0 && !paused) {
        refreshTimer = setInterval(refresh, refreshInterval);
    }
    updateRefreshIndicator();
}

function togglePause() {
    paused = !paused;
    document.getElementById('pause-label').textContent = paused ? 'Resume' : 'Pause';
    const icon = document.getElementById('pause-icon');
    if (paused) {
        icon.innerHTML = '<path d="M6 4l10 6-10 6V4z" fill="currentColor"/>';
    } else {
        icon.innerHTML = '<rect x="5" y="4" width="3.5" height="12" rx="1" fill="currentColor"/><rect x="11.5" y="4" width="3.5" height="12" rx="1" fill="currentColor"/>';
    }
    updateRefreshIndicator();
    startAutoRefresh();
}

function updateRefreshIndicator() {
    const indicator = document.getElementById('refresh-indicator');
    if (paused || refreshInterval === 0) {
        indicator.classList.add('paused');
    } else {
        indicator.classList.remove('paused');
    }
}

document.getElementById('refresh-interval').addEventListener('change', (e) => {
    refreshInterval = parseInt(e.target.value);
    startAutoRefresh();
});

// --- Filters ---

function setupFilterListeners() {
    ['search', 'state-filter', 'threat-filter', 'show-localhost'].forEach(id => {
        document.getElementById(id).addEventListener('change', () => {
            if (currentData) renderApps(currentData.apps);
        });
    });
    document.getElementById('search').addEventListener('input', () => {
        if (currentData) renderApps(currentData.apps);
    });
}

// --- Keyboard Shortcuts ---

function setupKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') {
            if (e.key === 'Escape') {
                e.target.blur();
                e.target.value = '';
                if (currentData) renderApps(currentData.apps);
            }
            return;
        }

        switch (e.key) {
            case 'r': refresh(); break;
            case 'p': togglePause(); break;
            case '/': e.preventDefault(); document.getElementById('search').focus(); break;
            case 'e': expandAll(); break;
            case 'c': collapseAll(); break;
            case 'Escape': closeModal(); break;
            case '?': window.location.href = '/help'; break;
        }
    });
}

// --- Helpers ---

function connectionFlagClass(flags) {
    if (!flags || flags.length === 0) return 'flag-green';
    const hasRed = flags.some(f => f.severity === 'red');
    if (hasRed) return 'flag-red';
    const hasYellow = flags.some(f => f.severity === 'yellow' || f.severity === 'orange');
    if (hasYellow) return 'flag-yellow';
    return 'flag-green';
}

function connectionFlagTooltip(flags) {
    if (!flags || flags.length === 0) return 'Clean: No issues detected with this connection';
    return flags.map(f => f.description).join('. ');
}

function svgCheck() {
    return '<svg viewBox="0 0 12 12" fill="none" width="12" height="12"><path d="M2.5 6l2.5 2.5 4.5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function svgX() {
    return '<svg viewBox="0 0 12 12" fill="none" width="12" height="12"><path d="M3 3l6 6M9 3l-6 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
}

function esc(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

function escAttr(str) {
    if (str === null || str === undefined) return '';
    return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
