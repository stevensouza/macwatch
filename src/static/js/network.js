/* MacWatch — Network Tab */

let expandedApps = new Set();
let initialRenderDone = false;

// --- Initialization ---

document.addEventListener('DOMContentLoaded', () => {
    if (window.__INITIAL_DATA__) {
        currentData = window.__INITIAL_DATA__;
        renderNetwork(currentData);
        updateRefreshTime();
    } else {
        refresh();
    }
    startAutoRefresh();
    setupRefreshIntervalListener();
    setupBaseKeyboardShortcuts((e) => {
        switch (e.key) {
            case '/': e.preventDefault(); document.getElementById('search').focus(); break;
            case 'e': expandAll(); break;
            case 'c': collapseAll(); break;
        }
    });
    setupFilterListeners();
});

// --- Data Fetching ---

async function refresh() {
    try {
        const resp = await fetch('/api/connections');
        currentData = await resp.json();
        renderNetwork(currentData);
        updateRefreshTime();
    } catch (err) {
        console.error('Refresh failed:', err);
    }
}

// --- Rendering ---

function renderNetwork(data) {
    renderNetworkSummary(data.summary);
    updateAlertTabBadge(data.alerts, data.summary);
    renderApps(data.apps);
}

function renderNetworkSummary(summary) {
    document.getElementById('app-count').textContent = summary.app_count;
    document.getElementById('conn-count').textContent = summary.connection_count;
    document.getElementById('bytes-in').textContent = summary.bytes_in_fmt;
    document.getElementById('bytes-out').textContent = summary.bytes_out_fmt;
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
                app.display_name || '',
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

        const animClass = initialRenderDone ? ' no-animate' : '';
        const animStyle = initialRenderDone ? '' : `animation-delay: ${Math.min(i * 0.03, 0.3)}s`;
        const displayName = app.display_name || app.app;
        const nameHint = displayName !== app.app
            ? `<span class="app-command-hint">${esc(app.app)}</span>`
            : (app.command && app.command !== app.path
                ? `<span class="app-command-hint">${esc(truncate(app.command, 80))}</span>` : '');

        return `<div class="app-card threat-${app.threat_color}${animClass}" style="${animStyle}">
            <div class="app-header" onclick="toggleApp('${escAttr(appKey)}')">
                <span class="app-toggle ${isExpanded ? 'expanded' : ''}">
                    <svg viewBox="0 0 20 20" fill="none"><path d="M7 4l6 6-6 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
                </span>
                <span class="app-name">${esc(displayName)}${nameHint}</span>
                <span class="threat-badge ${app.threat_color}" data-tooltip="${escAttr(threatTooltip)}">
                    ${app.threat_score}
                </span>
                <button class="app-info-btn" onclick="event.stopPropagation(); showProcessDetail(this)" data-app='${escAttr(JSON.stringify(app))}' data-tooltip="View process details">
                    <svg viewBox="0 0 16 16" fill="none" width="14" height="14"><circle cx="8" cy="8" r="6.5" stroke="currentColor" stroke-width="1.2"/><path d="M8 7v4M8 5.5v.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>
                </button>
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
            </div>
            <div class="conn-table-wrapper ${isExpanded ? 'expanded' : ''}">
                ${renderConnTable(conns, app)}
            </div>
        </div>`;
    }).join('');

    if (!initialRenderDone) initialRenderDone = true;
}

function renderConnTable(conns, app) {
    if (conns.length === 0) {
        return '<div class="conn-empty">No matching connections</div>';
    }

    const rows = conns.map(c => {
        const isListen = (c.state || '').toUpperCase() === 'LISTEN';
        const hostClass = isListen ? 'conn-listen-local' : (c.remote_host === '(no rDNS)' ? 'conn-no-rdns' : 'conn-host');
        const displayHost = isListen ? (c.local_addr || '*') : (c.remote_host || '-');
        const displayAddr = isListen ? (c.local_addr || '*') : (c.remote_addr || '-');
        const displayPort = isListen ? (c.local_port || '-') : (c.remote_port || '-');
        const portLabel = isListen
            ? (c.local_port ? `<span class="conn-port-label">${esc(portLabelForLocal(c.local_port))}</span>` : '')
            : (c.port_label ? `<span class="conn-port-label">${esc(c.port_label)}</span>` : '');
        const stateClass = (c.state || '').toLowerCase().replace('_', '-');
        const flagClass = connectionFlagClass(c.flags);
        const flagTooltip = connectionFlagTooltip(c.flags);

        return `<tr onclick="showConnectionDetail(${JSON.stringify(esc(JSON.stringify(c))).slice(1, -1)}, '${escAttr(app.app)}', ${app.pid})">
            <td class="${hostClass}">${esc(displayHost)}</td>
            <td>${esc(displayAddr)}</td>
            <td>${displayPort}${portLabel}</td>
            <td>${esc(c.protocol)}</td>
            <td><span class="conn-state ${stateClass}">${esc(c.state || '-')}</span></td>
            <td>${isListen ? '-' : esc(c.whois_org || '-')}</td>
            <td>${isListen ? '-' : esc(c.whois_country || '-')}</td>
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

// --- Filters ---

function setupFilterListeners() {
    ['search', 'state-filter', 'threat-filter', 'show-localhost'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('change', () => {
                if (currentData) renderApps(currentData.apps);
            });
        }
    });
    const searchEl = document.getElementById('search');
    if (searchEl) {
        searchEl.addEventListener('input', () => {
            if (currentData) renderApps(currentData.apps);
        });
    }
}

function onSearchClear() {
    if (currentData) renderApps(currentData.apps);
}
