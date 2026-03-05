/* MacWatch — Shared utilities, modals, and auto-refresh */

let refreshInterval = 120000;
let refreshTimer = null;
let paused = false;
let currentData = null;

// --- Tooltip definitions ---
const TOOLTIPS = {
    'Remote Host': 'The resolved domain name of the remote server (via reverse DNS lookup). Shows "(no rDNS)" if the IP has no hostname record.',
    'IP': 'The IP address of the remote server this app is communicating with.',
    'Port': 'The network port on the remote server. Common ports: 443 = HTTPS (encrypted web), 80 = HTTP (unencrypted), 22 = SSH, 53 = DNS.',
    'Proto': 'The transport protocol. TCP = reliable ordered delivery (web, email). UDP = fast but unordered (video, DNS, gaming).',
    'State': 'The TCP connection state. ESTABLISHED = actively connected. LISTEN = waiting for incoming connections. CLOSE_WAIT = remote side disconnected.',
    'Org': 'The organization that owns this IP address, determined via WHOIS lookup. Helps identify who your apps are talking to.',
    'CC': 'Two-letter country code where the IP address is registered.',
    'Status': 'Threat assessment for this connection based on port, DNS, signing, and traffic pattern analysis.',
    'conn': 'Current open network sockets for this application (snapshot at each refresh).',
    'traffic_in': '↓ Total bytes received (downloaded) by this app — cumulative since the process started, not per-refresh.',
    'traffic_out': '↑ Total bytes sent (uploaded) by this app — cumulative since the process started, not per-refresh.',
    'cpu': 'CPU usage — instantaneous snapshot at the time of each refresh, not an average.',
    'mem': 'Memory (RAM) usage — instantaneous snapshot at the time of each refresh.',
    'threat_green': 'Threat Score: 0 (Clean). All connections look normal. No suspicious indicators detected.',
    'threat_yellow': 'Threat Score: Low. Minor concerns detected, usually benign. Worth a glance.',
    'threat_orange': 'Threat Score: Medium. Multiple concerns detected. Recommended to investigate.',
    'threat_red': 'Threat Score: High. Significant risk indicators found. You should investigate this application.',
    'signed': 'This app has a valid Apple code signature, confirming it was distributed by an identified developer.',
    'unsigned': 'WARNING: This app has no valid code signature. It cannot be verified as legitimate software.',
};

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
    const label = document.getElementById('pause-label');
    if (label) label.textContent = paused ? 'Resume' : 'Pause';
    const icon = document.getElementById('pause-icon');
    if (icon) {
        if (paused) {
            icon.innerHTML = '<path d="M6 4l10 6-10 6V4z" fill="currentColor"/>';
        } else {
            icon.innerHTML = '<rect x="5" y="4" width="3.5" height="12" rx="1" fill="currentColor"/><rect x="11.5" y="4" width="3.5" height="12" rx="1" fill="currentColor"/>';
        }
    }
    updateRefreshIndicator();
    startAutoRefresh();
}

function updateRefreshIndicator() {
    const indicator = document.getElementById('refresh-indicator');
    if (!indicator) return;
    if (paused || refreshInterval === 0) {
        indicator.classList.add('paused');
    } else {
        indicator.classList.remove('paused');
    }
}

function updateRefreshTime() {
    const t = new Date().toLocaleTimeString();
    const el1 = document.getElementById('last-refresh');
    const el2 = document.getElementById('last-refresh-time');
    if (el1) el1.textContent = 'Updated ' + t;
    if (el2) el2.textContent = t;
}

function setupRefreshIntervalListener() {
    const el = document.getElementById('refresh-interval');
    if (el) {
        el.addEventListener('change', (e) => {
            refreshInterval = parseInt(e.target.value);
            startAutoRefresh();
        });
    }
}

// --- Alert Badge ---

function updateAlertTabBadge(alerts, summary) {
    const badge = document.getElementById('tab-alert-badge');
    if (!badge) return;
    const count = (summary.red_count || 0) + (summary.yellow_count || 0) + (summary.blue_count || 0);
    if (count === 0) {
        badge.style.display = 'none';
        return;
    }
    badge.textContent = count;
    badge.style.display = 'inline-block';
    if (summary.red_count > 0) {
        badge.className = 'tab-alert-badge badge-red';
    } else if (summary.yellow_count > 0) {
        badge.className = 'tab-alert-badge badge-yellow';
    } else {
        badge.className = 'tab-alert-badge badge-blue';
    }
}

// --- Modal ---

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
        <h3>Process Detail: ${esc(app.display_name || app.app || app.name)}</h3>

        <div class="modal-section">
            <h4>Process</h4>
            <div class="detail-grid">
                <span class="detail-label">PID</span>
                <span class="detail-value">${app.pid}</span>
                <span class="detail-label">Binary Path</span>
                <span class="detail-value" style="word-break:break-all">${esc(app.path || 'Unknown')}</span>
                <span class="detail-label">Command</span>
                <span class="detail-value" style="word-break:break-all;font-size:0.76rem">${esc(app.command || app.path || 'Unknown')}</span>
                ${app.lstart ? `<span class="detail-label">Started</span>
                <span class="detail-value">${esc(app.lstart)}</span>` : ''}
                ${app.etime ? `<span class="detail-label">Uptime</span>
                <span class="detail-value">${esc(app.etime)}</span>` : ''}
                <span class="detail-label">CPU</span>
                <span class="detail-value">${app.cpu.toFixed(1)}%</span>
                <span class="detail-label">Memory</span>
                <span class="detail-value">${app.mem.toFixed(1)}%</span>
            </div>
        </div>

        <div class="modal-section" id="process-deep-detail">
            <h4>System Detail</h4>
            <div style="color: var(--text-muted); font-size: 0.82rem;">Loading...</div>
        </div>

        ${app.signed !== undefined ? `<div class="modal-section">
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
        </div>` : ''}

        ${app.connection_count !== undefined ? `<div class="modal-section">
            <h4>Network</h4>
            <div class="detail-grid">
                <span class="detail-label">Connections</span>
                <span class="detail-value">${app.connection_count}</span>
                <span class="detail-label">Traffic In</span>
                <span class="detail-value">${app.bytes_in_fmt}</span>
                <span class="detail-label">Traffic Out</span>
                <span class="detail-value">${app.bytes_out_fmt}</span>
            </div>
        </div>` : ''}

        ${app.threat_score !== undefined ? `<div class="modal-section">
            <h4>Threat Assessment</h4>
            <div class="detail-grid">
                <span class="detail-label">Score</span>
                <span class="detail-value"><span class="threat-badge ${app.threat_color}">${app.threat_score}</span></span>
                <span class="detail-label">Level</span>
                <span class="detail-value">${esc(app.threat_level)}</span>
            </div>
            ${flagsHtml}
        </div>` : ''}

        <div class="modal-section modal-actions">
            <button class="kill-btn" onclick="confirmKill(${app.pid}, '${escAttr(app.display_name || app.app || app.name)}')">
                <svg viewBox="0 0 16 16" fill="none" width="14" height="14"><path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
                Terminate Process
            </button>
        </div>
    `;

    modal.classList.add('visible');
    loadProcessDeepDetail(app.pid);
}

async function loadProcessDeepDetail(pid) {
    const container = document.getElementById('process-deep-detail');
    if (!container) return;

    try {
        const resp = await fetch(`/api/process/${pid}`);
        if (!resp.ok) {
            container.innerHTML = '<h4>System Detail</h4><div style="color: var(--text-muted); font-size: 0.82rem;">Unable to load details</div>';
            return;
        }
        const d = await resp.json();

        const parentChainHtml = d.parent_chain && d.parent_chain.length > 0
            ? d.parent_chain.map(p =>
                `<span style="color:var(--text-muted);font-size:0.76rem">${esc(p.name)} (${p.pid})</span>`
            ).join(' \u2192 ')
            : '-';

        const openFilesHtml = d.open_files && d.open_files.length > 0
            ? `<a href="#" class="modal-link" onclick="toggleOpenFiles(event)">
                Show ${d.open_files_count} open file${d.open_files_count !== 1 ? 's' : ''}
                <svg viewBox="0 0 12 12" fill="none" width="12" height="12"><path d="M4 8l4-4M4 4h4v4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
              </a>
              <div id="open-files-list" style="display:none;margin-top:0.4rem;font-size:0.72rem;color:var(--text-muted);max-height:200px;overflow-y:auto;word-break:break-all">
                ${d.open_files.map(f => `<div style="padding:1px 0">${esc(f)}</div>`).join('')}
              </div>`
            : '';

        container.innerHTML = `
            <h4>System Detail</h4>
            <div class="detail-grid">
                <span class="detail-label">User</span>
                <span class="detail-value">${esc(d.user || '-')}</span>
                <span class="detail-label">Working Dir</span>
                <span class="detail-value" style="word-break:break-all;font-size:0.76rem">${esc(d.cwd || '-')}</span>
                <span class="detail-label">Parent</span>
                <span class="detail-value" style="word-break:break-all;font-size:0.76rem">${esc(d.parent_command || '-')}</span>
                <span class="detail-label">Parent Chain</span>
                <span class="detail-value">${parentChainHtml}</span>
                <span class="detail-label">State</span>
                <span class="detail-value">${esc(d.state || '-')}</span>
                <span class="detail-label">Nice / Priority</span>
                <span class="detail-value">${d.nice != null ? d.nice : '-'} / ${d.priority != null ? d.priority : '-'}</span>
                <span class="detail-label">RSS (Physical)</span>
                <span class="detail-value">${esc(d.rss_fmt || '-')}</span>
                <span class="detail-label">VSZ (Virtual)</span>
                <span class="detail-value">${esc(d.vsz_fmt || '-')}</span>
                <span class="detail-label">Threads</span>
                <span class="detail-value">${d.thread_count || '-'}</span>
                <span class="detail-label">Open Files</span>
                <span class="detail-value">${d.open_files_count || 0}</span>
                <span class="detail-label">Loaded Libs</span>
                <span class="detail-value">${d.loaded_libs_count || 0}</span>
                <span class="detail-label">Process Group</span>
                <span class="detail-value">${d.pgid != null ? d.pgid : '-'}</span>
            </div>
            ${openFilesHtml}
        `;
    } catch (err) {
        container.innerHTML = '<h4>System Detail</h4><div style="color: var(--red); font-size: 0.82rem;">Failed to load details</div>';
    }
}

function toggleOpenFiles(event) {
    event.preventDefault();
    const list = document.getElementById('open-files-list');
    if (list) {
        list.style.display = list.style.display === 'none' ? 'block' : 'none';
    }
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

function truncate(str, len) {
    if (!str || str.length <= len) return str;
    return str.substring(0, len) + '\u2026';
}

function portLabelForLocal(port) {
    const labels = {80:'HTTP', 443:'HTTPS', 8080:'HTTP-Alt', 8443:'HTTPS-Alt',
                    22:'SSH', 53:'DNS', 5353:'mDNS', 3000:'Dev', 5000:'Dev',
                    8077:'MacWatch'};
    return labels[port] || '';
}

// --- Shared keyboard shortcuts ---

function setupBaseKeyboardShortcuts(extraHandler) {
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') {
            if (e.key === 'Escape') {
                e.target.blur();
                e.target.value = '';
                if (typeof onSearchClear === 'function') onSearchClear();
            }
            return;
        }

        switch (e.key) {
            case 'r': refresh(); break;
            case 'p': togglePause(); break;
            case 'Escape': closeModal(); break;
            case '?': window.location.href = '/help'; break;
            default:
                if (extraHandler) extraHandler(e);
        }
    });
}

// --- Render process table rows (shared between dashboard overview and processes page) ---

function renderProcessTableRows(processes, options = {}) {
    const { showRank = true, maxCommand = 60, clickable = false } = options;

    return processes.map((p, i) => {
        const displayName = p.display_name || p.name;
        const nameHint = displayName !== p.name
            ? ` <span class="text-muted">(${esc(p.name)})</span>` : '';
        const networkBadge = p.has_network
            ? '<span class="top-proc-badge network" data-tooltip="Has active network connections">NET</span>'
            : '';

        const cpuBarWidth = Math.min(p.cpu, 100);
        const cpuBarClass = p.cpu > 50 ? 'cpu-high' : (p.cpu > 20 ? 'cpu-medium' : 'cpu-low');

        const clickAttr = clickable
            ? ` onclick="showProcessDetail(this)" data-app='${escAttr(JSON.stringify(p))}' style="cursor:pointer"`
            : '';

        return `<tr${clickAttr}>
            ${showRank ? `<td class="top-proc-rank">${i + 1}</td>` : ''}
            <td class="top-proc-name">${esc(displayName)}${nameHint}${networkBadge}</td>
            <td class="top-proc-pid">${p.pid}</td>
            <td class="top-proc-cpu">
                <div class="cpu-bar-wrapper">
                    <div class="cpu-bar ${cpuBarClass}" style="width: ${cpuBarWidth}%"></div>
                    <span class="cpu-value">${p.cpu.toFixed(1)}%</span>
                </div>
            </td>
            <td class="top-proc-mem">${p.mem.toFixed(1)}%</td>
            <td class="top-proc-command">${esc(truncate(p.command, maxCommand))}</td>
        </tr>`;
    }).join('');
}
