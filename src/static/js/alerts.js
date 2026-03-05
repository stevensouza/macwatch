/* MacWatch Alerts Page — grouped by category */

let alertData = null;
let alertInfoData = null;

const CATEGORIES = ['network', 'cpu', 'memory', 'disk'];
const SEVERITY_ORDER = { red: 0, yellow: 1, blue: 2, info: 3 };

// --- Initialization ---

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const [connectionsResp, alertInfoResp] = await Promise.all([
            fetch('/api/connections'),
            fetch('/api/alert-info'),
        ]);

        const connections = await connectionsResp.json();
        alertInfoData = await alertInfoResp.json();

        alertData = connections.alerts;

        document.getElementById('loading-state').style.display = 'none';
        document.getElementById('alert-analysis').style.display = 'block';

        renderAlertAnalysis(connections.alerts, connections.summary);
        updateAlertTabBadge(connections.summary);
    } catch (err) {
        document.getElementById('loading-state').innerHTML =
            '<div class="ai-message ai-message-error">Failed to load data. Is MacWatch running?</div>';
    }
});


// --- Alert Rendering ---

function renderAlertAnalysis(alerts, summary) {
    const summaryEl = document.getElementById('alert-summary-text');
    if (alerts.length === 0) {
        summaryEl.textContent = 'No alerts detected — system looks healthy';
        document.getElementById('alerts-none').style.display = 'flex';
        return;
    }

    // Build summary text from category counts
    const parts = [];
    if (summary.network_count) parts.push(`${summary.network_count} network`);
    if (summary.cpu_count) parts.push(`${summary.cpu_count} CPU`);
    if (summary.memory_count) parts.push(`${summary.memory_count} memory`);
    if (summary.disk_count) parts.push(`${summary.disk_count} disk`);
    summaryEl.textContent = parts.join(', ') + ` alert${alerts.length !== 1 ? 's' : ''}`;

    // Group alerts by category
    const groups = {};
    CATEGORIES.forEach(cat => groups[cat] = []);

    alerts.forEach(alert => {
        const cat = alert.category || 'network';
        if (groups[cat]) {
            groups[cat].push(alert);
        } else {
            groups.network.push(alert);
        }
    });

    // Sort alerts within each group by severity (red first)
    for (const cat of CATEGORIES) {
        groups[cat].sort((a, b) =>
            (SEVERITY_ORDER[a.severity] || 4) - (SEVERITY_ORDER[b.severity] || 4)
        );
    }

    for (const cat of CATEGORIES) {
        const container = document.getElementById(`alerts-${cat}`);
        if (!container) continue;

        const groupAlerts = groups[cat];
        if (groupAlerts.length === 0) {
            container.style.display = 'none';
            continue;
        }

        container.style.display = 'block';
        document.getElementById(`alert-count-${cat}`).textContent = groupAlerts.length;

        // Set the severity dot to the worst severity in this group
        const worstSeverity = groupAlerts[0].severity; // already sorted
        const dot = document.getElementById(`alert-dot-${cat}`);
        if (dot) dot.className = `alert-severity-dot sev-${worstSeverity}`;

        const body = document.getElementById(`alert-body-${cat}`);
        body.innerHTML = groupAlerts.map(alert => renderAlertCard(alert)).join('');
    }
}

function renderAlertCard(alert) {
    const info = alertInfoData[alert.type] || {};
    const hasInfo = info.what || info.why || info.typical || info.action;

    return `<div class="analysis-alert-card">
        <div class="analysis-alert-header${hasInfo ? '' : ' no-expand'}" ${hasInfo ? `onclick="toggleAlertDetail(this)"` : ''}>
            <span class="alert-severity-dot sev-${alert.severity}"></span>
            <span class="analysis-alert-app">${esc(alert.app)}</span>
            ${hasInfo ? `<span class="toggle-icon collapsed">
                <svg viewBox="0 0 20 20" fill="none" width="14" height="14">
                    <path d="M5 8l5 5 5-5" stroke="currentColor" stroke-width="1.5"
                          stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </span>` : ''}
            <span class="analysis-alert-desc">${esc(alert.description)}</span>
        </div>
        ${hasInfo ? `<div class="analysis-alert-detail collapsed">
            ${info.what ? `
            <div class="alert-info-section">
                <h5>What This Means</h5>
                <p>${esc(info.what)}</p>
            </div>` : ''}
            ${info.why ? `
            <div class="alert-info-section">
                <h5>Why It Matters</h5>
                <p>${esc(info.why)}</p>
            </div>` : ''}
            ${info.typical ? `
            <div class="alert-info-section">
                <h5>Is It Usually Benign?</h5>
                <p>${esc(info.typical)}</p>
            </div>` : ''}
            ${info.action ? `
            <div class="alert-info-section">
                <h5>What To Do</h5>
                <p>${esc(info.action)}</p>
            </div>` : ''}
        </div>` : ''}
    </div>`;
}

function toggleAlertDetail(headerEl) {
    const detail = headerEl.nextElementSibling;
    const icon = headerEl.querySelector('.toggle-icon');
    if (detail) detail.classList.toggle('collapsed');
    if (icon) icon.classList.toggle('collapsed');
}

function toggleAlertGroup(category) {
    const body = document.getElementById(`alert-body-${category}`);
    const icon = document.getElementById(`toggle-${category}`);
    if (body) body.classList.toggle('collapsed');
    if (icon) icon.classList.toggle('collapsed');
}


// --- Tab Badge ---

function updateAlertTabBadge(summary) {
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


// --- Keyboard Shortcuts ---

document.addEventListener('keydown', (e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
    switch (e.key) {
        case 'Escape': window.location.href = '/'; break;
        case '?': window.location.href = '/help'; break;
    }
});


// --- Helpers ---

function esc(str) {
    if (str === null || str === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}
