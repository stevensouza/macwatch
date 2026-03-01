/* MacWatch Alerts Page */

let alertData = null;
let alertInfoData = null;

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
        summaryEl.textContent = 'No alerts detected — all connections look normal';
        document.getElementById('alerts-none').style.display = 'flex';
        return;
    }

    const parts = [];
    if (summary.red_count) parts.push(`${summary.red_count} critical`);
    if (summary.yellow_count) parts.push(`${summary.yellow_count} warning`);
    if (summary.blue_count) parts.push(`${summary.blue_count} info`);
    const infos = alerts.filter(a => a.severity === 'info').length;
    if (infos) parts.push(`${infos} new`);
    summaryEl.textContent = parts.join(', ') + ` across ${summary.app_count} apps`;

    // Group alerts by severity
    const groups = { red: [], yellow: [], blue: [], info: [] };
    alerts.forEach(alert => {
        const bucket = groups[alert.severity] || groups.info;
        bucket.push(alert);
    });

    for (const [severity, groupAlerts] of Object.entries(groups)) {
        const container = document.getElementById(`alerts-${severity}`);
        if (!container) continue;

        if (groupAlerts.length === 0) {
            container.style.display = 'none';
            continue;
        }

        container.style.display = 'block';
        document.getElementById(`alert-count-${severity}`).textContent = groupAlerts.length;

        const body = document.getElementById(`alert-body-${severity}`);
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
            <span class="analysis-alert-desc">${esc(alert.description)}</span>
            ${hasInfo ? `<span class="toggle-icon collapsed">
                <svg viewBox="0 0 20 20" fill="none" width="14" height="14">
                    <path d="M5 8l5 5 5-5" stroke="currentColor" stroke-width="1.5"
                          stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </span>` : ''}
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

function toggleAlertGroup(severity) {
    const body = document.getElementById(`alert-body-${severity}`);
    const icon = document.getElementById(`toggle-${severity}`);
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
