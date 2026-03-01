/* MacWatch Analysis Page */

let alertData = null;
let alertInfoData = null;
let aiConfig = null;

// --- Initialization ---

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const [connectionsResp, alertInfoResp, aiConfigResp] = await Promise.all([
            fetch('/api/connections'),
            fetch('/api/alert-info'),
            fetch('/api/ai-config'),
        ]);

        const connections = await connectionsResp.json();
        alertInfoData = await alertInfoResp.json();
        aiConfig = await aiConfigResp.json();

        alertData = connections.alerts;

        document.getElementById('loading-state').style.display = 'none';
        document.getElementById('alert-analysis').style.display = 'block';
        document.getElementById('ai-analysis').style.display = 'block';

        renderAlertAnalysis(connections.alerts, connections.summary);
        updateAnalysisTabBadge(connections.summary);
        renderAIControls();
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


// --- AI Controls ---

function renderAIControls() {
    const select = document.getElementById('ai-provider');

    select.innerHTML = aiConfig.providers.map(p =>
        `<option value="${p.id}" ${p.id === aiConfig.default ? 'selected' : ''}>${esc(p.name)}</option>`
    ).join('');

    select.addEventListener('change', updateAIConfigStatus);
    updateAIConfigStatus();
}

function updateAIConfigStatus() {
    const select = document.getElementById('ai-provider');
    const selectedId = select.value;
    const provider = aiConfig.providers.find(p => p.id === selectedId);
    const notConfigured = document.getElementById('ai-not-configured');
    const btn = document.getElementById('ai-analyze-btn');

    if (provider && !provider.configured) {
        if (selectedId === 'ollama') {
            notConfigured.innerHTML = `
                <strong>Ollama is not reachable.</strong><br>
                Make sure Ollama is running locally:<br>
                <code style="display:block; margin-top:0.5rem; font-size:0.78rem;">
                ollama serve<br>
                ollama pull llama3.1
                </code>
            `;
        } else {
            const envVars = {
                claude: 'ANTHROPIC_API_KEY',
                openai: 'OPENAI_API_KEY',
                gemini: 'GOOGLE_AI_API_KEY',
            };
            const envVar = envVars[selectedId] || 'the appropriate API key';
            notConfigured.innerHTML = `
                <strong>${esc(provider.name)} is not configured.</strong><br>
                Set the <code>${esc(envVar)}</code> environment variable and restart MacWatch.<br>
                <code style="display:block; margin-top:0.5rem; font-size:0.78rem;">
                export ${esc(envVar)}="your-key-here"<br>
                python3 -m src
                </code>
            `;
        }
        notConfigured.style.display = 'block';
        btn.disabled = true;
        btn.classList.add('disabled');
    } else {
        notConfigured.style.display = 'none';
        btn.disabled = false;
        btn.classList.remove('disabled');
    }

    // Update privacy note based on provider
    const privacyNote = document.getElementById('ai-privacy-note');
    if (privacyNote) {
        if (selectedId === 'ollama') {
            privacyNote.textContent = 'Ollama runs locally — your data stays on this machine';
        } else {
            privacyNote.textContent = 'Sends current MacWatch data to the selected AI provider for analysis';
        }
    }
}


// --- AI Analysis ---

async function runAIAnalysis() {
    const provider = document.getElementById('ai-provider').value;
    const btn = document.getElementById('ai-analyze-btn');
    const loading = document.getElementById('ai-loading');
    const errorEl = document.getElementById('ai-error');
    const resultEl = document.getElementById('ai-result');

    btn.disabled = true;
    btn.classList.add('disabled');
    loading.style.display = 'flex';
    errorEl.style.display = 'none';
    resultEl.style.display = 'none';

    try {
        const resp = await fetch('/api/ai-analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ provider }),
        });

        const data = await resp.json();

        if (!resp.ok) {
            throw new Error(data.error || 'Analysis failed');
        }

        renderAIResult(data);
    } catch (err) {
        errorEl.textContent = err.message;
        errorEl.style.display = 'block';
    } finally {
        loading.style.display = 'none';
        btn.disabled = false;
        btn.classList.remove('disabled');
    }
}

function renderAIResult(data) {
    const resultEl = document.getElementById('ai-result');
    const verdictEl = document.getElementById('ai-verdict');
    const bodyEl = document.getElementById('ai-response-body');
    const metaEl = document.getElementById('ai-meta');

    const isConcerns = data.verdict === 'concerns';
    verdictEl.className = `ai-verdict ${isConcerns ? 'verdict-concerns' : 'verdict-clear'}`;
    verdictEl.innerHTML = `
        <span class="verdict-icon">${isConcerns ? '&#9888;' : '&#10003;'}</span>
        <span class="verdict-text">${isConcerns ? 'Concerns Identified' : 'No Concerns'}</span>
    `;

    bodyEl.innerHTML = markdownToHtml(data.raw_response);
    metaEl.textContent = `Analyzed by ${data.provider || 'AI'}`;
    resultEl.style.display = 'block';
}

function markdownToHtml(text) {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>')
        .replace(/^### (.+)$/gm, '<h5>$1</h5>')
        .replace(/^## (.+)$/gm, '<h4>$1</h4>')
        .replace(/^# (.+)$/gm, '<h3>$1</h3>')
        .replace(/^- (.+)$/gm, '<li>$1</li>')
        .replace(/(<li>[\s\S]*?<\/li>)/g, function(match) {
            return '<ul>' + match + '</ul>';
        })
        .replace(/<\/ul>\s*<ul>/g, '')
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>')
        .replace(/^/, '<p>')
        .replace(/$/, '</p>');
}


// --- Tab Badge ---

function updateAnalysisTabBadge(summary) {
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
