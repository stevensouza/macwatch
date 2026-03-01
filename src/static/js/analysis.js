/* MacWatch AI Analysis Page */

let aiConfig = null;

// --- Initialization ---

document.addEventListener('DOMContentLoaded', async () => {
    try {
        const resp = await fetch('/api/ai-config');
        aiConfig = await resp.json();
        renderAIControls();
    } catch (err) {
        document.getElementById('ai-analysis').innerHTML =
            '<div class="ai-message ai-message-error">Failed to load AI configuration. Is MacWatch running?</div>';
    }
});


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
