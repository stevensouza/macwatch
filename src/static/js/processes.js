/* MacWatch — Processes Tab */

let processSort = { col: 'cpu', asc: false };
let processSearch = '';

// --- Initialization ---

document.addEventListener('DOMContentLoaded', () => {
    refresh();
    startAutoRefresh();
    setupRefreshIntervalListener();
    setupBaseKeyboardShortcuts((e) => {
        if (e.key === '/') {
            e.preventDefault();
            document.getElementById('process-search').focus();
        }
    });
    setupProcessSearch();
});

// --- Data Fetching ---

async function refresh() {
    try {
        const [connResp, sysResp] = await Promise.all([
            fetch('/api/connections?full_processes=1'),
            fetch('/api/system')
        ]);
        const connData = await connResp.json();
        const sysData = await sysResp.json();
        currentData = { ...connData, system: sysData };
        renderProcesses(currentData);
        updateRefreshTime();
    } catch (err) {
        console.error('Refresh failed:', err);
    }
}

// --- Rendering ---

function renderProcesses(data) {
    renderSystemStats(data.system);
    updateAlertTabBadge(data.alerts, data.summary);
    renderProcessTable(data.top_processes);
}

function renderSystemStats(sys) {
    document.getElementById('sys-cpu').textContent = sys.cpu_percent + '%';
    document.getElementById('sys-cpu-bar').style.width = Math.min(sys.cpu_percent, 100) + '%';
    document.getElementById('sys-cpu-bar').className = 'stat-bar-fill ' +
        (sys.cpu_percent > 80 ? 'bar-red' : sys.cpu_percent > 50 ? 'bar-yellow' : 'bar-green');
    document.getElementById('sys-load').textContent =
        `${sys.load_avg_1.toFixed(2)} / ${sys.load_avg_5.toFixed(2)} / ${sys.load_avg_15.toFixed(2)}`;

    document.getElementById('sys-mem').textContent = sys.mem_percent + '%';
    document.getElementById('sys-mem-bar').style.width = Math.min(sys.mem_percent, 100) + '%';
    document.getElementById('sys-mem-bar').className = 'stat-bar-fill ' +
        (sys.mem_percent > 85 ? 'bar-red' : sys.mem_percent > 70 ? 'bar-yellow' : 'bar-green');
    document.getElementById('sys-mem-detail').textContent = `${sys.mem_used_fmt} / ${sys.mem_total_fmt}`;

    document.getElementById('sys-disk').textContent = sys.disk_percent + '%';
    document.getElementById('sys-disk-bar').style.width = Math.min(sys.disk_percent, 100) + '%';
    document.getElementById('sys-disk-bar').className = 'stat-bar-fill ' +
        (sys.disk_percent > 90 ? 'bar-red' : sys.disk_percent > 75 ? 'bar-yellow' : 'bar-green');
    document.getElementById('sys-disk-detail').textContent = `${sys.disk_used_fmt} / ${sys.disk_total_fmt}`;
}

function renderProcessTable(processes) {
    const container = document.getElementById('process-table-body');
    if (!container) return;

    let filtered = processes;
    if (processSearch) {
        const q = processSearch.toLowerCase();
        filtered = processes.filter(p => {
            const searchable = [
                p.display_name || '', p.name || '', p.command || '', String(p.pid)
            ].join(' ').toLowerCase();
            return searchable.includes(q);
        });
    }

    // Sort
    const sorted = [...filtered].sort((a, b) => {
        let va, vb;
        switch (processSort.col) {
            case 'name':
                va = (a.display_name || a.name).toLowerCase();
                vb = (b.display_name || b.name).toLowerCase();
                return processSort.asc ? va.localeCompare(vb) : vb.localeCompare(va);
            case 'pid':
                va = a.pid; vb = b.pid; break;
            case 'cpu':
                va = a.cpu; vb = b.cpu; break;
            case 'mem':
                va = a.mem; vb = b.mem; break;
            default:
                va = a.cpu; vb = b.cpu;
        }
        return processSort.asc ? va - vb : vb - va;
    });

    const rows = renderProcessTableRows(sorted, { showRank: false, maxCommand: 80, clickable: true });
    container.innerHTML = rows || '<tr><td colspan="5" class="top-procs-empty">No matching processes</td></tr>';

    // Update count
    const countEl = document.getElementById('process-count');
    if (countEl) countEl.textContent = `${filtered.length} process${filtered.length !== 1 ? 'es' : ''}`;

    // Update sort indicators
    document.querySelectorAll('.sort-header').forEach(th => {
        th.classList.toggle('sort-active', th.dataset.sort === processSort.col);
        th.classList.toggle('sort-asc', th.dataset.sort === processSort.col && processSort.asc);
    });
}

// --- Sort ---

function sortBy(col) {
    if (processSort.col === col) {
        processSort.asc = !processSort.asc;
    } else {
        processSort.col = col;
        processSort.asc = false;
    }
    if (currentData) renderProcessTable(currentData.top_processes);
}

// --- Search ---

function setupProcessSearch() {
    const input = document.getElementById('process-search');
    if (input) {
        input.addEventListener('input', () => {
            processSearch = input.value;
            if (currentData) renderProcessTable(currentData.top_processes);
        });
    }
}

function onSearchClear() {
    processSearch = '';
    const input = document.getElementById('process-search');
    if (input) input.value = '';
    if (currentData) renderProcessTable(currentData.top_processes);
}
