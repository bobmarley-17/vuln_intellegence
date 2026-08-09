document.addEventListener('DOMContentLoaded', function () {
    const API_BASE = '/api';
    let severityChart = null;
    let trendChart = null;
    let kevSplitChart = null;
    let vendorBarChart = null;
    let productBarChart = null;
    let articlesTrendChart = null;
    let sourceEffectivenessChart = null;

    const state = {
        page: 1,
        pageSize: 25,
        sortBy: 'risk_score',
        sortDir: 'desc',
        q: '',
        severity: '',
        vendor: '',
        product: '',
        min_cvss: '',
        max_cvss: '',
        min_epss: '',
        kev_only: false,
        source_site: '',
    };

    const SOURCE_TYPE_LABELS = {
        rss_feed: 'RSS Feed',
        xml_feed: 'XML Feed',
        security_blog: 'Security Blog',
        vendor_advisory: 'Vendor Advisory',
        json_api: 'JSON API',
    };

    const sourcesState = {
        all: [],       // raw rows from the API
        q: '',
        type: '',
        sortBy: 'name',
        sortDir: 'asc',
        page: 1,
        pageSize: 10,
    };

    function escapeHtml(value) {
        const element = document.createElement('div');
        element.textContent = value ?? '';
        return element.innerHTML;
    }

    function formatDate(value) {
        if (!value) return 'N/A';
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? 'N/A' : date.toLocaleDateString();
    }

    function riskLevel(value) {
        return ['Critical', 'High', 'Medium', 'Low'].includes(value) ? value : 'Low';
    }

    function pct(n, total) {
        if (!total) return 0;
        return Math.round((n / total) * 100);
    }

    function setTrend(elementId, text) {
        const el = document.getElementById(elementId);
        if (el) el.textContent = text;
    }

    function fetchStats() {
        fetch(`${API_BASE}/stats`)
            .then(response => response.json())
            .then(data => {
                const total = data.total_cves || 0;
                const sev = data.severity_counts || {};
                document.getElementById('total-cves').textContent = total;
                document.getElementById('total-articles').textContent = data.total_articles;
                document.getElementById('kev-count').textContent = data.kev_count;
                document.getElementById('vendor-count').textContent = data.vendor_count;
                document.getElementById('product-count').textContent = data.product_count;
                document.getElementById('critical-count').textContent = sev.Critical || 0;
                document.getElementById('high-count').textContent = sev.High || 0;

                // Real, non-fabricated secondary metrics -- no invented trend
                // arrows, since there's no historical snapshot to compare against.
                setTrend('trend-cves', data.recent_cves_7d ? `+${data.recent_cves_7d} in the last 7 days` : 'No new CVEs in 7 days');
                setTrend('trend-critical', total ? `${pct(sev.Critical, total)}% of tracked CVEs` : ' ');
                setTrend('trend-high', total ? `${pct(sev.High, total)}% of tracked CVEs` : ' ');
                setTrend('trend-kev', total ? `${pct(data.kev_count, total)}% of tracked CVEs` : ' ');
                setTrend('trend-articles', data.recent_articles_7d ? `+${data.recent_articles_7d} in the last 7 days` : 'No new articles in 7 days');
                setTrend('trend-vendors', data.top_vendor ? `Top: ${data.top_vendor.name} (${data.top_vendor.count})` : ' ');
                setTrend('trend-products', data.top_product ? `Top: ${data.top_product.name} (${data.top_product.count})` : ' ');

                renderSeverityChart(data.severity_counts);
            })
            .catch(error => console.error('Error fetching stats:', error));
    }

    function fetchFilters() {
        fetch(`${API_BASE}/filters`)
            .then(response => response.json())
            .then(data => {
                populateDropdown('filter-vendor', data.vendors);
                populateDropdown('filter-product', data.products);
                populateDropdown('filter-source', data.sources);
                populateDatalist('checker-vendor-list', data.vendors);
                populateDatalist('checker-product-list', data.products);
            })
            .catch(error => console.error('Error fetching filters:', error));
    }

    function fetchSources() {
        fetch(`${API_BASE}/sources`)
            .then(response => response.json())
            .then(data => {
                sourcesState.all = data;
                renderSourcesTable();
                renderSourceEffectivenessChart();
                populateScanHistorySourceFilter();
                const el = document.getElementById('sources-summary-line');
                if (el) {
                    const enabledCount = data.filter(s => s.enabled).length;
                    el.textContent = `${data.length} source${data.length === 1 ? '' : 's'} configured (${enabledCount} enabled).`;
                }
            })
            .catch(error => console.error('Error fetching sources:', error));
    }

    function fetchSourceTypes() {
        fetch(`${API_BASE}/source-types`)
            .then(response => response.json())
            .then(data => {
                const select = document.getElementById('sources-type-filter');
                (data.source_types || []).forEach(type => {
                    const opt = document.createElement('option');
                    opt.value = type;
                    opt.textContent = SOURCE_TYPE_LABELS[type] || type;
                    select.appendChild(opt);
                });
            })
            .catch(error => console.error('Error fetching source types:', error));
    }

    function cveFilterParams(overrides = {}) {
        return new URLSearchParams({
            sort_by: state.sortBy,
            sort_dir: state.sortDir,
            q: state.q,
            severity: state.severity,
            vendor: state.vendor,
            product: state.product,
            min_cvss: state.min_cvss,
            max_cvss: state.max_cvss,
            min_epss: state.min_epss,
            kev_only: state.kev_only,
            source_site: state.source_site,
            ...overrides,
        });
    }

    function fetchCVEs() {
        const params = cveFilterParams({ page: state.page, page_size: state.pageSize });
        fetch(`${API_BASE}/cves?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                renderTable(data.items);
                renderPagination(data.total, data.page, data.page_size);
                const el = document.getElementById('cve-summary-line');
                if (el) el.textContent = `${data.total} CVE${data.total === 1 ? '' : 's'} match your filters.`;
            })
            .catch(error => console.error('Error fetching CVEs:', error));
    }

    function populateDropdown(elementId, options) {
        const select = document.getElementById(elementId);
        select.innerHTML = '<option value="">All</option>'; // Reset
        options.forEach(option => {
            const opt = document.createElement('option');
            opt.value = option;
            opt.textContent = option;
            select.appendChild(opt);
        });
    }

    function populateDatalist(elementId, options) {
        const datalist = document.getElementById(elementId);
        if (!datalist) return;
        datalist.innerHTML = '';
        options.forEach(option => {
            const opt = document.createElement('option');
            opt.value = option;
            datalist.appendChild(opt);
        });
    }

    function getFilteredSortedSources() {
        let rows = sourcesState.all;
        if (sourcesState.type) {
            rows = rows.filter(s => s.source_type === sourcesState.type);
        }
        if (sourcesState.q) {
            const q = sourcesState.q.toLowerCase();
            rows = rows.filter(s =>
                (s.name || '').toLowerCase().includes(q) ||
                (s.url || '').toLowerCase().includes(q) ||
                (s.vendor || '').toLowerCase().includes(q)
            );
        }
        const dir = sourcesState.sortDir === 'asc' ? 1 : -1;
        const key = sourcesState.sortBy;
        rows = [...rows].sort((a, b) => {
            let av = a[key];
            let bv = b[key];
            if (key === 'name') {
                av = av || a.url;
                bv = bv || b.url;
            }
            if (av === null || av === undefined) av = '';
            if (bv === null || bv === undefined) bv = '';
            if (typeof av === 'string') av = av.toLowerCase();
            if (typeof bv === 'string') bv = bv.toLowerCase();
            if (av < bv) return -1 * dir;
            if (av > bv) return 1 * dir;
            return 0;
        });
        return rows;
    }

    function sourceActionButtons(source) {
        return `
            <div class="source-actions">
                <button class="btn btn-outline-secondary" data-action="view" data-id="${source.id}" title="View"><i class="bi bi-eye"></i></button>
                <button class="btn btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#addSourceModal" data-source-id="${source.id}" title="Edit"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-outline-secondary" data-action="scan" data-id="${source.id}" title="Run Scan" ${!source.enabled ? 'disabled' : ''}><i class="bi bi-play-fill"></i></button>
                <button class="btn btn-outline-secondary" data-action="toggle" data-id="${source.id}" data-enabled="${source.enabled}" title="${source.enabled ? 'Disable' : 'Enable'}"><i class="bi ${source.enabled ? 'bi-toggle-on' : 'bi-toggle-off'}"></i></button>
                <button class="btn btn-outline-secondary" data-action="history" data-id="${source.id}" title="Scan History"><i class="bi bi-clock-history"></i></button>
                <button class="btn btn-outline-danger" data-action="delete" data-id="${source.id}" title="Delete"><i class="bi bi-trash"></i></button>
            </div>
        `;
    }

    function handleSourceAction(e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const { action, id } = btn.dataset;
        if (action === 'view') viewSource(id);
        else if (action === 'scan') runSourceScan(id);
        else if (action === 'toggle') toggleSourceEnabled(id, btn.dataset.enabled === 'true');
        else if (action === 'history') showSourceHistory(id);
        else if (action === 'delete') openDeleteSourceModal(id);
    }

    let lastFilteredSources = [];

    function renderSourcesTable() {
        const tbody = document.getElementById('sources-table-body');
        const cardContainer = document.getElementById('sources-card-view');
        const emptyState = document.getElementById('sources-empty-state');
        const filtered = getFilteredSortedSources();
        lastFilteredSources = filtered;

        if (sourcesState.all.length === 0) {
            tbody.innerHTML = '';
            cardContainer.innerHTML = '';
            emptyState.classList.remove('d-none');
            renderSourcesPagination(0);
            return;
        }
        emptyState.classList.add('d-none');

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted py-4">No sources match your search/filter.</td></tr>';
            cardContainer.innerHTML = '<p class="text-muted text-center py-4">No sources match your search/filter.</p>';
            renderSourcesPagination(0);
            return;
        }

        const totalPages = Math.max(Math.ceil(filtered.length / sourcesState.pageSize), 1);
        sourcesState.page = Math.min(sourcesState.page, totalPages);
        const start = (sourcesState.page - 1) * sourcesState.pageSize;
        const pageRows = filtered.slice(start, start + sourcesState.pageSize);

        tbody.innerHTML = '';
        cardContainer.innerHTML = '';
        pageRows.forEach(source => {
            const row = document.createElement('tr');
            if (!source.enabled) row.classList.add('source-row-disabled');

            const statusKey = source.enabled ? (source.status || 'Pending').toLowerCase() : 'disabled';
            const statusLabel = source.enabled ? (source.status || 'Pending') : 'Disabled';
            const lastScan = source.last_checked ? new Date(source.last_checked).toLocaleString() : 'Never';
            const typeLabel = SOURCE_TYPE_LABELS[source.source_type] || source.source_type;
            const articles = source.last_articles_processed !== null && source.last_articles_processed !== undefined ? source.last_articles_processed : '—';
            const cves = source.cves_found !== null && source.cves_found !== undefined ? source.cves_found : '—';

            row.innerHTML = `
                <td><strong>${escapeHtml(source.name || '(unnamed)')}</strong>${source.vendor ? `<div class="text-muted small">${escapeHtml(source.vendor)}</div>` : ''}</td>
                <td><a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer" class="source-url-cell" title="${escapeHtml(source.url)}">${escapeHtml(source.url)}</a></td>
                <td><span class="source-type-badge">${escapeHtml(typeLabel)}</span></td>
                <td class="text-center"><span class="source-status-pill status-${statusKey}">${escapeHtml(statusLabel)}</span></td>
                <td>${lastScan}</td>
                <td class="text-center">${articles}</td>
                <td class="text-center">${cves}</td>
                <td>${source.last_error ? `<span class="source-error-cell" title="${escapeHtml(source.last_error)}">${escapeHtml(source.last_error)}</span>` : '<span class="text-muted">&mdash;</span>'}</td>
                <td>${sourceActionButtons(source)}</td>
            `;
            tbody.appendChild(row);

            const card = document.createElement('div');
            card.className = `entity-card${!source.enabled ? ' source-card-disabled' : ''}`;
            card.innerHTML = `
                <div class="entity-card-head">
                    <span class="avatar-circle" style="background: ${avatarColor(source.name || source.url)};"><i class="bi bi-rss"></i></span>
                    <div>
                        <div class="entity-card-title">${escapeHtml(source.name || '(unnamed)')}</div>
                        <div class="entity-card-subtitle text-truncate" title="${escapeHtml(source.url)}">${escapeHtml(source.url)}</div>
                    </div>
                </div>
                <div class="entity-card-metrics">
                    <span class="source-type-badge">${escapeHtml(typeLabel)}</span>
                    <span class="source-status-pill status-${statusKey}">${escapeHtml(statusLabel)}</span>
                    ${cves !== '—' ? `<span class="metric-chip chip-accent">${cves} CVEs</span>` : ''}
                </div>
                <div class="article-card-foot">
                    <span>Last scan: ${lastScan}</span>
                    <span>${articles !== '—' ? `${articles} articles` : ''}</span>
                </div>
                ${source.last_error ? `<div class="source-error-cell text-truncate" title="${escapeHtml(source.last_error)}">${escapeHtml(source.last_error)}</div>` : ''}
                ${sourceActionButtons(source)}
            `;
            cardContainer.appendChild(card);
        });

        renderSourcesPagination(filtered.length);
    }

    function renderSourcesPagination(total) {
        const pagination = document.getElementById('sources-pagination');
        pagination.innerHTML = '';
        const totalPages = Math.ceil(total / sourcesState.pageSize);
        if (totalPages <= 1) return;

        const createPageItem = (text, pageNum, isDisabled = false, isActive = false) => {
            const li = document.createElement('li');
            li.className = `page-item ${isDisabled ? 'disabled' : ''} ${isActive ? 'active' : ''}`;
            const a = document.createElement('a');
            a.className = 'page-link';
            a.href = '#';
            a.textContent = text;
            if (!isDisabled) a.dataset.page = pageNum;
            li.appendChild(a);
            return li;
        };

        pagination.appendChild(createPageItem('Previous', sourcesState.page - 1, sourcesState.page === 1));
        for (let i = 1; i <= totalPages; i++) {
            pagination.appendChild(createPageItem(i, i, false, i === sourcesState.page));
        }
        pagination.appendChild(createPageItem('Next', sourcesState.page + 1, sourcesState.page === totalPages));
    }

    function renderTable(cves) {
        const tbody = document.getElementById('cve-table-body');
        tbody.innerHTML = '';
        if (cves.length === 0) {
            tbody.innerHTML = '<tr><td colspan="9" class="text-center">No CVEs found.</td></tr>';
            return;
        }
        cves.forEach(cve => {
            const row = document.createElement('tr');
            row.setAttribute('data-bs-toggle', 'modal');
            row.setAttribute('data-bs-target', '#cveDetailModal');
            row.dataset.cveId = cve.cve_id; // For click events
            row.innerHTML = `
                <td>
                    <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}" target="_blank" rel="noopener noreferrer" class="cve-id-link">${escapeHtml(cve.cve_id)}</a>
                    ${cve.kev_listed ? '<span class="badge bg-danger ms-1">KEV</span>' : ''}
                </td>
                <td>${escapeHtml(cve.summary || (cve.description ? `${cve.description.slice(0, 150)}...` : 'No description'))}</td>
                <td class="text-center"><span class="badge badge-${riskLevel(cve.risk_level).toUpperCase()}">${escapeHtml(cve.risk_level || 'Not Available')}</span></td>
                <td class="text-center">${cve.cvss_score !== null && cve.cvss_score !== undefined ? cve.cvss_score.toFixed(1) : 'N/A'}</td>
                <td class="text-center">${cve.epss_score !== null && cve.epss_score !== undefined ? (cve.epss_score * 100).toFixed(1) + '%' : 'N/A'}</td>
                <td class="text-center">${cve.risk_score !== null ? cve.risk_score.toFixed(2) : 'N/A'}</td>
                <td>${escapeHtml(cve.vendor || 'N/A')}</td>
                <td>${formatDate(cve.published_date)}</td>
                <td>${formatDate(cve.modified_date)}</td>
            `;
            tbody.appendChild(row);
        });
    }

    function renderPagination(total, page, pageSize) {
        const pagination = document.getElementById('pagination');
        pagination.innerHTML = '';
        const totalPages = Math.ceil(total / pageSize);
        if (totalPages <= 1) return;

        const createPageItem = (text, pageNum, isDisabled = false, isActive = false) => {
            const li = document.createElement('li');
            li.className = `page-item ${isDisabled ? 'disabled' : ''} ${isActive ? 'active' : ''}`;
            const a = document.createElement('a');
            a.className = 'page-link';
            a.href = '#';
            a.textContent = text;
            if (!isDisabled) {
                a.dataset.page = pageNum;
            }
            li.appendChild(a);
            return li;
        };

        pagination.appendChild(createPageItem('Previous', page - 1, page === 1));

        // Simplified pagination logic
        for (let i = 1; i <= totalPages; i++) {
            if (i === 1 || i === totalPages || (i >= page - 2 && i <= page + 2)) {
                pagination.appendChild(createPageItem(i, i, false, i === page));
            } else if (i === page - 3 || i === page + 3) {
                pagination.appendChild(createPageItem('...', 0, true));
            }
        }

        pagination.appendChild(createPageItem('Next', page + 1, page === totalPages));
    }

    function cssVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    }

    function hexToRgba(hex, alpha) {
        const clean = (hex || '#888888').replace('#', '');
        const full = clean.length === 3 ? clean.split('').map(c => c + c).join('') : clean;
        const bigint = parseInt(full, 16);
        const r = (bigint >> 16) & 255;
        const g = (bigint >> 8) & 255;
        const b = bigint & 255;
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }

    // Letter avatars: no external logo service is wired up, so vendors and
    // sources get a deterministic colored initial instead of a fetched icon.
    const AVATAR_COLOR_VARS = ['--avatar-palette-1', '--avatar-palette-2', '--avatar-palette-3', '--avatar-palette-4', '--avatar-palette-5', '--avatar-palette-6'];
    function avatarColor(name) {
        const str = name || '?';
        let hash = 0;
        for (let i = 0; i < str.length; i++) hash = str.charCodeAt(i) + ((hash << 5) - hash);
        return cssVar(AVATAR_COLOR_VARS[Math.abs(hash) % AVATAR_COLOR_VARS.length]);
    }
    function avatarInitial(name) {
        const trimmed = (name || '').trim();
        return trimmed ? trimmed.charAt(0).toUpperCase() : '?';
    }

    // Fixed status palette: severity is a state, not an open-ended category,
    // so each bar gets a reserved status color rather than a generated hue.
    const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low'];
    const SEVERITY_COLOR_VAR = { Critical: '--critical', High: '--high', Medium: '--medium', Low: '--low' };

    function renderSeverityChart(severityCounts) {
        const ctx = document.getElementById('severityChart').getContext('2d');
        const data = SEVERITY_ORDER.map(level => severityCounts[level] || 0);
        const colors = SEVERITY_ORDER.map(level => cssVar(SEVERITY_COLOR_VAR[level]));
        const mutedText = cssVar('--text-muted');
        const gridColor = cssVar('--chart-grid');
        const axisColor = cssVar('--chart-axis');

        if (severityChart) {
            severityChart.destroy();
        }

        severityChart = new Chart(ctx, {
            type: 'bar',
            data: {
                // Counts ride the axis labels directly -- a single-series bar
                // chart needs no legend box.
                labels: SEVERITY_ORDER.map((level, i) => `${level} (${data[i]})`),
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderRadius: 4,
                    borderSkipped: false,
                    maxBarThickness: 24,
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            title: (items) => SEVERITY_ORDER[items[0].dataIndex],
                            label: (item) => `${item.raw} CVE${item.raw === 1 ? '' : 's'}`,
                        },
                    },
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: { precision: 0, color: mutedText },
                        grid: { color: gridColor },
                    },
                    y: {
                        ticks: { color: mutedText, font: { weight: '600' } },
                        grid: { display: false },
                    },
                },
            },
        });
    }

    function handleFilterChange() {
        state.q = document.getElementById('search-input').value;
        state.severity = document.getElementById('filter-severity').value;
        state.vendor = document.getElementById('filter-vendor').value;
        state.product = document.getElementById('filter-product').value;
        state.min_cvss = document.getElementById('filter-min-cvss').value;
        state.max_cvss = document.getElementById('filter-max-cvss').value;
        state.min_epss = document.getElementById('filter-min-epss').value;
        state.kev_only = document.getElementById('filter-kev').checked;
        state.source_site = document.getElementById('filter-source').value;
        state.page = 1; // Reset to first page on filter change
        fetchCVEs();
    }

    // --- App shell navigation: sidebar pages, breadcrumbs, hash deep-links ---
    // This is a small custom router rather than Bootstrap's Tab component:
    // the sidebar links live far from .app-page in the DOM, and navigation
    // here also needs to drive the breadcrumb, page title, and location.hash
    // in lockstep, which is simpler to own directly than to layer on top of
    // Tab's own active-state management.
    function switchToTab(pageId, options = {}) {
        document.querySelectorAll('.app-page').forEach(p => p.classList.remove('active'));
        const page = document.getElementById(pageId);
        if (!page) return;
        page.classList.add('active');

        document.querySelectorAll('.sidebar-link').forEach(link => link.classList.remove('active'));
        const link = document.querySelector(`.sidebar-link[data-target="${pageId}"]`);
        if (link) {
            link.classList.add('active');
            document.getElementById('page-title').textContent = link.dataset.title;
            document.getElementById('breadcrumb-section').textContent = link.dataset.section;
            document.getElementById('breadcrumb-page').textContent = link.dataset.title;
        }
        if (!options.skipHash) {
            history.replaceState(null, '', `#/${pageId.replace('tab-', '')}`);
        }
        document.getElementById('app-shell').classList.remove('sidebar-mobile-open');

        if (pageId === 'tab-dashboard' && severityChart) severityChart.resize();
        if (pageId === 'tab-analytics') {
            [trendChart, kevSplitChart, vendorBarChart, productBarChart, articlesTrendChart, sourceEffectivenessChart].forEach(c => c && c.resize());
        }
    }

    function pageIdFromHash() {
        const slug = location.hash.replace('#/', '').trim();
        if (!slug) return 'tab-dashboard';
        const candidate = `tab-${slug}`;
        return document.getElementById(candidate) ? candidate : 'tab-dashboard';
    }

    document.querySelectorAll('.sidebar-link').forEach(link => {
        link.addEventListener('click', () => switchToTab(link.dataset.target));
    });
    document.querySelectorAll('[data-nav]').forEach(el => {
        el.addEventListener('click', () => switchToTab(el.dataset.nav));
    });

    document.getElementById('sidebar-collapse-btn').addEventListener('click', () => {
        document.getElementById('app-shell').classList.toggle('sidebar-collapsed');
    });
    document.getElementById('sidebar-mobile-toggle').addEventListener('click', () => {
        document.getElementById('app-shell').classList.toggle('sidebar-mobile-open');
    });

    function goToOverviewFiltered(filters = {}) {
        document.getElementById('search-input').value = '';
        document.getElementById('filter-severity').value = filters.severity || '';
        document.getElementById('filter-vendor').value = filters.vendor || '';
        document.getElementById('filter-product').value = filters.product || '';
        document.getElementById('filter-source').value = '';
        document.getElementById('filter-min-cvss').value = '';
        document.getElementById('filter-max-cvss').value = '';
        document.getElementById('filter-min-epss').value = '';
        document.getElementById('filter-kev').checked = !!filters.kevOnly;

        handleFilterChange();

        const collapseEl = document.getElementById('filterCollapse');
        if (filters.vendor || filters.product || filters.kevOnly || filters.severity) {
            bootstrap.Collapse.getOrCreateInstance(collapseEl, { toggle: false }).show();
        }
        switchToTab('tab-overview');
    }

    document.getElementById('stat-tile-cves').addEventListener('click', () => goToOverviewFiltered({}));
    document.getElementById('stat-tile-critical').addEventListener('click', () => goToOverviewFiltered({ severity: 'CRITICAL' }));
    document.getElementById('stat-tile-high').addEventListener('click', () => goToOverviewFiltered({ severity: 'HIGH' }));
    document.getElementById('stat-tile-kev').addEventListener('click', () => switchToTab('tab-kev'));
    document.getElementById('stat-tile-articles').addEventListener('click', () => switchToTab('tab-articles'));
    document.getElementById('stat-tile-vendors').addEventListener('click', () => switchToTab('tab-vendors'));
    document.getElementById('stat-tile-products').addEventListener('click', () => switchToTab('tab-products'));

    // role="button" tiles should also respond to keyboard activation.
    document.querySelectorAll('.stat-tile-clickable[role="button"]').forEach(el => {
        el.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                el.click();
            }
        });
    });

    // Event Listeners
    document.getElementById('filter-btn').addEventListener('click', handleFilterChange);

    document.getElementById('reset-btn').addEventListener('click', () => {
        document.getElementById('filter-form').reset();
        handleFilterChange();
    });

    document.getElementById('cve-export-btn').addEventListener('click', () => {
        const params = cveFilterParams({ page: 1, page_size: 200 });
        fetch(`${API_BASE}/cves?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                exportToCsv('cve-explorer.csv', data.items, [
                    { key: 'cve_id', label: 'CVE ID' },
                    { key: 'risk_level', label: 'Severity' },
                    { label: 'CVSS', value: (r) => r.cvss_score },
                    { label: 'EPSS', value: (r) => r.epss_score },
                    { key: 'risk_score', label: 'Risk Score' },
                    { key: 'vendor', label: 'Vendor' },
                    { key: 'product', label: 'Product' },
                    { key: 'published_date', label: 'Published' },
                    { key: 'modified_date', label: 'Updated' },
                    { key: 'kev_listed', label: 'KEV' },
                ]);
                if (data.total > data.items.length) {
                    showToast(`Note: only the first ${data.items.length} of ${data.total} matching CVEs were exported.`, 'info');
                }
            })
            .catch(error => console.error('Error exporting CVEs:', error));
    });

    document.getElementById('pagination').addEventListener('click', (e) => {
        if (e.target.tagName === 'A' && e.target.dataset.page) {
            e.preventDefault();
            state.page = parseInt(e.target.dataset.page, 10);
            fetchCVEs();
        }
    });

    document.getElementById('cveTable').querySelector('thead').addEventListener('click', (e) => {
        const th = e.target.closest('th');
        if (th && th.dataset.sort) {
            const sortField = th.dataset.sort;
            if (state.sortBy === sortField) {
                state.sortDir = state.sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                state.sortBy = sortField;
                state.sortDir = 'desc';
            }
            // Update sort indicators
            document.querySelectorAll('#cveTable thead th').forEach(header => {
                header.classList.remove('sort-asc', 'sort-desc');
                const icon = header.querySelector('.sort-icon');
                if (icon) icon.innerHTML = '&#x2195;';
            });
            th.classList.add(state.sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
            const icon = th.querySelector('.sort-icon');
            if(icon) icon.innerHTML = state.sortDir === 'asc' ? '&#x2191;' : '&#x2193;';

            fetchCVEs();
        }
    });

    // Debounce search input
    let searchTimeout;
    document.getElementById('search-input').addEventListener('keyup', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            handleFilterChange();
        }, 300);
    });

    document.getElementById('cve-table-body').addEventListener('click', (e) => {
        const row = e.target.closest('tr');
        if (row && row.dataset.cveId) {
            const cveId = row.dataset.cveId;
            fetchAndShowCveDetails(cveId);
        }
    });

    function fetchAndShowCveDetails(cveId) {
        fetch(`${API_BASE}/cve/${encodeURIComponent(cveId)}`)
            .then(response => {
                if (!response.ok) throw new Error(`CVE not found: ${cveId}`);
                return response.json();
            })
            .then(cve => {
                renderCveModal(cve);
                loadRelatedCves(cve);
            })
            .catch(error => console.error('Could not find details for', cveId, error));
    }

    function humanizeEnum(value) {
        if (!value) return null;
        return value.toLowerCase().split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
    }

    function renderCveModal(cve) {
        document.getElementById('cveDetailModalLabel').innerHTML = `
            ${escapeHtml(cve.cve_id)}
            ${cve.kev_listed ? '<span class="badge bg-danger ms-2">KEV &mdash; Actively Exploited</span>' : ''}
        `;
        const body = document.getElementById('cve-detail-body');

        const score = (s) => (s !== null && s !== undefined) ? s.toFixed(2) : 'N/A';
        const na = (v) => v || 'Not Available';
        const enumOrNA = (v) => humanizeEnum(v) || 'N/A';

        const cvssRows = [
            ['Attack Vector', enumOrNA(cve.attack_vector)],
            ['Attack Complexity', enumOrNA(cve.attack_complexity)],
            ['Privileges Required', enumOrNA(cve.privileges_required)],
            ['User Interaction', enumOrNA(cve.user_interaction)],
            ['Scope', enumOrNA(cve.scope)],
            ['Confidentiality Impact', enumOrNA(cve.confidentiality_impact)],
            ['Integrity Impact', enumOrNA(cve.integrity_impact)],
            ['Availability Impact', enumOrNA(cve.availability_impact)],
        ];

        const timelineItems = [
            ['Published', formatDate(cve.published_date)],
            ['Last Modified', formatDate(cve.modified_date)],
        ];
        if (cve.kev_listed) {
            timelineItems.push(['Added to CISA KEV', formatDate(cve.kev_date_added)]);
            if (cve.kev_due_date) timelineItems.push(['KEV Remediation Due', formatDate(cve.kev_due_date)]);
        }

        const references = cve.references || [];
        const visibleRefs = references.slice(0, 5);
        const extraRefs = references.slice(5);

        body.innerHTML = `
            <div class="detail-section">
                <h6>Analyst Summary</h6>
                <p class="mb-0">${na(cve.summary)}</p>
            </div>

            ${cve.description && cve.description !== cve.summary ? `
            <div class="detail-section">
                <h6>Official Description</h6>
                <p class="mb-0 text-muted">${escapeHtml(cve.description)}</p>
            </div>` : ''}

            <div class="row">
                <div class="col-md-6">
                    <div class="detail-section">
                        <h6>Overview</h6>
                        <dl class="detail-kv">
                            <dt>Severity</dt><dd><span class="badge badge-${(cve.risk_level || 'LOW').toUpperCase()}">${escapeHtml(cve.risk_level || 'Not Available')}</span></dd>
                            <dt>Risk Score</dt><dd>${score(cve.risk_score)} / 100</dd>
                            <dt>Recommendation</dt><dd>${na(cve.risk_recommendation)}</dd>
                            <dt>Vendor</dt><dd>${na(cve.vendor)}</dd>
                            <dt>Product</dt><dd>${na(cve.product)}</dd>
                            <dt>CWE</dt><dd>${cve.cwe && cve.cwe.length ? cve.cwe.join(', ') : 'N/A'}</dd>
                        </dl>
                    </div>
                    <div class="detail-section">
                        <h6>Scoring</h6>
                        <dl class="detail-kv">
                            <dt>CVSS v4</dt><dd>${score(cve.cvss_v4_score)}</dd>
                            <dt>CVSS v3</dt><dd>${score(cve.cvss_v3_score)}</dd>
                            <dt>EPSS</dt><dd>${cve.epss_score !== null && cve.epss_score !== undefined ? (cve.epss_score * 100).toFixed(1) + '%' : 'N/A'}</dd>
                            <dt>KEV Listed</dt><dd>${cve.kev_listed ? '<span class="text-danger fw-bold">Yes</span>' : 'No'}</dd>
                        </dl>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="detail-section">
                        <h6>CVSS Vector Breakdown</h6>
                        <dl class="detail-kv">
                            ${cvssRows.map(([label, value]) => `<dt>${label}</dt><dd>${escapeHtml(value)}</dd>`).join('')}
                        </dl>
                    </div>
                    <div class="detail-section">
                        <h6>Timeline</h6>
                        <ul class="timeline-list">
                            ${timelineItems.map(([label, value]) => `<li><span>${label}</span><span>${escapeHtml(value)}</span></li>`).join('')}
                        </ul>
                    </div>
                </div>
            </div>

            <div class="row">
                <div class="col-md-6">
                    <div class="detail-section">
                        <h6>Affected Versions</h6>
                        <p class="mb-0">${na(cve.affected_versions_display)}</p>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="detail-section">
                        <h6>Fixed Versions</h6>
                        <p class="mb-0">${na(cve.fixed_versions_display)}</p>
                    </div>
                </div>
            </div>

            <div class="detail-section">
                <h6>References (${references.length})</h6>
                <div class="reference-list">
                    ${references.length === 0 ? '<p class="text-muted mb-0">No references collected.</p>' : ''}
                    ${visibleRefs.map(ref => `<a href="${escapeHtml(ref)}" target="_blank" rel="noopener noreferrer" class="d-block text-truncate">${escapeHtml(ref)}</a>`).join('')}
                    <div id="extra-references" class="d-none">
                        ${extraRefs.map(ref => `<a href="${escapeHtml(ref)}" target="_blank" rel="noopener noreferrer" class="d-block text-truncate">${escapeHtml(ref)}</a>`).join('')}
                    </div>
                    ${extraRefs.length > 0 ? `<button type="button" class="btn btn-link btn-sm ps-0" id="toggle-references-btn">Show ${extraRefs.length} more</button>` : ''}
                </div>
            </div>

            <div class="detail-section">
                <h6>Related CVEs (same vendor/product)</h6>
                <div id="related-cves-container" class="related-cve-list">
                    <span class="text-muted small">Loading&hellip;</span>
                </div>
            </div>
        `;

        const toggleBtn = document.getElementById('toggle-references-btn');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                const extra = document.getElementById('extra-references');
                const expanding = extra.classList.contains('d-none');
                extra.classList.toggle('d-none');
                toggleBtn.textContent = expanding ? 'Show fewer' : `Show ${extraRefs.length} more`;
            });
        }
    }

    function loadRelatedCves(cve) {
        const container = document.getElementById('related-cves-container');
        if (!container) return;
        if (!cve.vendor || !cve.product) {
            container.innerHTML = '<span class="text-muted small">Not enough vendor/product data to find related CVEs.</span>';
            return;
        }
        const params = new URLSearchParams({
            vendor: cve.vendor,
            product: cve.product,
            page_size: 6,
            sort_by: 'published',
            sort_dir: 'desc',
        });
        fetch(`${API_BASE}/cves?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                // The modal may have re-rendered for a different CVE while this was in flight.
                const current = document.getElementById('related-cves-container');
                if (!current) return;
                const related = (data.items || []).filter(item => item.cve_id !== cve.cve_id).slice(0, 5);
                if (related.length === 0) {
                    current.innerHTML = '<span class="text-muted small">No other known CVEs for this product.</span>';
                    return;
                }
                current.innerHTML = related.map(item => `
                    <a href="#" class="related-cve-link" data-cve-id="${escapeHtml(item.cve_id)}">
                        <span class="cve-id-link">${escapeHtml(item.cve_id)}</span>
                        <span class="badge badge-${riskLevel(item.risk_level).toUpperCase()}">${escapeHtml(item.risk_level || 'N/A')}</span>
                    </a>
                `).join('');
            })
            .catch(error => console.error('Error loading related CVEs:', error));
    }

    document.getElementById('cve-detail-body').addEventListener('click', (e) => {
        const link = e.target.closest('.related-cve-link');
        if (link) {
            e.preventDefault();
            fetchAndShowCveDetails(link.dataset.cveId);
        }
    });

    function severityBarsHtml(counts, total) {
        const order = [['Critical', '--critical'], ['High', '--high'], ['Medium', '--medium'], ['Low', '--low']];
        return order.map(([level, colorVar]) => {
            const n = counts[level] || 0;
            const barPct = total ? Math.round((n / total) * 100) : 0;
            return `
                <div class="severity-bar-row">
                    <span class="label">${level}</span>
                    <span class="track"><span class="fill" style="width:${barPct}%; background: var(${colorVar});"></span></span>
                    <span class="count">${n}</span>
                </div>
            `;
        }).join('');
    }

    function recentCveRowsHtml(items) {
        return items.map(item => `
            <div class="recent-cve-row" data-cve-id="${escapeHtml(item.cve_id)}">
                <div>
                    <span class="cve-id-link">${escapeHtml(item.cve_id)}</span>
                    ${item.kev_listed ? '<span class="badge bg-danger ms-1">KEV</span>' : ''}
                    <div class="recent-cve-meta">${escapeHtml(item.vendor || 'Unknown vendor')}${item.product ? ' / ' + escapeHtml(item.product) : ''}</div>
                </div>
                <div class="text-end">
                    <span class="badge badge-${riskLevel(item.risk_level).toUpperCase()}">${escapeHtml(item.risk_level || 'N/A')}</span>
                    <div class="recent-cve-meta">${formatDate(item.published_date)}</div>
                </div>
            </div>
        `).join('');
    }

    function recentAdvisoriesHtml(items) {
        if (!items || items.length === 0) return '<p class="text-muted small mb-0">No CVEs found.</p>';
        return `<div class="recent-cve-list">${recentCveRowsHtml(items)}</div>`;
    }

    function wireRecentCveRows(container) {
        container.querySelectorAll('.recent-cve-row').forEach(row => {
            row.addEventListener('click', () => fetchAndShowCveDetails(row.dataset.cveId));
        });
    }

    // --- Vendor detail modal ---
    function showVendorDetail(vendorName) {
        document.getElementById('vendorDetailModalLabel').textContent = vendorName;
        const body = document.getElementById('vendor-detail-body');
        body.innerHTML = '<div class="text-center py-4"><div class="spinner-border spinner-border-sm text-accent" role="status"></div></div>';
        bootstrap.Modal.getOrCreateInstance(document.getElementById('vendorDetailModal')).show();

        const params = new URLSearchParams({ vendor: vendorName, page_size: 200, sort_by: 'published', sort_dir: 'desc' });
        fetch(`${API_BASE}/cves?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                const items = data.items || [];
                const products = [...new Set(items.map(c => c.product).filter(Boolean))];
                const severityCounts = {};
                let kevCount = 0;
                items.forEach(c => {
                    const level = c.risk_level || 'Low';
                    severityCounts[level] = (severityCounts[level] || 0) + 1;
                    if (c.kev_listed) kevCount++;
                });

                body.innerHTML = `
                    <div class="detail-section">
                        <h6>Overview</h6>
                        <dl class="detail-kv">
                            <dt>Total CVEs</dt><dd>${data.total}</dd>
                            <dt>KEV Listed</dt><dd>${kevCount}</dd>
                            <dt>Products</dt><dd>${products.length}</dd>
                        </dl>
                    </div>
                    <div class="detail-section">
                        <h6>Severity Distribution</h6>
                        ${severityBarsHtml(severityCounts, data.total)}
                    </div>
                    <div class="detail-section">
                        <h6>Associated Products</h6>
                        <div class="entity-card-metrics">
                            ${products.length ? products.map(p => `<button type="button" class="metric-chip chip-accent product-chip-link" data-product="${escapeHtml(p)}" style="border:none; cursor:pointer;">${escapeHtml(p)}</button>`).join('') : '<span class="text-muted small">No products identified.</span>'}
                        </div>
                    </div>
                    <div class="detail-section">
                        <h6>Recent Advisories</h6>
                        ${recentAdvisoriesHtml(items.slice(0, 8))}
                    </div>
                    <button type="button" class="btn btn-outline-secondary btn-sm" id="vendor-detail-view-all">
                        <i class="bi bi-funnel"></i> View all ${data.total} CVEs in Explorer
                    </button>
                `;
                wireRecentCveRows(body);
                document.getElementById('vendor-detail-view-all').addEventListener('click', () => {
                    bootstrap.Modal.getInstance(document.getElementById('vendorDetailModal'))?.hide();
                    goToOverviewFiltered({ vendor: vendorName });
                });
                body.querySelectorAll('.product-chip-link').forEach(chip => {
                    chip.addEventListener('click', () => showProductDetail(vendorName, chip.dataset.product));
                });
            })
            .catch(error => {
                console.error('Error loading vendor detail:', error);
                body.innerHTML = '<p class="text-danger small mb-0">Failed to load vendor details.</p>';
            });
    }

    // --- Product detail modal ---
    function showProductDetail(vendorName, productName) {
        document.getElementById('productDetailModalLabel').textContent = productName;
        const body = document.getElementById('product-detail-body');
        body.innerHTML = '<div class="text-center py-4"><div class="spinner-border spinner-border-sm text-accent" role="status"></div></div>';
        bootstrap.Modal.getOrCreateInstance(document.getElementById('productDetailModal')).show();

        const params = new URLSearchParams({ vendor: vendorName || '', product: productName, page_size: 200, sort_by: 'published', sort_dir: 'desc' });
        fetch(`${API_BASE}/cves?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                const items = data.items || [];
                const kevCount = items.filter(c => c.kev_listed).length;

                body.innerHTML = `
                    <div class="detail-section">
                        <h6>Overview</h6>
                        <dl class="detail-kv">
                            <dt>Vendor</dt><dd>${escapeHtml(vendorName || 'Unknown')}</dd>
                            <dt>Total CVEs</dt><dd>${data.total}</dd>
                            <dt>KEV Listed</dt><dd>${kevCount}</dd>
                        </dl>
                    </div>
                    <div class="detail-section">
                        <h6>Affected &amp; Fixed Versions</h6>
                        <div class="table-responsive">
                            <table class="table app-table">
                                <thead><tr><th>CVE ID</th><th class="text-center">Severity</th><th>Affected Versions</th><th>Fixed Versions</th></tr></thead>
                                <tbody>
                                    ${items.slice(0, 15).map(c => `
                                        <tr class="version-row" data-cve-id="${escapeHtml(c.cve_id)}" style="cursor:pointer;">
                                            <td><span class="cve-id-link">${escapeHtml(c.cve_id)}</span></td>
                                            <td class="text-center"><span class="badge badge-${riskLevel(c.risk_level).toUpperCase()}">${escapeHtml(c.risk_level || 'N/A')}</span></td>
                                            <td class="small">${escapeHtml(c.affected_versions_display || 'Not Available')}</td>
                                            <td class="small">${escapeHtml(c.fixed_versions_display || 'Not published')}</td>
                                        </tr>
                                    `).join('') || '<tr><td colspan="4" class="text-center text-muted">No CVEs found.</td></tr>'}
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <button type="button" class="btn btn-outline-secondary btn-sm" id="product-detail-view-all">
                        <i class="bi bi-funnel"></i> View all ${data.total} CVEs in Explorer
                    </button>
                `;
                body.querySelectorAll('.version-row').forEach(row => {
                    row.addEventListener('click', () => fetchAndShowCveDetails(row.dataset.cveId));
                });
                document.getElementById('product-detail-view-all').addEventListener('click', () => {
                    bootstrap.Modal.getInstance(document.getElementById('productDetailModal'))?.hide();
                    goToOverviewFiltered({ vendor: vendorName, product: productName });
                });
            })
            .catch(error => {
                console.error('Error loading product detail:', error);
                body.innerHTML = '<p class="text-danger small mb-0">Failed to load product details.</p>';
            });
    }

    // --- KEV page ---
    let lastKevResults = [];

    function fetchKevCves() {
        const params = new URLSearchParams({ kev_only: 'true', sort_by: 'risk_score', sort_dir: 'desc', page_size: 100 });
        fetch(`${API_BASE}/cves?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                lastKevResults = data.items || [];
                renderKevTable(lastKevResults);
                const el = document.getElementById('kev-summary-line');
                if (el) el.textContent = `${lastKevResults.length} actively exploited CVE${lastKevResults.length === 1 ? '' : 's'} confirmed by CISA.`;
            })
            .catch(error => console.error('Error fetching KEV CVEs:', error));
    }

    function renderKevTable(cves) {
        const tbody = document.getElementById('kev-table-body');
        const emptyState = document.getElementById('kev-empty-state');
        tbody.innerHTML = '';
        if (!cves || cves.length === 0) {
            emptyState.classList.remove('d-none');
            return;
        }
        emptyState.classList.add('d-none');
        cves.forEach(cve => {
            const row = document.createElement('tr');
            row.dataset.cveId = cve.cve_id;
            row.innerHTML = `
                <td><span class="cve-id-link">${escapeHtml(cve.cve_id)}</span></td>
                <td>${escapeHtml(cve.vendor || 'N/A')}${cve.product ? ` <span class="text-muted">/ ${escapeHtml(cve.product)}</span>` : ''}</td>
                <td class="text-center"><span class="badge badge-${riskLevel(cve.risk_level).toUpperCase()}">${escapeHtml(cve.risk_level || 'N/A')}</span></td>
                <td class="text-center">${cve.risk_score !== null ? cve.risk_score.toFixed(2) : 'N/A'}</td>
                <td>${formatDate(cve.kev_date_added)}</td>
                <td>${formatDate(cve.kev_due_date)}</td>
                <td>${formatDate(cve.published_date)}</td>
                <td class="text-muted small">${escapeHtml(cve.risk_recommendation || 'N/A')}</td>
            `;
            tbody.appendChild(row);
        });
    }

    document.getElementById('kev-export-btn').addEventListener('click', () => {
        exportToCsv('kev-catalog.csv', lastKevResults, [
            { key: 'cve_id', label: 'CVE ID' },
            { key: 'vendor', label: 'Vendor' },
            { key: 'product', label: 'Product' },
            { key: 'risk_level', label: 'Severity' },
            { label: 'CVSS', value: (r) => r.cvss_score },
            { label: 'EPSS', value: (r) => r.epss_score },
            { key: 'kev_date_added', label: 'KEV Added' },
            { key: 'kev_due_date', label: 'Remediation Due' },
            { key: 'published_date', label: 'Published' },
            { key: 'risk_recommendation', label: 'Mitigation Guidance' },
        ]);
    });

    document.getElementById('kev-table-body').addEventListener('click', (e) => {
        const row = e.target.closest('tr');
        if (row && row.dataset.cveId) fetchAndShowCveDetails(row.dataset.cveId);
    });

    // --- Recently-published mini list (shared by Dashboard and Analytics) ---
    function renderRecentCves(containerId, items) {
        const container = document.getElementById(containerId);
        if (!container) return;
        if (!items || items.length === 0) {
            container.innerHTML = '<div class="text-center text-muted small py-4">No CVEs published yet.</div>';
            return;
        }
        container.innerHTML = recentCveRowsHtml(items);
        wireRecentCveRows(container);
    }

    // --- Analytics page ---
    function fetchAnalytics() {
        fetch(`${API_BASE}/analytics`)
            .then(response => response.json())
            .then(data => {
                renderTrendChart(data.monthly_trend || []);
                renderArticlesTrendChart(data.articles_trend || []);
                renderKevSplitChart(data.kev_vs_non_kev || { kev: 0, non_kev: 0 });
                renderVendorBarChart(data.vendor_bar || []);
                renderProductBarChart(data.product_bar || []);
                renderRecentCves('analytics-recent-cves', data.recent_cves);
                renderRecentCves('dashboard-recent-cves', (data.recent_cves || []).slice(0, 5));
            })
            .catch(error => console.error('Error fetching analytics:', error));
        renderSourceEffectivenessChart();
    }

    function renderArticlesTrendChart(articlesTrend) {
        const ctx = document.getElementById('articlesTrendChart').getContext('2d');
        const mutedText = cssVar('--text-muted');
        const gridColor = cssVar('--chart-grid');
        const low = cssVar('--low');

        if (articlesTrendChart) articlesTrendChart.destroy();
        articlesTrendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: articlesTrend.map(m => m.month),
                datasets: [{
                    data: articlesTrend.map(m => m.count),
                    borderColor: low,
                    backgroundColor: hexToRgba(low, 0.15),
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3,
                    pointBackgroundColor: low,
                    borderWidth: 2,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: mutedText }, grid: { display: false } },
                    y: { beginAtZero: true, ticks: { precision: 0, color: mutedText }, grid: { color: gridColor } },
                },
            },
        });
    }

    function renderSourceEffectivenessChart() {
        const canvas = document.getElementById('sourceEffectivenessChart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const rows = [...sourcesState.all].sort((a, b) => (b.cves_found || 0) - (a.cves_found || 0)).slice(0, 8);
        const accent = cssVar('--accent');

        if (sourceEffectivenessChart) sourceEffectivenessChart.destroy();
        sourceEffectivenessChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: rows.map(r => r.name || r.url),
                datasets: [{ data: rows.map(r => r.cves_found || 0), backgroundColor: accent, borderRadius: 4, borderSkipped: false, maxBarThickness: 20 }],
            },
            options: barChartOptions(cssVar('--text-muted'), cssVar('--chart-grid')),
        });
    }

    function renderTrendChart(monthlyTrend) {
        const ctx = document.getElementById('trendChart').getContext('2d');
        const mutedText = cssVar('--text-muted');
        const gridColor = cssVar('--chart-grid');
        const accent = cssVar('--accent');

        if (trendChart) trendChart.destroy();
        trendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: monthlyTrend.map(m => m.month),
                datasets: [{
                    data: monthlyTrend.map(m => m.count),
                    borderColor: accent,
                    backgroundColor: hexToRgba(accent, 0.15),
                    fill: true,
                    tension: 0.3,
                    pointRadius: 3,
                    pointBackgroundColor: accent,
                    borderWidth: 2,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: mutedText }, grid: { display: false } },
                    y: { beginAtZero: true, ticks: { precision: 0, color: mutedText }, grid: { color: gridColor } },
                },
            },
        });
    }

    function renderKevSplitChart(split) {
        const ctx = document.getElementById('kevSplitChart').getContext('2d');
        const critical = cssVar('--critical');
        const axisColor = cssVar('--chart-axis');
        document.getElementById('kev-split-kev').textContent = split.kev;
        document.getElementById('kev-split-non-kev').textContent = split.non_kev;

        if (kevSplitChart) kevSplitChart.destroy();
        kevSplitChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['KEV', 'Non-KEV'],
                datasets: [{ data: [split.kev, split.non_kev], backgroundColor: [critical, axisColor], borderWidth: 0 }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '68%',
                plugins: { legend: { display: false }, tooltip: { callbacks: { label: (item) => `${item.label}: ${item.raw}` } } },
            },
        });
    }

    function barChartOptions(mutedText, gridColor) {
        return {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: (item) => `${item.raw} CVE${item.raw === 1 ? '' : 's'}` } },
            },
            scales: {
                x: { beginAtZero: true, ticks: { precision: 0, color: mutedText }, grid: { color: gridColor } },
                y: { ticks: { color: mutedText }, grid: { display: false } },
            },
        };
    }

    function renderVendorBarChart(rows) {
        const ctx = document.getElementById('vendorBarChart').getContext('2d');
        const accent = cssVar('--accent');
        if (vendorBarChart) vendorBarChart.destroy();
        vendorBarChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: rows.map(r => r.vendor),
                datasets: [{ data: rows.map(r => r.count), backgroundColor: accent, borderRadius: 4, borderSkipped: false, maxBarThickness: 20 }],
            },
            options: barChartOptions(cssVar('--text-muted'), cssVar('--chart-grid')),
        });
    }

    function renderProductBarChart(rows) {
        const ctx = document.getElementById('productBarChart').getContext('2d');
        const accent = cssVar('--accent');
        if (productBarChart) productBarChart.destroy();
        productBarChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: rows.map(r => r.product),
                datasets: [{ data: rows.map(r => r.count), backgroundColor: accent, borderRadius: 4, borderSkipped: false, maxBarThickness: 20 }],
            },
            options: barChartOptions(cssVar('--text-muted'), cssVar('--chart-grid')),
        });
    }

    // --- Settings page ---
    function fetchSettings() {
        fetch(`${API_BASE}/settings`)
            .then(response => response.json())
            .then(data => {
                document.getElementById('setting-timeout').textContent = `${data.request_timeout_seconds}s`;
                document.getElementById('setting-retries').textContent = data.max_retries;
                document.getElementById('setting-backoff').textContent = data.backoff_factor;
                document.getElementById('setting-concurrency').textContent = data.concurrency;
                document.getElementById('setting-nvd-key').textContent = data.nvd_api_key_configured ? 'Yes' : 'No (using unauthenticated NVD rate limit)';
                document.getElementById('setting-nvd-delay').textContent = `${data.nvd_rate_limit_delay_seconds}s`;
                document.getElementById('setting-cache-ttl').textContent = `${data.cache_ttl_hours}h`;
                document.getElementById('setting-cache-folder').textContent = data.cache_folder;
                document.getElementById('setting-output-folder').textContent = data.output_folder;
                document.getElementById('setting-log-folder').textContent = data.log_folder;
            })
            .catch(error => console.error('Error fetching settings:', error));
    }

    document.getElementById('settings-theme-toggle').addEventListener('click', () => {
        document.getElementById('theme-toggle').click();
    });

    function setDynamicFooter() {
        const year = new Date().getFullYear();
        const footer = document.getElementById('copyright-year');
        if (footer) {
            footer.textContent = `Copyright © Vuln Intel ${year}. All rights reserved.`;
        }
    }

    function showAlert(element, message, type) {
        element.className = `alert alert-${type}`;
        element.textContent = message;
        element.style.display = 'block';
    }

    // --- CSV export (client-side; columns = [{key, label} | {value: fn, label}]) ---
    function exportToCsv(filename, rows, columns) {
        if (!rows || rows.length === 0) {
            showToast('Nothing to export.', 'info');
            return;
        }
        const escapeCsv = (value) => {
            const str = value === null || value === undefined ? '' : String(value);
            return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
        };
        const cell = (row, col) => (typeof col.value === 'function' ? col.value(row) : row[col.key]);
        const lines = [
            columns.map(c => escapeCsv(c.label)).join(','),
            ...rows.map(row => columns.map(c => escapeCsv(cell(row, c))).join(',')),
        ];
        const blob = new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast(`Exported ${rows.length} row${rows.length === 1 ? '' : 's'} to ${filename}.`, 'success');
    }

    // --- Toast notifications ---
    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        const icons = { success: 'bi-check-circle-fill', danger: 'bi-x-circle-fill', info: 'bi-info-circle-fill' };
        const toastEl = document.createElement('div');
        toastEl.className = `toast toast-${type}`;
        toastEl.setAttribute('role', 'status');
        toastEl.setAttribute('aria-live', 'polite');
        toastEl.setAttribute('aria-atomic', 'true');
        toastEl.innerHTML = `
            <div class="toast-header">
                <i class="bi ${icons[type] || icons.info} me-2"></i>
                <strong class="me-auto">${type === 'danger' ? 'Error' : type === 'success' ? 'Success' : 'Notice'}</strong>
                <button type="button" class="btn-close" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">${escapeHtml(message)}</div>
        `;
        container.appendChild(toastEl);
        const toast = new bootstrap.Toast(toastEl, { delay: 5000 });
        toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
        toast.show();
    }

    // --- Add / Edit source form ---
    function resetSourceForm() {
        document.getElementById('addSourceModalLabel').textContent = 'Add Security Source';
        document.getElementById('source-form-save-btn').textContent = 'Save';
        document.getElementById('source-form-id').value = '';
        document.getElementById('source-name-input').value = '';
        document.getElementById('source-vendor-input').value = '';
        document.getElementById('source-url-input').value = '';
        document.getElementById('source-type-input').value = 'security_blog';
        document.getElementById('source-interval-input').value = '';
        document.getElementById('source-enabled-input').checked = true;
        hideElement('test-connection-result');
        hideElement('source-form-alert');
    }

    function openSourceFormForEdit(sourceId) {
        const source = sourcesState.all.find(s => String(s.id) === String(sourceId));
        if (!source) return;
        document.getElementById('addSourceModalLabel').textContent = `Edit Source: ${source.name || source.url}`;
        document.getElementById('source-form-save-btn').textContent = 'Save Changes';
        document.getElementById('source-form-id').value = source.id;
        document.getElementById('source-name-input').value = source.name || '';
        document.getElementById('source-vendor-input').value = source.vendor || '';
        document.getElementById('source-url-input').value = source.url || '';
        document.getElementById('source-type-input').value = source.source_type || 'security_blog';
        document.getElementById('source-interval-input').value = source.polling_interval_minutes || '';
        document.getElementById('source-enabled-input').checked = !!source.enabled;
        hideElement('test-connection-result');
        hideElement('source-form-alert');
    }

    function hideElement(id) {
        const el = document.getElementById(id);
        el.classList.add('d-none');
        el.innerHTML = '';
    }

    document.getElementById('addSourceModal').addEventListener('show.bs.modal', (event) => {
        const trigger = event.relatedTarget;
        const sourceId = trigger && trigger.dataset ? trigger.dataset.sourceId : null;
        if (sourceId) {
            openSourceFormForEdit(sourceId);
        } else {
            resetSourceForm();
        }
    });

    function testSourceConnection() {
        const url = document.getElementById('source-url-input').value.trim();
        const sourceType = document.getElementById('source-type-input').value;
        const resultEl = document.getElementById('test-connection-result');
        const spinner = document.getElementById('test-connection-spinner');

        if (!url) {
            resultEl.className = 'alert alert-danger mt-3';
            resultEl.textContent = 'Enter a URL first.';
            resultEl.classList.remove('d-none');
            return;
        }

        spinner.classList.remove('d-none');
        resultEl.classList.add('d-none');
        document.getElementById('test-connection-btn').disabled = true;

        fetch(`${API_BASE}/sources/test`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, source_type: sourceType }),
        })
            .then(response => response.json())
            .then(result => {
                resultEl.className = `alert mt-3 ${result.ok ? 'alert-success' : 'alert-danger'}`;
                resultEl.innerHTML = `<strong>${escapeHtml(result.message || (result.ok ? 'Connection Successful' : 'Connection Failed'))}</strong>${result.detail ? `<div class="small mt-1">${escapeHtml(result.detail)}</div>` : ''}`;
                resultEl.classList.remove('d-none');
            })
            .catch(error => {
                resultEl.className = 'alert alert-danger mt-3';
                resultEl.textContent = `A network error occurred: ${error}`;
                resultEl.classList.remove('d-none');
            })
            .finally(() => {
                spinner.classList.add('d-none');
                document.getElementById('test-connection-btn').disabled = false;
            });
    }

    document.getElementById('test-connection-btn').addEventListener('click', testSourceConnection);

    function saveSource() {
        const alertEl = document.getElementById('source-form-alert');
        const sourceId = document.getElementById('source-form-id').value;
        const url = document.getElementById('source-url-input').value.trim();
        if (!url) {
            showAlert(alertEl, 'Please enter a source URL.', 'danger');
            return;
        }

        const payload = {
            name: document.getElementById('source-name-input').value.trim(),
            vendor: document.getElementById('source-vendor-input').value.trim(),
            url,
            source_type: document.getElementById('source-type-input').value,
            polling_interval_minutes: document.getElementById('source-interval-input').value || null,
            enabled: document.getElementById('source-enabled-input').checked,
        };

        const saveBtn = document.getElementById('source-form-save-btn');
        saveBtn.disabled = true;

        const request = sourceId
            ? fetch(`${API_BASE}/sources/${sourceId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            })
            : fetch(`${API_BASE}/sources`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

        request
            .then(response => response.json().then(data => ({ status: response.status, body: data })))
            .then(({ status, body }) => {
                if (status === 200 || status === 201) {
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addSourceModal'));
                    if (modal) modal.hide();
                    showToast(sourceId ? 'Source updated.' : 'Source added; scanning in the background.', 'success');
                    fetchSources();
                    fetchSourceTypes();
                    if (!sourceId) startStatusPolling();
                } else {
                    showAlert(alertEl, body.error || 'Could not save source.', 'danger');
                }
            })
            .catch(error => {
                console.error('Error saving source:', error);
                showAlert(alertEl, 'A network error occurred.', 'danger');
            })
            .finally(() => {
                saveBtn.disabled = false;
            });
    }

    document.getElementById('source-form-save-btn').addEventListener('click', saveSource);

    // --- View source ---
    function viewSource(sourceId) {
        const source = sourcesState.all.find(s => String(s.id) === String(sourceId));
        if (!source) return;
        document.getElementById('viewSourceModalLabel').textContent = source.name || source.url;
        const typeLabel = SOURCE_TYPE_LABELS[source.source_type] || source.source_type;
        document.getElementById('view-source-body').innerHTML = `
            <dl class="detail-kv">
                <dt>Name</dt><dd>${escapeHtml(source.name || 'Not set')}</dd>
                <dt>URL</dt><dd><a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.url)}</a></dd>
                <dt>Type</dt><dd>${escapeHtml(typeLabel)}</dd>
                <dt>Vendor</dt><dd>${escapeHtml(source.vendor || 'Not set')}</dd>
                <dt>Enabled</dt><dd>${source.enabled ? 'Yes' : 'No'}</dd>
                <dt>Polling Interval</dt><dd>${source.polling_interval_minutes ? `Every ${source.polling_interval_minutes} minute(s)` : 'Manual scans only'}</dd>
                <dt>Status</dt><dd><span class="source-status-pill status-${(source.status || 'pending').toLowerCase()}">${escapeHtml(source.status || 'Pending')}</span></dd>
                <dt>Last Scan</dt><dd>${source.last_checked ? new Date(source.last_checked).toLocaleString() : 'Never'}</dd>
                <dt>Articles (last scan)</dt><dd>${source.last_articles_processed ?? 'N/A'}</dd>
                <dt>CVEs Found</dt><dd>${source.cves_found ?? 'N/A'}</dd>
                <dt>Last Error</dt><dd>${source.last_error ? escapeHtml(source.last_error) : 'None'}</dd>
                <dt>Added</dt><dd>${source.created_at ? new Date(source.created_at).toLocaleString() : 'N/A'}</dd>
            </dl>
        `;
        bootstrap.Modal.getOrCreateInstance(document.getElementById('viewSourceModal')).show();
    }

    // --- Scan history ---
    function showSourceHistory(sourceId) {
        const source = sourcesState.all.find(s => String(s.id) === String(sourceId));
        document.getElementById('sourceHistoryModalLabel').textContent = `Scan History: ${source ? (source.name || source.url) : sourceId}`;
        const tbody = document.getElementById('source-history-table-body');
        const emptyState = document.getElementById('source-history-empty');
        tbody.innerHTML = '<tr><td colspan="6" class="text-center p-4"><div class="spinner-border spinner-border-sm text-accent" role="status"></div></td></tr>';
        emptyState.classList.add('d-none');
        bootstrap.Modal.getOrCreateInstance(document.getElementById('sourceHistoryModal')).show();

        fetch(`${API_BASE}/sources/${sourceId}/history`)
            .then(response => response.json())
            .then(history => {
                if (!Array.isArray(history) || history.length === 0) {
                    tbody.innerHTML = '';
                    emptyState.classList.remove('d-none');
                    return;
                }
                tbody.innerHTML = history.map(scan => `
                    <tr>
                        <td>${scan.scan_time ? new Date(scan.scan_time).toLocaleString() : 'N/A'}</td>
                        <td class="text-center"><span class="source-status-pill status-${(scan.status || '').toLowerCase()}">${escapeHtml(scan.status || 'Unknown')}</span></td>
                        <td class="text-center">${scan.duration_seconds !== null && scan.duration_seconds !== undefined ? `${scan.duration_seconds.toFixed(2)}s` : 'N/A'}</td>
                        <td class="text-center">${scan.articles_processed ?? 0}</td>
                        <td class="text-center">${scan.cves_found ?? 0}</td>
                        <td>${scan.error_message ? escapeHtml(scan.error_message) : '&mdash;'}</td>
                    </tr>
                `).join('');
            })
            .catch(error => {
                console.error('Error loading scan history:', error);
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger py-3">Failed to load scan history.</td></tr>';
            });
    }

    // --- Run scan / enable / disable / delete ---
    function runSourceScan(sourceId) {
        fetch(`${API_BASE}/sources/${sourceId}/scan`, { method: 'POST' })
            .then(response => response.json().then(data => ({ status: response.status, body: data })))
            .then(({ status, body }) => {
                if (status === 202) {
                    showToast('Scan started.', 'success');
                    startStatusPolling();
                } else {
                    showToast(body.error || 'Could not start scan.', 'danger');
                }
            })
            .catch(error => {
                console.error('Error starting scan:', error);
                showToast('A network error occurred.', 'danger');
            });
    }

    function toggleSourceEnabled(sourceId, currentlyEnabled) {
        const endpoint = currentlyEnabled ? 'disable' : 'enable';
        fetch(`${API_BASE}/sources/${sourceId}/${endpoint}`, { method: 'POST' })
            .then(response => response.json().then(data => ({ status: response.status, body: data })))
            .then(({ status, body }) => {
                if (status === 200) {
                    showToast(currentlyEnabled ? 'Source disabled.' : 'Source enabled.', 'success');
                    fetchSources();
                } else {
                    showToast(body.error || 'Could not update source.', 'danger');
                }
            })
            .catch(error => {
                console.error('Error toggling source:', error);
                showToast('A network error occurred.', 'danger');
            });
    }

    let pendingDeleteSourceId = null;

    function openDeleteSourceModal(sourceId) {
        const source = sourcesState.all.find(s => String(s.id) === String(sourceId));
        pendingDeleteSourceId = sourceId;
        document.getElementById('delete-source-name').textContent = source ? (source.name || source.url) : 'this source';
        bootstrap.Modal.getOrCreateInstance(document.getElementById('deleteSourceModal')).show();
    }

    document.getElementById('confirm-delete-source-btn').addEventListener('click', () => {
        if (!pendingDeleteSourceId) return;
        fetch(`${API_BASE}/sources/${pendingDeleteSourceId}`, { method: 'DELETE' })
            .then(response => {
                const modal = bootstrap.Modal.getInstance(document.getElementById('deleteSourceModal'));
                if (modal) modal.hide();
                if (response.ok) {
                    showToast('Source deleted.', 'success');
                    fetchSources();
                } else {
                    showToast('Failed to delete source.', 'danger');
                }
            })
            .catch(error => {
                console.error('Error deleting source:', error);
                showToast('A network error occurred.', 'danger');
            })
            .finally(() => {
                pendingDeleteSourceId = null;
            });
    });

    // --- Sources table: search / type filter / sort / pagination / row actions ---
    let sourcesSearchTimeout;
    document.getElementById('sources-search').addEventListener('keyup', () => {
        clearTimeout(sourcesSearchTimeout);
        sourcesSearchTimeout = setTimeout(() => {
            sourcesState.q = document.getElementById('sources-search').value.trim();
            sourcesState.page = 1;
            renderSourcesTable();
        }, 300);
    });

    document.getElementById('sources-type-filter').addEventListener('change', (e) => {
        sourcesState.type = e.target.value;
        sourcesState.page = 1;
        renderSourcesTable();
    });

    document.getElementById('sourcesTable').querySelector('thead').addEventListener('click', (e) => {
        const th = e.target.closest('th');
        if (!th || !th.dataset.sort) return;
        const field = th.dataset.sort;
        if (sourcesState.sortBy === field) {
            sourcesState.sortDir = sourcesState.sortDir === 'asc' ? 'desc' : 'asc';
        } else {
            sourcesState.sortBy = field;
            sourcesState.sortDir = 'asc';
        }
        document.querySelectorAll('#sourcesTable thead th').forEach(header => {
            header.classList.remove('sort-asc', 'sort-desc');
            const icon = header.querySelector('.sort-icon');
            if (icon) icon.innerHTML = '&#x2195;';
        });
        th.classList.add(sourcesState.sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
        const icon = th.querySelector('.sort-icon');
        if (icon) icon.innerHTML = sourcesState.sortDir === 'asc' ? '&#x2191;' : '&#x2193;';
        renderSourcesTable();
    });

    document.getElementById('sources-pagination').addEventListener('click', (e) => {
        if (e.target.tagName === 'A' && e.target.dataset.page) {
            e.preventDefault();
            sourcesState.page = parseInt(e.target.dataset.page, 10);
            renderSourcesTable();
        }
    });

    document.getElementById('sources-export-btn').addEventListener('click', () => {
        exportToCsv('security-sources.csv', lastFilteredSources, [
            { key: 'name', label: 'Name' },
            { key: 'url', label: 'URL' },
            { key: 'source_type', label: 'Type' },
            { key: 'vendor', label: 'Vendor' },
            { key: 'enabled', label: 'Enabled' },
            { key: 'status', label: 'Status' },
            { key: 'last_checked', label: 'Last Scan' },
            { key: 'last_articles_processed', label: 'Articles' },
            { key: 'cves_found', label: 'CVEs Found' },
            { key: 'last_error', label: 'Last Error' },
        ]);
    });

    document.getElementById('sources-table-body').addEventListener('click', handleSourceAction);
    document.getElementById('sources-card-view').addEventListener('click', handleSourceAction);

    // --- Scan History page ---
    let lastScanHistory = [];

    function populateScanHistorySourceFilter() {
        const select = document.getElementById('scan-history-source-filter');
        const current = select.value;
        // Rebuild is cheap and keeps the list in sync as sources are added/removed.
        select.innerHTML = '<option value="">All Sources</option>';
        sourcesState.all.forEach(source => {
            const opt = document.createElement('option');
            opt.value = source.id;
            opt.textContent = source.name || source.url;
            select.appendChild(opt);
        });
        select.value = current;
    }

    function fetchScanHistory() {
        const sourceId = document.getElementById('scan-history-source-filter').value;
        const params = new URLSearchParams();
        if (sourceId) params.set('source_id', sourceId);

        fetch(`${API_BASE}/scan-history?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                lastScanHistory = data || [];
                renderScanHistoryTable(lastScanHistory);
                const el = document.getElementById('scan-history-summary-line');
                if (el) el.textContent = `${lastScanHistory.length} scan${lastScanHistory.length === 1 ? '' : 's'} recorded${sourceId ? ' for this source' : ' across every source'}.`;
            })
            .catch(error => console.error('Error fetching scan history:', error));
    }

    function renderScanHistoryTable(history) {
        const tbody = document.getElementById('scan-history-table-body');
        const emptyState = document.getElementById('scan-history-empty-state');
        tbody.innerHTML = '';
        if (!history || history.length === 0) {
            emptyState.classList.remove('d-none');
            return;
        }
        emptyState.classList.add('d-none');
        history.forEach(scan => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${escapeHtml(scan.source_name || 'Deleted source')}</strong></td>
                <td>${scan.scan_time ? new Date(scan.scan_time).toLocaleString() : 'N/A'}</td>
                <td class="text-center"><span class="source-status-pill status-${(scan.status || '').toLowerCase()}">${escapeHtml(scan.status || 'Unknown')}</span></td>
                <td class="text-center">${scan.duration_seconds !== null && scan.duration_seconds !== undefined ? `${scan.duration_seconds.toFixed(2)}s` : 'N/A'}</td>
                <td class="text-center">${scan.articles_processed ?? 0}</td>
                <td class="text-center">${scan.cves_found ?? 0}</td>
                <td>${scan.error_message ? `<span class="truncate-cell text-danger" title="${escapeHtml(scan.error_message)}">${escapeHtml(scan.error_message)}</span>` : '&mdash;'}</td>
            `;
            tbody.appendChild(row);
        });
    }

    document.getElementById('scan-history-source-filter').addEventListener('change', fetchScanHistory);

    document.getElementById('scan-history-export-btn').addEventListener('click', () => {
        exportToCsv('scan-history.csv', lastScanHistory, [
            { key: 'source_name', label: 'Source' },
            { key: 'scan_time', label: 'Scan Time' },
            { key: 'status', label: 'Status' },
            { key: 'duration_seconds', label: 'Duration (s)' },
            { key: 'articles_processed', label: 'Articles' },
            { key: 'cves_found', label: 'CVEs Found' },
            { key: 'error_message', label: 'Error' },
        ]);
    });

    // --- Articles page ---
    const articlesState = { page: 1, pageSize: 25, sortBy: 'fetched_at', sortDir: 'desc', q: '' };
    let currentArticlesPage = [];

    function fetchArticles() {
        const params = new URLSearchParams({
            page: articlesState.page,
            page_size: articlesState.pageSize,
            sort_by: articlesState.sortBy,
            sort_dir: articlesState.sortDir,
            q: articlesState.q,
        });
        fetch(`${API_BASE}/articles?${params.toString()}`)
            .then(response => response.json())
            .then(data => {
                currentArticlesPage = data.items || [];
                renderArticlesTable(currentArticlesPage);
                renderArticlesCards(currentArticlesPage);
                renderGenericPagination('articles-pagination', data.total, data.page, data.page_size, (page) => {
                    articlesState.page = page;
                    fetchArticles();
                });
                const el = document.getElementById('articles-summary-line');
                if (el) el.textContent = `${data.total} article${data.total === 1 ? '' : 's'} collected from your security sources.`;
            })
            .catch(error => console.error('Error fetching articles:', error));
    }

    function severityBadgeOrDash(level) {
        return level ? `<span class="badge badge-${level.toUpperCase()}">${escapeHtml(level)}</span>` : '<span class="text-muted">&mdash;</span>';
    }

    function renderArticlesTable(articles) {
        const tbody = document.getElementById('articles-table-body');
        const emptyState = document.getElementById('articles-empty-state');
        tbody.innerHTML = '';
        if (articles.length === 0) {
            emptyState.classList.remove('d-none');
            return;
        }
        emptyState.classList.add('d-none');
        articles.forEach(article => {
            const row = document.createElement('tr');
            row.dataset.articleId = article.id;
            const cveCount = (article.cves || []).length;
            row.innerHTML = `
                <td><a href="${escapeHtml(article.url)}" target="_blank" rel="noopener noreferrer" class="article-title-link">${escapeHtml(article.title || article.url)}</a></td>
                <td class="text-muted">${escapeHtml(article.source_name || article.site_name || 'N/A')}</td>
                <td>${formatDate(article.published_date)}</td>
                <td>${formatDate(article.fetched_at)}</td>
                <td class="text-center">${cveCount > 0 ? `<span class="badge bg-secondary">${cveCount}</span>` : '<span class="text-muted">0</span>'}</td>
                <td class="text-center">${severityBadgeOrDash(article.highest_severity)}</td>
            `;
            tbody.appendChild(row);
        });
    }

    function renderArticlesCards(articles) {
        const container = document.getElementById('articles-card-view');
        container.innerHTML = '';
        articles.forEach(article => {
            const cveCount = (article.cves || []).length;
            const card = document.createElement('div');
            card.className = 'entity-card is-clickable';
            card.dataset.articleId = article.id;
            card.innerHTML = `
                <div class="entity-card-head">
                    <span class="avatar-circle" style="background: ${avatarColor(article.source_name || article.site_name || article.title)};"><i class="bi bi-newspaper"></i></span>
                    <div>
                        <div class="entity-card-title">
                            <a href="${escapeHtml(article.url)}" target="_blank" rel="noopener noreferrer" class="text-reset text-decoration-none article-title-link">${escapeHtml(article.title || article.url)}</a>
                        </div>
                        <div class="entity-card-subtitle">${escapeHtml(article.source_name || article.site_name || 'Unknown source')}</div>
                    </div>
                </div>
                <div class="entity-card-metrics">
                    ${cveCount > 0 ? `<span class="metric-chip chip-accent"><i class="bi bi-bug-fill"></i> ${cveCount} CVE${cveCount === 1 ? '' : 's'}</span>` : '<span class="metric-chip">No CVEs found</span>'}
                    ${article.highest_severity ? `<span class="badge badge-${article.highest_severity.toUpperCase()}">${escapeHtml(article.highest_severity)}</span>` : ''}
                </div>
                <div class="article-card-foot">
                    <span>Published ${formatDate(article.published_date)}</span>
                    <span>Scanned ${formatDate(article.fetched_at)}</span>
                </div>
            `;
            container.appendChild(card);
        });
    }

    function openArticleDetailFromEvent(e, containerSelector) {
        // The title is a real outbound link; let it navigate on its own
        // rather than also opening the detail modal underneath it.
        if (e.target.closest('.article-title-link')) return;
        const el = e.target.closest(containerSelector);
        if (!el || !el.dataset.articleId) return;
        const article = currentArticlesPage.find(a => String(a.id) === el.dataset.articleId);
        if (article) showArticleDetail(article);
    }

    document.getElementById('articles-table-body').addEventListener('click', (e) => openArticleDetailFromEvent(e, 'tr'));
    document.getElementById('articles-card-view').addEventListener('click', (e) => openArticleDetailFromEvent(e, '.entity-card'));

    function showArticleDetail(article) {
        document.getElementById('articleDetailModalLabel').textContent = article.title || article.url;
        const body = document.getElementById('article-detail-body');
        const cveIds = article.cves || [];
        body.innerHTML = `
            <div class="detail-section">
                <p class="text-muted small mb-2">
                    <i class="bi bi-globe"></i> ${escapeHtml(article.source_name || article.site_name || 'Unknown source')}
                    &nbsp;&middot;&nbsp; Published ${formatDate(article.published_date)}
                    &nbsp;&middot;&nbsp; Scanned ${formatDate(article.fetched_at)}
                </p>
                <a href="${escapeHtml(article.url)}" target="_blank" rel="noopener noreferrer" class="btn btn-outline-secondary btn-sm">
                    <i class="bi bi-box-arrow-up-right"></i> Open Original Article
                </a>
            </div>
            <div class="detail-section">
                <h6>Extracted CVEs (${cveIds.length})</h6>
                <div id="article-cve-list" class="related-cve-list">
                    ${cveIds.length ? '<span class="text-muted small">Loading&hellip;</span>' : '<span class="text-muted small">No CVE IDs were detected in this article.</span>'}
                </div>
            </div>
        `;
        bootstrap.Modal.getOrCreateInstance(document.getElementById('articleDetailModal')).show();

        if (cveIds.length) {
            Promise.all(cveIds.map(id => fetch(`${API_BASE}/cve/${encodeURIComponent(id)}`).then(r => (r.ok ? r.json() : null))))
                .then(results => {
                    const container = document.getElementById('article-cve-list');
                    if (!container) return;
                    const valid = results.filter(Boolean);
                    container.innerHTML = valid.length
                        ? valid.map(cve => `
                            <a href="#" class="related-cve-link" data-cve-id="${escapeHtml(cve.cve_id)}">
                                <span class="cve-id-link">${escapeHtml(cve.cve_id)}</span>
                                <span>
                                    ${escapeHtml(cve.vendor || '')} ${escapeHtml(cve.product || '')}
                                    <span class="badge badge-${riskLevel(cve.risk_level).toUpperCase()} ms-1">${escapeHtml(cve.risk_level || 'N/A')}</span>
                                </span>
                            </a>
                        `).join('')
                        : '<span class="text-muted small">CVE details unavailable.</span>';
                })
                .catch(error => console.error('Error loading article CVE details:', error));
        }
    }

    document.getElementById('article-detail-body').addEventListener('click', (e) => {
        const link = e.target.closest('.related-cve-link');
        if (link) {
            e.preventDefault();
            bootstrap.Modal.getInstance(document.getElementById('articleDetailModal'))?.hide();
            fetchAndShowCveDetails(link.dataset.cveId);
        }
    });

    document.getElementById('articles-export-btn').addEventListener('click', () => {
        exportToCsv('security-intelligence.csv', currentArticlesPage, [
            { key: 'title', label: 'Title' },
            { label: 'Source', value: (a) => a.source_name || a.site_name },
            { key: 'published_date', label: 'Published' },
            { key: 'fetched_at', label: 'Fetched' },
            { label: 'CVE Count', value: (a) => (a.cves || []).length },
            { key: 'highest_severity', label: 'Highest Severity' },
            { key: 'url', label: 'URL' },
        ]);
    });

    function renderGenericPagination(elementId, total, page, pageSize, onPageClick) {
        const pagination = document.getElementById(elementId);
        pagination.innerHTML = '';
        const totalPages = Math.ceil(total / pageSize);
        if (totalPages <= 1) return;

        const createPageItem = (text, pageNum, isDisabled = false, isActive = false) => {
            const li = document.createElement('li');
            li.className = `page-item ${isDisabled ? 'disabled' : ''} ${isActive ? 'active' : ''}`;
            const a = document.createElement('a');
            a.className = 'page-link';
            a.href = '#';
            a.textContent = text;
            if (!isDisabled) {
                a.addEventListener('click', (e) => {
                    e.preventDefault();
                    onPageClick(pageNum);
                });
            }
            li.appendChild(a);
            return li;
        };

        pagination.appendChild(createPageItem('Previous', page - 1, page === 1));
        for (let i = 1; i <= totalPages; i++) {
            if (i === 1 || i === totalPages || (i >= page - 2 && i <= page + 2)) {
                pagination.appendChild(createPageItem(i, i, false, i === page));
            } else if (i === page - 3 || i === page + 3) {
                pagination.appendChild(createPageItem('...', 0, true));
            }
        }
        pagination.appendChild(createPageItem('Next', page + 1, page === totalPages));
    }

    function wireSortableHeaders(tableId, getState, onChange) {
        document.getElementById(tableId).querySelector('thead').addEventListener('click', (e) => {
            const th = e.target.closest('th');
            if (!th || !th.dataset.sort) return;
            const s = getState();
            const field = th.dataset.sort;
            if (s.sortBy === field) {
                s.sortDir = s.sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                s.sortBy = field;
                s.sortDir = 'asc';
            }
            document.querySelectorAll(`#${tableId} thead th`).forEach(header => {
                header.classList.remove('sort-asc', 'sort-desc');
                const icon = header.querySelector('.sort-icon');
                if (icon) icon.innerHTML = '&#x2195;';
            });
            th.classList.add(s.sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
            const icon = th.querySelector('.sort-icon');
            if (icon) icon.innerHTML = s.sortDir === 'asc' ? '&#x2191;' : '&#x2193;';
            onChange();
        });
    }

    wireSortableHeaders('articlesTable', () => articlesState, () => { articlesState.page = 1; fetchArticles(); });

    let articlesSearchTimeout;
    document.getElementById('articles-search').addEventListener('keyup', () => {
        clearTimeout(articlesSearchTimeout);
        articlesSearchTimeout = setTimeout(() => {
            articlesState.q = document.getElementById('articles-search').value.trim();
            articlesState.page = 1;
            fetchArticles();
        }, 300);
    });

    // --- Vendors / Products pages ---
    const vendorsState = { all: [], q: '', sortBy: 'cve_count', sortDir: 'desc' };
    const productsState = { all: [], q: '', sortBy: 'cve_count', sortDir: 'desc' };

    function fetchVendors() {
        fetch(`${API_BASE}/vendors`)
            .then(response => response.json())
            .then(data => {
                vendorsState.all = data.items || [];
                renderVendorsTable();
                const el = document.getElementById('vendors-summary-line');
                if (el) {
                    const totalCves = vendorsState.all.reduce((sum, v) => sum + v.cve_count, 0);
                    el.textContent = `${vendorsState.all.length} vendor${vendorsState.all.length === 1 ? '' : 's'} across ${totalCves} tracked CVEs.`;
                }
            })
            .catch(error => console.error('Error fetching vendors:', error));
    }

    function fetchProducts() {
        fetch(`${API_BASE}/products`)
            .then(response => response.json())
            .then(data => {
                productsState.all = data.items || [];
                renderProductsTable();
                const el = document.getElementById('products-summary-line');
                if (el) {
                    const totalCves = productsState.all.reduce((sum, p) => sum + p.cve_count, 0);
                    el.textContent = `${productsState.all.length} product${productsState.all.length === 1 ? '' : 's'} across ${totalCves} tracked CVEs.`;
                }
            })
            .catch(error => console.error('Error fetching products:', error));
    }

    function sortRows(rows, sortBy, sortDir) {
        const dir = sortDir === 'asc' ? 1 : -1;
        return [...rows].sort((a, b) => {
            let av = a[sortBy];
            let bv = b[sortBy];
            if (typeof av === 'string') av = av.toLowerCase();
            if (typeof bv === 'string') bv = bv.toLowerCase();
            if (av < bv) return -1 * dir;
            if (av > bv) return 1 * dir;
            return 0;
        });
    }

    let lastFilteredVendors = [];

    function renderVendorsTable() {
        const tbody = document.getElementById('vendors-table-body');
        const cardContainer = document.getElementById('vendors-card-view');
        const emptyState = document.getElementById('vendors-empty-state');
        let rows = vendorsState.all;
        if (vendorsState.q) {
            const q = vendorsState.q.toLowerCase();
            rows = rows.filter(v => v.vendor.toLowerCase().includes(q));
        }
        rows = sortRows(rows, vendorsState.sortBy, vendorsState.sortDir);
        lastFilteredVendors = rows;

        tbody.innerHTML = '';
        cardContainer.innerHTML = '';
        if (vendorsState.all.length === 0) {
            emptyState.classList.remove('d-none');
            return;
        }
        emptyState.classList.add('d-none');
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No vendors match your search.</td></tr>';
            cardContainer.innerHTML = '<p class="text-muted text-center py-4">No vendors match your search.</p>';
            return;
        }
        rows.forEach(v => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${escapeHtml(v.vendor)}</strong></td>
                <td class="text-center">${v.product_count}</td>
                <td class="text-center">${v.cve_count}</td>
                <td class="text-center">${v.kev_count > 0 ? `<span class="badge bg-danger">${v.kev_count}</span>` : '0'}</td>
                <td class="text-center">${v.critical_count}</td>
                <td class="text-center">${v.high_count}</td>
            `;
            row.addEventListener('click', () => showVendorDetail(v.vendor));
            tbody.appendChild(row);

            const card = document.createElement('div');
            card.className = 'entity-card is-clickable';
            card.innerHTML = `
                <div class="entity-card-head">
                    <span class="avatar-circle" style="background: ${avatarColor(v.vendor)};">${escapeHtml(avatarInitial(v.vendor))}</span>
                    <div>
                        <div class="entity-card-title">${escapeHtml(v.vendor)}</div>
                        <div class="entity-card-subtitle">${v.product_count} product${v.product_count === 1 ? '' : 's'}</div>
                    </div>
                </div>
                <div class="entity-card-metrics">
                    <span class="metric-chip chip-accent">${v.cve_count} CVE${v.cve_count === 1 ? '' : 's'}</span>
                    ${v.kev_count > 0 ? `<span class="metric-chip chip-kev"><i class="bi bi-bullseye"></i> ${v.kev_count} KEV</span>` : ''}
                    ${v.critical_count > 0 ? `<span class="metric-chip chip-critical">${v.critical_count} Critical</span>` : ''}
                    ${v.high_count > 0 ? `<span class="metric-chip chip-high">${v.high_count} High</span>` : ''}
                </div>
            `;
            card.addEventListener('click', () => showVendorDetail(v.vendor));
            cardContainer.appendChild(card);
        });
    }

    let lastFilteredProducts = [];

    function renderProductsTable() {
        const tbody = document.getElementById('products-table-body');
        const cardContainer = document.getElementById('products-card-view');
        const emptyState = document.getElementById('products-empty-state');
        let rows = productsState.all;
        if (productsState.q) {
            const q = productsState.q.toLowerCase();
            rows = rows.filter(p => p.product.toLowerCase().includes(q) || (p.vendor || '').toLowerCase().includes(q));
        }
        rows = sortRows(rows, productsState.sortBy, productsState.sortDir);
        lastFilteredProducts = rows;

        tbody.innerHTML = '';
        cardContainer.innerHTML = '';
        if (productsState.all.length === 0) {
            emptyState.classList.remove('d-none');
            return;
        }
        emptyState.classList.add('d-none');
        if (rows.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No products match your search.</td></tr>';
            cardContainer.innerHTML = '<p class="text-muted text-center py-4">No products match your search.</p>';
            return;
        }
        rows.forEach(p => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><strong>${escapeHtml(p.product)}</strong></td>
                <td class="text-muted">${escapeHtml(p.vendor || 'N/A')}</td>
                <td class="text-center">${p.cve_count}</td>
                <td class="text-center">${p.kev_count > 0 ? `<span class="badge bg-danger">${p.kev_count}</span>` : '0'}</td>
                <td class="text-center">${p.critical_count}</td>
                <td class="text-center">${p.high_count}</td>
            `;
            row.addEventListener('click', () => showProductDetail(p.vendor, p.product));
            tbody.appendChild(row);

            const card = document.createElement('div');
            card.className = 'entity-card is-clickable';
            card.innerHTML = `
                <div class="entity-card-head">
                    <span class="avatar-circle" style="background: ${avatarColor(p.product)};"><i class="bi bi-box-seam-fill"></i></span>
                    <div>
                        <div class="entity-card-title">${escapeHtml(p.product)}</div>
                        <div class="entity-card-subtitle">${escapeHtml(p.vendor || 'Unknown vendor')}</div>
                    </div>
                </div>
                <div class="entity-card-metrics">
                    <span class="metric-chip chip-accent">${p.cve_count} CVE${p.cve_count === 1 ? '' : 's'}</span>
                    ${p.kev_count > 0 ? `<span class="metric-chip chip-kev"><i class="bi bi-bullseye"></i> ${p.kev_count} KEV</span>` : ''}
                    ${p.critical_count > 0 ? `<span class="metric-chip chip-critical">${p.critical_count} Critical</span>` : ''}
                    ${p.high_count > 0 ? `<span class="metric-chip chip-high">${p.high_count} High</span>` : ''}
                </div>
            `;
            card.addEventListener('click', () => showProductDetail(p.vendor, p.product));
            cardContainer.appendChild(card);
        });
    }

    wireSortableHeaders('vendorsTable', () => vendorsState, renderVendorsTable);
    wireSortableHeaders('productsTable', () => productsState, renderProductsTable);

    let vendorsSearchTimeout;
    document.getElementById('vendors-search').addEventListener('keyup', () => {
        clearTimeout(vendorsSearchTimeout);
        vendorsSearchTimeout = setTimeout(() => {
            vendorsState.q = document.getElementById('vendors-search').value.trim();
            renderVendorsTable();
        }, 300);
    });

    let productsSearchTimeout;
    document.getElementById('products-search').addEventListener('keyup', () => {
        clearTimeout(productsSearchTimeout);
        productsSearchTimeout = setTimeout(() => {
            productsState.q = document.getElementById('products-search').value.trim();
            renderProductsTable();
        }, 300);
    });

    document.getElementById('vendors-export-btn').addEventListener('click', () => {
        exportToCsv('vendors.csv', lastFilteredVendors, [
            { key: 'vendor', label: 'Vendor' },
            { key: 'product_count', label: 'Products' },
            { key: 'cve_count', label: 'CVEs' },
            { key: 'kev_count', label: 'KEV' },
            { key: 'critical_count', label: 'Critical' },
            { key: 'high_count', label: 'High' },
        ]);
    });

    document.getElementById('products-export-btn').addEventListener('click', () => {
        exportToCsv('products.csv', lastFilteredProducts, [
            { key: 'product', label: 'Product' },
            { key: 'vendor', label: 'Vendor' },
            { key: 'cve_count', label: 'CVEs' },
            { key: 'kev_count', label: 'KEV' },
            { key: 'critical_count', label: 'Critical' },
            { key: 'high_count', label: 'High' },
        ]);
    });

    // --- Vulnerability checker ---
    const STATUS_LABELS = { vulnerable: 'Vulnerable', not_affected: 'Not Affected', unknown: 'Unknown' };
    const STATUS_ICONS = {
        vulnerable: 'bi-exclamation-octagon-fill',
        not_affected: 'bi-check-circle-fill',
        unknown: 'bi-question-circle-fill',
    };

    function runVulnerabilityCheck() {
        const vendor = document.getElementById('checker-vendor').value.trim();
        const product = document.getElementById('checker-product').value.trim();
        const version = document.getElementById('checker-version').value.trim();
        if (!product) return;

        const submitBtn = document.getElementById('checker-submit-btn');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Checking...';

        const params = new URLSearchParams({ product });
        if (vendor) params.set('vendor', vendor);
        if (version) params.set('version', version);

        fetch(`${API_BASE}/check?${params.toString()}`)
            .then(response => response.json())
            .then(data => renderCheckerResults(data))
            .catch(error => console.error('Error checking vulnerability:', error))
            .finally(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="bi bi-search"></i> Check';
            });
    }

    function renderCheckerResults(data) {
        const resultsWrap = document.getElementById('checker-results-wrap');
        const emptyState = document.getElementById('checker-empty-state');
        const summary = document.getElementById('checker-summary');
        const tbody = document.getElementById('checker-table-body');

        if (!data.results || data.total === 0) {
            resultsWrap.classList.add('d-none');
            emptyState.classList.remove('d-none');
            return;
        }

        emptyState.classList.add('d-none');
        resultsWrap.classList.remove('d-none');

        const productLabel = escapeHtml(data.query.product);
        if (data.query.version) {
            const vulnerable = data.vulnerable_count;
            summary.className = `app-summary-banner ${vulnerable > 0 ? 'has-vulnerable' : 'no-vulnerable'}`;
            summary.innerHTML = vulnerable > 0
                ? `<strong>${vulnerable}</strong> of ${data.total} known CVEs for <strong>${productLabel}</strong> affect version <strong>${escapeHtml(data.query.version)}</strong>.`
                : `None of the ${data.total} known CVEs for <strong>${productLabel}</strong> are confirmed to affect version <strong>${escapeHtml(data.query.version)}</strong>, based on the affected-version ranges collected so far.`;
        } else {
            summary.className = 'app-summary-banner';
            summary.innerHTML = `Found <strong>${data.total}</strong> known CVEs for <strong>${productLabel}</strong> across all versions. Add a version above for a per-CVE verdict.`;
        }

        tbody.innerHTML = '';
        data.results.forEach(item => {
            const cve = item.cve;
            const row = document.createElement('tr');
            row.setAttribute('data-bs-toggle', 'modal');
            row.setAttribute('data-bs-target', '#cveDetailModal');
            row.dataset.cveId = cve.cve_id;
            row.innerHTML = `
                <td>
                    <span class="cve-id-link">${escapeHtml(cve.cve_id)}</span>
                    ${cve.kev_listed ? '<span class="badge bg-danger ms-1">KEV</span>' : ''}
                </td>
                <td>${escapeHtml(item.matched_vendor || '')} ${escapeHtml(item.matched_product || '')}</td>
                <td class="text-center"><span class="badge badge-${riskLevel(cve.risk_level).toUpperCase()}">${escapeHtml(cve.risk_level || 'N/A')}</span></td>
                <td class="text-center">${cve.risk_score !== null ? cve.risk_score.toFixed(2) : 'N/A'}</td>
                <td>${escapeHtml(item.affected_range || 'Unknown')}</td>
                <td>${escapeHtml(item.fixed_version || 'Not published')}</td>
                <td class="text-center">
                    <span class="status-pill status-${item.version_status}">
                        <i class="bi ${STATUS_ICONS[item.version_status]}"></i> ${STATUS_LABELS[item.version_status]}
                    </span>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    document.getElementById('checker-form').addEventListener('submit', (e) => {
        e.preventDefault();
        runVulnerabilityCheck();
    });

    document.getElementById('checker-table-body').addEventListener('click', (e) => {
        const row = e.target.closest('tr');
        if (row && row.dataset.cveId) {
            fetchAndShowCveDetails(row.dataset.cveId);
        }
    });

    // --- Theme toggle ---
    const THEME_KEY = 'vulnintel-theme';

    function applyTheme(theme) {
        if (theme) {
            document.documentElement.setAttribute('data-theme', theme);
        } else {
            document.documentElement.removeAttribute('data-theme');
        }
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const isDark = theme ? theme === 'dark' : prefersDark;
        // Bootstrap 5.3's own components (tables, modals, form controls) only
        // switch to their dark palette when data-bs-theme is set -- our
        // data-theme attribute only drives our own custom CSS variables.
        // Without this, raw Bootstrap-styled elements stayed light-mode even
        // when the rest of the page went dark.
        document.documentElement.setAttribute('data-bs-theme', isDark ? 'dark' : 'light');
        const icon = document.querySelector('#theme-toggle i');
        if (icon) icon.className = isDark ? 'bi bi-sun' : 'bi bi-moon-stars';
        if (severityChart) {
            // Re-render so the chart picks up the new CSS custom property values.
            fetchStats();
        }
    }

    document.getElementById('theme-toggle').addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        const currentlyDark = current ? current === 'dark' : prefersDark;
        const next = currentlyDark ? 'light' : 'dark';
        localStorage.setItem(THEME_KEY, next);
        applyTheme(next);
    });

    applyTheme(localStorage.getItem(THEME_KEY));

    // --- Pipeline run/status ---
    let statusPollTimer = null;
    let wasRunning = null; // null = unknown yet (avoids refreshing data on first page load)

    function renderPipelineStatus(data) {
        const el = document.getElementById('pipeline-status');
        if (data.running) {
            el.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status"></span>${escapeHtml(data.job || 'Running')}`;
        } else if (data.last_error) {
            el.textContent = `Last run failed: ${data.last_error}`;
        } else if (data.last_finished_at) {
            const finished = new Date(data.last_finished_at);
            const when = Number.isNaN(finished.getTime()) ? '' : ` (${finished.toLocaleTimeString()})`;
            el.textContent = `Idle — last run finished${when}`;
        } else {
            el.textContent = 'Idle';
        }
    }

    function pollPipelineStatus() {
        fetch(`${API_BASE}/pipeline/status`)
            .then(response => response.json())
            .then(data => {
                renderPipelineStatus(data);
                if (data.running) {
                    statusPollTimer = setTimeout(pollPipelineStatus, 2000);
                } else {
                    statusPollTimer = null;
                    if (wasRunning) {
                        // A job just finished: refresh data that may have changed.
                        fetchStats();
                        fetchCVEs();
                        fetchFilters();
                        fetchSources();
                        fetchArticles();
                        fetchVendors();
                        fetchProducts();
                        fetchKevCves();
                        fetchAnalytics();
                        fetchScanHistory();
                    }
                }
                wasRunning = data.running;
            })
            .catch(error => console.error('Error polling pipeline status:', error));
    }

    function startStatusPolling() {
        if (statusPollTimer) return; // already polling
        pollPipelineStatus();
    }

    document.getElementById('run-pipeline-btn').addEventListener('click', () => {
        fetch(`${API_BASE}/pipeline/run`, { method: 'POST' })
            .then(response => response.json().then(data => ({ status: response.status, body: data })))
            .then(({ status, body }) => {
                if (status !== 202) {
                    alert(body.error || 'Could not start pipeline run.');
                }
                startStatusPolling();
            })
            .catch(error => console.error('Error starting pipeline run:', error));
    });

    // --- Card / table view toggles (Articles, Vendors, Products, Sources) ---
    function wireViewToggle(toggleId, cardViewId, tableViewId) {
        const toggle = document.getElementById(toggleId);
        toggle.querySelectorAll('button').forEach(btn => {
            btn.addEventListener('click', () => {
                toggle.querySelectorAll('button').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const isCard = btn.dataset.view === 'card';
                document.getElementById(cardViewId).classList.toggle('d-none', !isCard);
                document.getElementById(tableViewId).classList.toggle('d-none', isCard);
            });
        });
    }
    wireViewToggle('articles-view-toggle', 'articles-card-view', 'articles-table-view');
    wireViewToggle('vendors-view-toggle', 'vendors-card-view', 'vendors-table-view');
    wireViewToggle('products-view-toggle', 'products-card-view', 'products-table-view');
    wireViewToggle('sources-view-toggle', 'sources-card-view', 'sources-table-view');

    // Initial data load
    switchToTab(pageIdFromHash(), { skipHash: true });
    fetchStats();
    fetchFilters();
    fetchCVEs();
    fetchArticles();
    fetchVendors();
    fetchProducts();
    fetchSourceTypes();
    fetchSources();
    fetchKevCves();
    fetchAnalytics();
    fetchScanHistory();
    fetchSettings();
    setDynamicFooter();
    pollPipelineStatus(); // reflect status immediately (e.g. a run already in progress)

    window.addEventListener('hashchange', () => switchToTab(pageIdFromHash(), { skipHash: true }));
});
