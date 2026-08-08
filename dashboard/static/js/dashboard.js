document.addEventListener('DOMContentLoaded', function () {
    const API_BASE = '/api';
    let severityChart = null;

    const state = {
        page: 1,
        pageSize: 25,
        sortBy: 'risk_score',
        sortDir: 'desc',
        q: '',
        severity: '',
        vendor: '',
        min_cvss: '',
        min_epss: '',
        kev_only: false,
        source_site: '',
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

    function fetchStats() {
        fetch(`${API_BASE}/stats`)
            .then(response => response.json())
            .then(data => {
                document.getElementById('total-cves').textContent = data.total_cves;
                document.getElementById('total-articles').textContent = data.total_articles;
                document.getElementById('kev-count').textContent = data.kev_count;
                document.getElementById('vendor-count').textContent = data.vendor_count;
                document.getElementById('product-count').textContent = data.product_count;
                renderSeverityChart(data.severity_counts);
            })
            .catch(error => console.error('Error fetching stats:', error));
    }

    function fetchFilters() {
        fetch(`${API_BASE}/filters`)
            .then(response => response.json())
            .then(data => {
                populateDropdown('filter-vendor', data.vendors);
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
                renderSourcesTable(data);
            })
            .catch(error => console.error('Error fetching sources:', error));
    }

    function fetchCVEs() {
        const params = new URLSearchParams({
            page: state.page,
            page_size: state.pageSize,
            sort_by: state.sortBy,
            sort_dir: state.sortDir,
            q: state.q,
            severity: state.severity,
            vendor: state.vendor,
            min_cvss: state.min_cvss,
            min_epss: state.min_epss,
            kev_only: state.kev_only,
            source_site: state.source_site,
        });

        const url = `${API_BASE}/cves?${params.toString()}`;
        fetch(url)
            .then(response => response.json())
            .then(data => {
                renderTable(data.items);
                renderPagination(data.total, data.page, data.page_size);
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

    function renderSourcesTable(sources) {
        const tbody = document.getElementById('sources-table-body');
        tbody.innerHTML = '';
        if (sources.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No security sources have been added yet.</td></tr>';
            return;
        }
        sources.forEach(source => {
            const row = document.createElement('tr');
            const cvesFound = source.cves_found !== null ? source.cves_found : 'N/A';
            const lastChecked = source.last_checked ? new Date(source.last_checked).toLocaleString() : 'Never';

            row.innerHTML = `
                <td><a href="${escapeHtml(source.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(source.title || source.url)}</a></td>
                <td><span class="badge bg-secondary">${escapeHtml(source.status)}</span></td>
                <td class="text-center">${cvesFound}</td>
                <td>${lastChecked}</td>
                <td>
                    <button class="btn btn-sm btn-outline-danger delete-source-btn" data-id="${source.id}">
                        <i class="bi bi-trash"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(row);
        });

        // Add event listeners for the new delete buttons
        document.querySelectorAll('.delete-source-btn').forEach(button => {
            button.addEventListener('click', (e) => {
                const sourceId = e.currentTarget.dataset.id;
                deleteSource(sourceId);
            });
        });
    }

    function renderTable(cves) {
        const tbody = document.getElementById('cve-table-body');
        tbody.innerHTML = '';
        if (cves.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">No CVEs found.</td></tr>';
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
                <td class="text-center">${cve.risk_score !== null ? cve.risk_score.toFixed(2) : 'N/A'}</td>
                <td>${escapeHtml(cve.vendor || 'N/A')}</td>
                <td>${formatDate(cve.published_date)}</td>
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
        state.min_cvss = document.getElementById('filter-min-cvss').value;
        state.min_epss = document.getElementById('filter-min-epss').value;
        state.kev_only = document.getElementById('filter-kev').checked;
        state.source_site = document.getElementById('filter-source').value;
        state.page = 1; // Reset to first page on filter change
        fetchCVEs();
    }

    // Event Listeners
    document.getElementById('filter-btn').addEventListener('click', handleFilterChange);

    document.getElementById('reset-btn').addEventListener('click', () => {
        document.getElementById('filter-form').reset();
        handleFilterChange();
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


    function setDynamicFooter() {
        const year = new Date().getFullYear();
        const footer = document.getElementById('copyright-year');
        if (footer) {
            footer.textContent = `Copyright © Vuln Intel ${year}. All rights reserved.`;
        }
    }

    function addSource() {
        const urlInput = document.getElementById('source-url-input');
        const url = urlInput.value.trim();
        const alertEl = document.getElementById('add-source-alert');

        if (!url) {
            showAlert(alertEl, 'Please enter a URL.', 'danger');
            return;
        }

        fetch(`${API_BASE}/sources`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json().then(data => ({ status: response.status, body: data })))
        .then(({ status, body }) => {
            if (status === 201) {
                showAlert(alertEl, 'Source added successfully! It will be processed shortly.', 'success');
                urlInput.value = '';
                fetchSources(); // Refresh the sources table
                startStatusPolling();
                setTimeout(() => {
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addSourceModal'));
                    modal.hide();
                    alertEl.style.display = 'none';
                }, 1500);
            } else {
                showAlert(alertEl, `Error: ${body.error || 'Could not add source.'}`, 'danger');
            }
        })
        .catch(error => {
            console.error('Error adding source:', error);
            showAlert(alertEl, 'A network error occurred.', 'danger');
        });
    }

    function deleteSource(sourceId) {
        if (!confirm('Are you sure you want to delete this source?')) {
            return;
        }
        fetch(`${API_BASE}/sources/${sourceId}`, { method: 'DELETE' })
            .then(response => {
                if (response.ok) {
                    fetchSources(); // Refresh the table
                } else {
                    alert('Failed to delete source.');
                }
            });
    }

    function showAlert(element, message, type) {
        element.className = `alert alert-${type}`;
        element.textContent = message;
        element.style.display = 'block';
    }

    document.getElementById('add-source-submit-btn').addEventListener('click', addSource);

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

    // Initial data load
    fetchStats();
    fetchFilters();
    fetchCVEs();
    fetchSources();
    setDynamicFooter();
    pollPipelineStatus(); // reflect status immediately (e.g. a run already in progress)
});
