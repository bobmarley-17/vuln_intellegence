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

    function renderSeverityChart(severityCounts) {
        const ctx = document.getElementById('severityChart').getContext('2d');
        const labels = Object.keys(severityCounts);
        const data = Object.values(severityCounts);

        if (severityChart) {
            severityChart.destroy();
        }

        severityChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: [
                        '#dc3545', // Critical
                        '#fd7e14', // High
                        '#ffc107', // Medium
                        '#198754', // Low
                    ],
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'CVEs by Severity'
                    }
                }
            }
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
            .then(cve => renderCveModal(cve))
            .catch(error => console.error('Could not find details for', cveId, error));
    }

    function renderCveModal(cve) {
        document.getElementById('cveDetailModalLabel').textContent = cve.cve_id;
        const body = document.getElementById('cve-detail-body');

        const score = (s) => s !== null ? s.toFixed(2) : 'N/A';
        const na = (v) => v || 'Not Available';

        body.innerHTML = `
            <p><strong>Summary:</strong> ${na(cve.summary)}</p>
            <div class="row">
                <div class="col-md-6">
                    <h5>Details</h5>
                    <ul class="list-unstyled">
                        <li><strong>Severity:</strong> <span class="badge badge-${(cve.risk_level || 'LOW').toUpperCase()}">${escapeHtml(cve.risk_level || 'Not Available')}</span></li>
                        <li><strong>Published:</strong> ${formatDate(cve.published_date)}</li>
                        <li><strong>Last Modified:</strong> ${formatDate(cve.modified_date)}</li>
                        <li><strong>Vendor:</strong> ${na(cve.vendor)}</li>
                        <li><strong>Product:</strong> ${na(cve.product)}</li>
                        <li><strong>CWE:</strong> ${cve.cwe.length > 0 ? cve.cwe.join(', ') : 'N/A'}</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <h5>Scoring</h5>
                    <ul class="list-unstyled">
                        <li><strong>CVSSv4:</strong> ${score(cve.cvss_v4_score)}</li>
                        <li><strong>CVSSv3:</strong> ${score(cve.cvss_v3_score)}</li>
                        <li><strong>EPSS:</strong> ${cve.epss_score !== null ? (cve.epss_score * 100).toFixed(1) + '%' : 'N/A'}</li>
                        <li><strong>KEV:</strong> ${cve.kev_listed ? '<span class="text-danger">Yes, Actively Exploited</span>' : 'No'}</li>
                    </ul>
                </div>
            </div>

            <h5>Affected Versions</h5>
            <p>${na(cve.affected_versions_display)}</p>

            <h5>Fixed Versions</h5>
            <p>${na(cve.fixed_versions_display)}</p>

            <h5>References</h5>
            <div class="reference-list">
                ${cve.references.slice(0, 5).map(ref => `
                    <a href="${ref}" target="_blank" rel="noopener noreferrer" class="d-block text-truncate">${ref}</a>
                `).join('')}
                ${cve.references.length > 5 ? `<small>...and ${cve.references.length - 5} more.</small>` : ''}
            </div>
        `;
    }


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
