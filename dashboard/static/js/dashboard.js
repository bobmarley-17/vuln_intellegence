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

    function renderTable(cves) {
        const tbody = document.getElementById('cve-table-body');
        tbody.innerHTML = '';
        if (cves.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center">No CVEs found.</td></tr>';
            return;
        }
        cves.forEach(cve => {
            const row = document.createElement('tr');
            row.dataset.cveId = cve.cve_id; // For click events
            row.innerHTML = `
                <td>
                    <a href="https://nvd.nist.gov/vuln/detail/${cve.cve_id}" target="_blank" class="cve-id-link">${cve.cve_id}</a>
                    ${cve.kev_listed ? '<span class="badge bg-danger ms-1">KEV</span>' : ''}
                </td>
                <td>${cve.summary || cve.description.substring(0, 150) + '...' || 'No description'}</td>
                <td class="text-center"><span class="badge badge-${cve.risk_level || 'LOW'}">${cve.risk_level || 'N/A'}</span></td>
                <td class="text-center">${cve.risk_score !== null ? cve.risk_score.toFixed(2) : 'N/A'}</td>
                <td>${cve.vendor || 'N/A'}</td>
                <td>${new Date(cve.published_date).toLocaleDateString()}</td>
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

    // Initial data load
    fetchStats();
    fetchFilters();
    fetchCVEs();
});