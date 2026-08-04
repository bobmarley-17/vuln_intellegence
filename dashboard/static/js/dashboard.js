(() => {
  "use strict";

  const state = {
    page: 1,
    pageSize: 25,
    sortBy: "risk_score",
    sortDir: "desc",
  };
  let searchDebounce = null;
  let severityChart = null;
  let vendorChart = null;

  const el = (id) => document.getElementById(id);

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("vi-theme", theme);
  }

  function initTheme() {
    const saved = localStorage.getItem("vi-theme");
    const preferred = saved || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    applyTheme(preferred);
    el("themeToggle").addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme");
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }

  function buildQuery() {
    const params = new URLSearchParams();
    const q = el("searchInput").value.trim();
    if (q) params.set("q", q);

    const severity = el("filterSeverity").value;
    if (severity) params.set("severity", severity);
    const vendor = el("filterVendor").value;
    if (vendor) params.set("vendor", vendor);
    const product = el("filterProduct").value;
    if (product) params.set("product", product);
    const source = el("filterSource").value;
    if (source) params.set("source_site", source);
    const minCvss = el("filterMinCvss").value;
    if (minCvss) params.set("min_cvss", minCvss);
    const minEpss = el("filterMinEpss").value;
    if (minEpss) params.set("min_epss", minEpss);
    const publishedAfter = el("filterPublishedAfter").value;
    if (publishedAfter) params.set("published_after", publishedAfter);
    if (el("filterKev").checked) params.set("kev_only", "true");

    params.set("sort_by", state.sortBy);
    params.set("sort_dir", state.sortDir);
    params.set("page", state.page);
    params.set("page_size", state.pageSize);
    return params.toString();
  }

  async function loadCves() {
    const res = await fetch(`/api/cves?${buildQuery()}`);
    const data = await res.json();
    renderTable(data.items);
    renderPagination(data.total, data.page, data.page_size);
  }

  function severityBadge(level) {
    const cls = { Critical: "badge-critical", High: "badge-high", Medium: "badge-medium", Low: "badge-low" }[level] || "badge-low";
    return `<span class="badge ${cls}">${level || "Low"}</span>`;
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str ?? "";
    return div.innerHTML;
  }

  function renderTable(items) {
    const body = el("cveTableBody");
    if (!items.length) {
      body.innerHTML = `<tr><td colspan="11" style="text-align:center; color:var(--text-muted); padding:24px;">No CVEs match the current filters.</td></tr>`;
      return;
    }
    body.innerHTML = items
      .map(
        (c) => `
      <tr data-cve="${escapeHtml(c.cve_id)}">
        <td><strong>${escapeHtml(c.cve_id)}</strong></td>
        <td>${severityBadge(c.risk_level)} ${c.risk_score ?? "-"}</td>
        <td>${c.cvss_v3_score ?? "-"}</td>
        <td>${c.epss_score != null ? (c.epss_score * 100).toFixed(1) + "%" : "-"}</td>
        <td>${c.kev_listed ? '<span class="kev-yes">Yes</span>' : '<span class="kev-no">No</span>'}</td>
        <td>${escapeHtml(c.vendor) || "-"}</td>
        <td>${escapeHtml(c.product) || "-"}</td>
        <td>${escapeHtml(c.affected_versions_display) || "-"}</td>
        <td>${escapeHtml(c.fixed_versions_display) || "-"}</td>
        <td>${c.published_date ? c.published_date.slice(0, 10) : "-"}</td>
        <td class="summary-cell">${escapeHtml(c.summary)}</td>
      </tr>`
      )
      .join("");

    body.querySelectorAll("tr[data-cve]").forEach((row) => {
      row.addEventListener("click", () => {
        const cve = items.find((c) => c.cve_id === row.dataset.cve);
        if (cve) showDetail(cve);
      });
    });
  }

  function showDetail(c) {
    el("modalBody").innerHTML = `
      <h3>${escapeHtml(c.cve_id)} ${severityBadge(c.risk_level)}</h3>
      <p>${escapeHtml(c.summary)}</p>
      <dl>
        <dt>Vendor / Product</dt><dd>${escapeHtml(c.vendor)} / ${escapeHtml(c.product)}</dd>
        <dt>Affected</dt><dd>${escapeHtml(c.affected_versions_display) || "Unknown"}</dd>
        <dt>Fixed</dt><dd>${escapeHtml(c.fixed_versions_display) || "Not yet fixed"}</dd>
        <dt>CVSS v3</dt><dd>${c.cvss_v3_score ?? "-"} (${escapeHtml(c.cvss_v3_vector) || "-"})</dd>
        <dt>EPSS</dt><dd>${c.epss_score != null ? (c.epss_score * 100).toFixed(2) + "%" : "-"} (percentile ${c.epss_percentile != null ? (c.epss_percentile * 100).toFixed(1) + "%" : "-"})</dd>
        <dt>KEV</dt><dd>${c.kev_listed ? `Yes — added ${c.kev_date_added || "-"}, due ${c.kev_due_date || "-"}` : "No"}</dd>
        <dt>CWE</dt><dd>${(c.cwe || []).join(", ") || "-"}</dd>
        <dt>Published</dt><dd>${c.published_date || "-"}</dd>
        <dt>Modified</dt><dd>${c.modified_date || "-"}</dd>
        <dt>Recommendation</dt><dd><strong>${escapeHtml(c.risk_recommendation)}</strong></dd>
        <dt>Sources</dt><dd>${(c.source_articles || []).map((u) => `<a href="${u}" target="_blank" rel="noopener">${escapeHtml(new URL(u).hostname)}</a>`).join(", ")}</dd>
        <dt>References</dt><dd>${(c.references || []).slice(0, 8).map((u) => `<a href="${u}" target="_blank" rel="noopener">link</a>`).join(", ")}</dd>
      </dl>
    `;
    el("detailModal").classList.remove("hidden");
  }

  function renderPagination(total, page, pageSize) {
    const totalPages = Math.max(Math.ceil(total / pageSize), 1);
    el("pagination").innerHTML = `
      <span>${total} CVEs — page ${page} of ${totalPages}</span>
      <button id="prevPage" ${page <= 1 ? "disabled" : ""}>&larr; Prev</button>
      <button id="nextPage" ${page >= totalPages ? "disabled" : ""}>Next &rarr;</button>
    `;
    el("prevPage")?.addEventListener("click", () => {
      state.page = Math.max(state.page - 1, 1);
      loadCves();
    });
    el("nextPage")?.addEventListener("click", () => {
      state.page = Math.min(state.page + 1, totalPages);
      loadCves();
    });
  }

  async function loadFilters() {
    const res = await fetch("/api/filters");
    const data = await res.json();
    fillSelect("filterVendor", data.vendors);
    fillSelect("filterProduct", data.products);
    fillSelect("filterSource", data.sources);
  }

  function fillSelect(id, values) {
    const select = el(id);
    const placeholder = select.options[0];
    select.innerHTML = "";
    select.appendChild(placeholder);
    values.forEach((v) => {
      const opt = document.createElement("option");
      opt.value = v;
      opt.textContent = v;
      select.appendChild(opt);
    });
  }

  async function loadStats() {
    const res = await fetch("/api/stats");
    const data = await res.json();
    renderStatTiles(data);
    renderCharts(data);
  }

  function renderStatTiles(data) {
    const tiles = [
      ["Total Articles", data.total_articles],
      ["Total CVEs", data.total_cves],
      ["Critical", data.severity_counts.Critical],
      ["High", data.severity_counts.High],
      ["Medium", data.severity_counts.Medium],
      ["Low", data.severity_counts.Low],
      ["KEV Listed", data.kev_count],
      ["Vendors", data.vendor_count],
      ["Products", data.product_count],
    ];
    el("statsGrid").innerHTML = tiles
      .map(([label, value]) => `<div class="stat-tile"><div class="value">${value}</div><div class="label">${label}</div></div>`)
      .join("");
  }

  function chartTextColor() {
    return getComputedStyle(document.documentElement).getPropertyValue("--text").trim();
  }

  function renderCharts(data) {
    const textColor = chartTextColor();
    Chart.defaults.color = textColor;
    Chart.defaults.borderColor = "rgba(128,128,128,0.2)";

    const sevCtx = el("severityChart");
    const sevData = data.severity_counts;
    if (severityChart) severityChart.destroy();
    severityChart = new Chart(sevCtx, {
      type: "doughnut",
      data: {
        labels: Object.keys(sevData),
        datasets: [
          {
            data: Object.values(sevData),
            backgroundColor: ["#b91c1c", "#d9730d", "#ca8a04", "#16794e"],
          },
        ],
      },
      options: { plugins: { legend: { position: "bottom" } } },
    });

    const vendorCtx = el("vendorChart");
    if (vendorChart) vendorChart.destroy();
    vendorChart = new Chart(vendorCtx, {
      type: "bar",
      data: {
        labels: data.top_vendors.map((v) => v.vendor),
        datasets: [{ label: "CVEs", data: data.top_vendors.map((v) => v.count), backgroundColor: "#2563eb" }],
      },
      options: {
        indexAxis: "y",
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
      },
    });
  }

  function bindToolbar() {
    el("searchInput").addEventListener("input", () => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        state.page = 1;
        loadCves();
      }, 300);
    });

    ["filterSeverity", "filterVendor", "filterProduct", "filterSource", "filterMinCvss", "filterMinEpss", "filterPublishedAfter", "filterKev"].forEach(
      (id) => {
        el(id).addEventListener("change", () => {
          state.page = 1;
          loadCves();
        });
      }
    );

    el("resetFilters").addEventListener("click", () => {
      el("searchInput").value = "";
      el("filterSeverity").value = "";
      el("filterVendor").value = "";
      el("filterProduct").value = "";
      el("filterSource").value = "";
      el("filterMinCvss").value = "";
      el("filterMinEpss").value = "";
      el("filterPublishedAfter").value = "";
      el("filterKev").checked = false;
      state.page = 1;
      loadCves();
    });

    document.querySelectorAll("th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const sortBy = th.dataset.sort;
        if (state.sortBy === sortBy) {
          state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
        } else {
          state.sortBy = sortBy;
          state.sortDir = "desc";
        }
        loadCves();
      });
    });

    el("closeModal").addEventListener("click", () => el("detailModal").classList.add("hidden"));
    el("detailModal").addEventListener("click", (e) => {
      if (e.target.id === "detailModal") el("detailModal").classList.add("hidden");
    });
  }

  document.addEventListener("DOMContentLoaded", async () => {
    initTheme();
    bindToolbar();
    await Promise.all([loadFilters(), loadStats(), loadCves()]);
  });
})();
