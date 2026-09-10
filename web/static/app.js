"use strict";

/* ------------------------------------------------------------------ */
/* Shared helpers                                                       */
/* ------------------------------------------------------------------ */

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return "";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatTimestamp(isoString) {
  if (!isoString) return "";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  return date.toLocaleString();
}

function severityBadgeHtml(severity) {
  const normalized = (severity || "info").toLowerCase();
  return `<span class="badge badge-${normalized}">${normalized}</span>`;
}

function statusBadgeHtml(status) {
  const normalized = (status || "pending").toLowerCase();
  const label = normalized === "complete" ? (arguments[1] || "complete") : normalized;
  return `<span class="badge badge-${normalized}">${label}</span>`;
}

/* Default confidence per severity, used for findings that don't carry
   their own raw.confidence (only modules/strings.py's findings do) --
   keeps the Confidence column meaningful for every module. */
const DEFAULT_CONFIDENCE_BY_SEVERITY = { critical: 0.95, high: 0.75, medium: 0.5, low: 0.3, info: 0.1 };

function findingConfidence(finding) {
  if (finding.raw && typeof finding.raw.confidence === "number") {
    return finding.raw.confidence;
  }
  return DEFAULT_CONFIDENCE_BY_SEVERITY[(finding.severity || "info").toLowerCase()] || 0.1;
}

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/* Scan ids ticked for comparison in the history list. Kept in module
   scope so the 10s history auto-refresh can restore checkbox state
   instead of wiping a half-made selection. */
const _selectedForCompare = new Set();

const TRASH_SVG =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" ' +
  'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
  '<polyline points="3 6 5 6 21 6"></polyline>' +
  '<path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>' +
  '<line x1="10" y1="11" x2="10" y2="17"></line>' +
  '<line x1="14" y1="11" x2="14" y2="17"></line></svg>';

/* ------------------------------------------------------------------ */
/* Index page                                                           */
/* ------------------------------------------------------------------ */

function setupDropzone(dropzoneEl, inputEl, onChange) {
  if (!dropzoneEl || !inputEl) return;

  const openPicker = () => inputEl.click();
  dropzoneEl.addEventListener("click", openPicker);
  dropzoneEl.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      openPicker();
    }
  });

  inputEl.addEventListener("change", () => {
    if (inputEl.files.length > 0) onChange(inputEl.files[0]);
  });

  ["dragenter", "dragover"].forEach((eventName) => {
    dropzoneEl.addEventListener(eventName, (event) => {
      event.preventDefault();
      event.stopPropagation();
      dropzoneEl.classList.add("dragover");
    });
  });

  ["dragleave", "dragend"].forEach((eventName) => {
    dropzoneEl.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzoneEl.classList.remove("dragover");
    });
  });

  dropzoneEl.addEventListener("drop", (event) => {
    event.preventDefault();
    event.stopPropagation();
    dropzoneEl.classList.remove("dragover");
    const files = event.dataTransfer.files;
    if (files.length === 0) return;
    const transfer = new DataTransfer();
    transfer.items.add(files[0]);
    inputEl.files = transfer.files;
    onChange(files[0]);
  });
}

function initIndexPage() {
  const form = document.getElementById("upload-form");
  if (!form) return;

  const firmwareDropzone = document.getElementById("firmware-dropzone");
  const firmwareInput = document.getElementById("firmware-input");
  const firmwareDropzoneContent = document.getElementById("firmware-dropzone-content");
  const firmwareFileInfo = document.getElementById("firmware-file-info");
  const firmwareFileName = document.getElementById("firmware-file-name");
  const firmwareFileSize = document.getElementById("firmware-file-size");
  const firmwareClear = document.getElementById("firmware-clear");
  const analyseButton = document.getElementById("analyse-button");
  const formError = document.getElementById("form-error");

  function selectFirmware(file) {
    firmwareFileName.textContent = file.name;
    firmwareFileSize.textContent = formatBytes(file.size);
    firmwareDropzoneContent.hidden = true;
    firmwareFileInfo.hidden = false;
    analyseButton.disabled = false;
    formError.hidden = true;
  }

  setupDropzone(firmwareDropzone, firmwareInput, selectFirmware);

  firmwareClear.addEventListener("click", (event) => {
    event.stopPropagation();
    firmwareInput.value = "";
    firmwareDropzoneContent.hidden = false;
    firmwareFileInfo.hidden = true;
    analyseButton.disabled = true;
  });

  [
    { dropzone: "golden-dropzone", input: "golden-input", label: "golden-label" },
    { dropzone: "pcap-dropzone", input: "pcap-input", label: "pcap-label" },
  ].forEach(({ dropzone, input, label }) => {
    const dropzoneEl = document.getElementById(dropzone);
    const inputEl = document.getElementById(input);
    const labelEl = document.getElementById(label);
    setupDropzone(dropzoneEl, inputEl, (file) => {
      labelEl.textContent = `${file.name} (${formatBytes(file.size)})`;
      labelEl.classList.add("has-file");
    });
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!firmwareInput.files.length) return;

    analyseButton.disabled = true;
    analyseButton.textContent = "Uploading...";
    formError.hidden = true;

    try {
      const formData = new FormData(form);
      const response = await fetch("/scan", { method: "POST", body: formData });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Upload failed.");
      }
      window.location.href = data.redirect;
    } catch (error) {
      formError.textContent = error.message || "Upload failed.";
      formError.hidden = false;
      analyseButton.disabled = false;
      analyseButton.textContent = "Analyse Firmware";
    }
  });

  loadHistory();
  setInterval(loadHistory, 10000);
}

async function loadHistory() {
  const listEl = document.getElementById("history-list");
  const emptyEl = document.getElementById("history-empty");
  if (!listEl) return;

  try {
    const response = await fetch("/history");
    const scans = await response.json();

    listEl.querySelectorAll(".history-item").forEach((el) => el.remove());

    const liveIds = new Set(scans.map((scan) => scan.id));
    [..._selectedForCompare].forEach((id) => {
      if (!liveIds.has(id)) _selectedForCompare.delete(id);
    });

    if (scans.length === 0) {
      emptyEl.hidden = false;
      updateCompareButton();
      return;
    }
    emptyEl.hidden = true;

    scans.forEach((scan) => {
      const item = document.createElement("div");
      item.className = "history-item";
      item.dataset.scanId = scan.id;

      const badge =
        scan.status === "complete"
          ? `<span class="badge badge-${(scan.verdict || "low").toLowerCase()}">${scan.verdict}</span>`
          : statusBadgeHtml(scan.status);

      item.innerHTML = `
        <input type="checkbox" class="history-checkbox" aria-label="Select for comparison" ${
          _selectedForCompare.has(scan.id) ? "checked" : ""
        } />
        <a class="history-item-link" href="/scan/${scan.id}">
          <span class="history-item-name">${escapeHtml(scan.firmware_filename)}</span>
          ${badge}
          <span class="history-item-time">${formatTimestamp(scan.created_at)}</span>
        </a>
        <button class="history-delete" type="button" title="Delete scan" aria-label="Delete scan">
          ${TRASH_SVG}
        </button>
      `;

      item.querySelector(".history-checkbox").addEventListener("change", (event) => {
        if (event.target.checked) _selectedForCompare.add(scan.id);
        else _selectedForCompare.delete(scan.id);
        updateCompareButton();
      });

      item.querySelector(".history-delete").addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!window.confirm("Delete this scan? This cannot be undone.")) return;
        try {
          const deleteResponse = await fetch(`/scan/${scan.id}`, { method: "DELETE" });
          if (!deleteResponse.ok) throw new Error(`HTTP ${deleteResponse.status}`);
          _selectedForCompare.delete(scan.id);
          item.remove();
          if (!listEl.querySelector(".history-item")) emptyEl.hidden = false;
          updateCompareButton();
        } catch (deleteError) {
          console.error("Failed to delete scan", deleteError);
          window.alert("Could not delete this scan.");
        }
      });

      listEl.appendChild(item);
    });

    updateCompareButton();
  } catch (error) {
    /* History polling is best-effort; a transient failure just leaves the
       existing list in place until the next 10s tick. */
    console.error("Failed to load scan history", error);
  }
}

function updateCompareButton() {
  const button = document.getElementById("compare-selected-btn");
  if (!button) return;
  button.hidden = _selectedForCompare.size !== 2;
}

function initCompareSelection() {
  const button = document.getElementById("compare-selected-btn");
  if (!button) return;
  button.addEventListener("click", () => {
    if (_selectedForCompare.size !== 2) return;
    const [a, b] = [..._selectedForCompare];
    window.location.href = `/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`;
  });
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text == null ? "" : String(text);
  return div.innerHTML;
}

/* ------------------------------------------------------------------ */
/* Report page                                                          */
/* ------------------------------------------------------------------ */

function initReportPage() {
  if (typeof window.SCAN_ID === "undefined") return;
  const scanId = window.SCAN_ID;

  const progressSection = document.getElementById("progress-section");
  const resultsSection = document.getElementById("results-section");
  const progressBarFill = document.getElementById("progress-bar-fill");
  const stepListItems = document.querySelectorAll("#step-list li");
  const progressError = document.getElementById("progress-error");

  function markSteps(currentStepText, progress) {
    progressBarFill.style.width = `${progress}%`;
    let reachedCurrent = false;
    stepListItems.forEach((li) => {
      const stepText = li.dataset.step;
      if (reachedCurrent) {
        li.classList.remove("active", "done");
        return;
      }
      if (stepText === currentStepText) {
        li.classList.add("active");
        li.classList.remove("done");
        reachedCurrent = true;
      } else {
        li.classList.remove("active");
        li.classList.add("done");
      }
    });
  }

  function onComplete() {
    progressSection.hidden = true;
    resultsSection.hidden = false;
    loadReport(scanId);
  }

  function onFailed(message) {
    progressError.textContent = message || "Scan failed.";
    progressError.hidden = false;
  }

  const source = new EventSource(`/scan/${scanId}/stream`);
  source.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.error) {
      onFailed(data.error);
      source.close();
      return;
    }
    markSteps(data.step, data.progress);
    if (data.complete) {
      source.close();
      onComplete();
    }
  };
  source.onerror = () => {
    /* EventSource retries on its own; if the scan already finished by
       the time this fires, loadReport() below is idempotent to call
       again once, so just leave it be rather than surfacing noise. */
  };

  setupExportButton(scanId);
}

let _reportFindings = [];
let _currentFilter = "all";
let _currentPage = 1;
let _sortField = "severity";
let _sortDirection = "desc";
const FINDINGS_PER_PAGE = 20;

async function loadReport(scanId) {
  const response = await fetch(`/scan/${scanId}/report`);
  const report = await response.json();

  renderVerdict(report);
  renderModuleBreakdown(report);
  renderEntropyPlot(report);
  renderCorroborated(report);

  _reportFindings = report.findings || [];
  _currentPage = 1;
  renderFindingsTable();
  setupFilters();
  setupSorting();
}

function renderVerdict(report) {
  const score = report.score || {};
  const badge = document.getElementById("verdict-badge");
  badge.textContent = score.verdict || report.verdict || "N/A";
  badge.classList.add(score.verdict_color || "green");

  const displayScore = Math.min(score.total_score ?? report.total_score ?? 0, 100);
  document.getElementById("verdict-score").textContent = `${displayScore} / 100`;

  const moduleCount = Object.keys(score.module_scores || {}).length;
  const confidencePct = Math.round((score.confidence || 0) * 100);
  document.getElementById("verdict-confidence").textContent =
    `${moduleCount} module(s) contributed findings (${confidencePct}% confidence)`;

  document.getElementById("verdict-summary").textContent = score.summary || "";
}

function renderModuleBreakdown(report) {
  const container = document.getElementById("module-breakdown");
  container.innerHTML = "";
  const counts = (report.score && report.score.module_finding_counts) || {};

  Object.entries(counts).forEach(([moduleName, severities]) => {
    const total = Object.values(severities).reduce((sum, n) => sum + n, 0);
    const highestSeverity =
      ["critical", "high", "medium", "low"].find((sev) => (severities[sev] || 0) > 0) || "low";

    const card = document.createElement("div");
    card.className = "module-card";
    card.style.borderLeftColor = `var(--${highestSeverity})`;
    card.innerHTML = `
      <div class="module-card-name">${escapeHtml(moduleName.replace(/_/g, " "))}</div>
      <div class="module-card-count">${total} finding(s)</div>
      <div class="module-card-severities">
        ${["critical", "high", "medium", "low"]
          .filter((sev) => (severities[sev] || 0) > 0)
          .map((sev) => `<span class="badge badge-${sev}">${severities[sev]} ${sev}</span>`)
          .join("")}
      </div>
    `;
    container.appendChild(card);
  });
}

function renderEntropyPlot(report) {
  const card = document.getElementById("entropy-plot-card");
  const img = document.getElementById("entropy-plot-image");
  if (!report.entropy_plot_path) {
    card.hidden = true;
    return;
  }
  img.src = `/scan/${report.id}/plot`;
  card.hidden = false;
}

function renderCorroborated(report) {
  const card = document.getElementById("corroborated-card");
  const list = document.getElementById("corroborated-list");
  const corroborated = (report.score && report.score.corroborated_findings) || [];

  if (corroborated.length === 0) {
    card.hidden = true;
    return;
  }
  card.hidden = false;
  list.innerHTML = corroborated
    .map(
      (finding) => `
        <li>
          ${severityBadgeHtml(finding.severity)}
          <strong>${escapeHtml(finding.description)}</strong>
          <div class="corroborated-modules">
            Module: ${escapeHtml(finding.module_name)}
            ${finding.offset !== null ? `&middot; Offset: 0x${Number(finding.offset).toString(16)}` : ""}
          </div>
        </li>
      `
    )
    .join("");
}

function setupFilters() {
  const buttons = document.querySelectorAll(".filter-btn");
  buttons.forEach((button) => {
    button.onclick = () => {
      buttons.forEach((b) => b.classList.remove("active"));
      button.classList.add("active");
      _currentFilter = button.dataset.filter;
      _currentPage = 1;
      renderFindingsTable();
    };
  });
}

function setupSorting() {
  document.querySelectorAll(".findings-table th.sortable").forEach((th) => {
    th.onclick = () => {
      const field = th.dataset.sort;
      if (_sortField === field) {
        _sortDirection = _sortDirection === "asc" ? "desc" : "asc";
      } else {
        _sortField = field;
        _sortDirection = "desc";
      }
      document.querySelectorAll(".findings-table th.sortable").forEach((el) => el.classList.remove("sort-active"));
      th.classList.add("sort-active");
      renderFindingsTable();
    };
  });
}

function getFilteredSortedFindings() {
  let findings = _reportFindings;
  if (_currentFilter !== "all") {
    findings = findings.filter((f) => (f.severity || "").toLowerCase() === _currentFilter);
  }

  const direction = _sortDirection === "asc" ? 1 : -1;
  findings = [...findings].sort((a, b) => {
    let aVal;
    let bVal;
    if (_sortField === "severity") {
      aVal = SEVERITY_RANK[(a.severity || "info").toLowerCase()] || 0;
      bVal = SEVERITY_RANK[(b.severity || "info").toLowerCase()] || 0;
    } else if (_sortField === "confidence") {
      aVal = findingConfidence(a);
      bVal = findingConfidence(b);
    } else if (_sortField === "offset") {
      aVal = a.offset === null || a.offset === undefined ? -1 : a.offset;
      bVal = b.offset === null || b.offset === undefined ? -1 : b.offset;
    } else {
      aVal = (a[_sortField] || "").toString();
      bVal = (b[_sortField] || "").toString();
    }
    if (aVal < bVal) return -1 * direction;
    if (aVal > bVal) return 1 * direction;
    return 0;
  });

  return findings;
}

function renderFindingsTable() {
  const tbody = document.getElementById("findings-tbody");
  const emptyEl = document.getElementById("findings-empty");
  const findings = getFilteredSortedFindings();

  if (findings.length === 0) {
    tbody.innerHTML = "";
    emptyEl.hidden = false;
    document.getElementById("pagination").innerHTML = "";
    return;
  }
  emptyEl.hidden = true;

  const totalPages = Math.max(1, Math.ceil(findings.length / FINDINGS_PER_PAGE));
  _currentPage = Math.min(_currentPage, totalPages);
  const start = (_currentPage - 1) * FINDINGS_PER_PAGE;
  const pageFindings = findings.slice(start, start + FINDINGS_PER_PAGE);

  tbody.innerHTML = pageFindings
    .map((finding) => {
      const offsetText =
        finding.offset === null || finding.offset === undefined
          ? "--"
          : `0x${Number(finding.offset).toString(16)}`;
      const confidencePct = Math.round(findingConfidence(finding) * 100);
      return `
        <tr>
          <td>${severityBadgeHtml(finding.severity)}</td>
          <td class="col-module">${escapeHtml(finding.module_name)}</td>
          <td class="col-offset">${offsetText}</td>
          <td>${escapeHtml(finding.description)}</td>
          <td>${confidencePct}%</td>
        </tr>
      `;
    })
    .join("");

  renderPagination(totalPages);
}

function renderPagination(totalPages) {
  const container = document.getElementById("pagination");
  if (totalPages <= 1) {
    container.innerHTML = "";
    return;
  }

  const buttons = [];
  buttons.push(
    `<button ${_currentPage === 1 ? "disabled" : ""} data-page="${_currentPage - 1}">Prev</button>`
  );
  for (let page = 1; page <= totalPages; page += 1) {
    buttons.push(
      `<button class="${page === _currentPage ? "active" : ""}" data-page="${page}">${page}</button>`
    );
  }
  buttons.push(
    `<button ${_currentPage === totalPages ? "disabled" : ""} data-page="${_currentPage + 1}">Next</button>`
  );

  container.innerHTML = buttons.join("");
  container.querySelectorAll("button[data-page]").forEach((button) => {
    button.onclick = () => {
      _currentPage = Number(button.dataset.page);
      renderFindingsTable();
    };
  });
}

function setupExportButton(scanId) {
  const button = document.getElementById("export-btn");
  if (!button) return;
  button.addEventListener("click", async () => {
    const response = await fetch(`/scan/${scanId}/report`);
    const report = await response.json();
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `hexwarden_report_${scanId}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  });
}

/* ------------------------------------------------------------------ */
/* Compare page                                                          */
/* ------------------------------------------------------------------ */

async function fetchReport(scanId) {
  try {
    const response = await fetch(`/scan/${scanId}/report`);
    if (!response.ok) return null;
    return await response.json();
  } catch (error) {
    console.error("Failed to load report", scanId, error);
    return null;
  }
}

function renderCompareColumn(container, report) {
  if (!report) {
    container.innerHTML = '<p class="compare-loading">Could not load this scan.</p>';
    return;
  }

  const score = report.score || {};
  const verdict = score.verdict || report.verdict || "N/A";
  const verdictColor = score.verdict_color || "green";
  const displayScore = Math.min(score.total_score ?? report.total_score ?? 0, 100);
  const counts = score.module_finding_counts || {};

  const statusNote =
    report.status !== "complete"
      ? `<p class="compare-loading">Scan status: ${escapeHtml(report.status)}</p>`
      : "";

  const moduleRows = Object.keys(counts).length
    ? Object.entries(counts)
        .map(([name, severities]) => {
          const total = Object.values(severities).reduce((sum, n) => sum + n, 0);
          return `<div class="compare-module-row">
            <span class="compare-module-name">${escapeHtml(name.replace(/_/g, " "))}</span>
            <span>${total} finding(s)</span>
          </div>`;
        })
        .join("")
    : '<p class="compare-loading">No modules produced findings.</p>';

  container.innerHTML = `
    <p class="compare-col-firmware">${escapeHtml(report.firmware_filename)}</p>
    <div class="compare-col-verdict">
      <span class="verdict-badge ${verdictColor}">${escapeHtml(verdict)}</span>
      <span class="compare-col-score">${displayScore} / 100</span>
    </div>
    ${score.summary ? `<p class="compare-loading">${escapeHtml(score.summary)}</p>` : ""}
    ${statusNote}
    <div class="compare-col-modules">${moduleRows}</div>
  `;
}

function renderCompareDiff(reportA, reportB) {
  const diffEl = document.getElementById("compare-diff");
  const textEl = document.getElementById("compare-diff-text");
  if (!diffEl || !textEl || !reportA || !reportB) return;

  const modulesA = new Set(Object.keys((reportA.score || {}).module_finding_counts || {}));
  const modulesB = new Set(Object.keys((reportB.score || {}).module_finding_counts || {}));
  const onlyInB = [...modulesB].filter((moduleName) => !modulesA.has(moduleName));

  textEl.textContent = onlyInB.length
    ? `Modules that fired in B but not in A: ${onlyInB
        .map((moduleName) => moduleName.replace(/_/g, " "))
        .join(", ")}`
    : "No modules fired in B that did not also fire in A.";
  diffEl.hidden = false;
}

async function initComparePage() {
  if (typeof window.COMPARE_A === "undefined") return;

  const [reportA, reportB] = await Promise.all([
    fetchReport(window.COMPARE_A),
    fetchReport(window.COMPARE_B),
  ]);

  renderCompareColumn(document.getElementById("compare-col-a"), reportA);
  renderCompareColumn(document.getElementById("compare-col-b"), reportB);
  renderCompareDiff(reportA, reportB);
}

/* ------------------------------------------------------------------ */
/* Boot                                                                  */
/* ------------------------------------------------------------------ */

document.addEventListener("DOMContentLoaded", () => {
  initIndexPage();
  initCompareSelection();
  initReportPage();
  initComparePage();
});
