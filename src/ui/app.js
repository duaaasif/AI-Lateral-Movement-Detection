let jobPollTimer = null;

function esc(val) {
  return String(val ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function fmtNum(n) {
  return Number(n || 0).toLocaleString();
}
async function apiGet(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
async function apiPost(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

// Theme selector (Executive Daylight: Light / Dark / System)
const themeSelect = document.getElementById("theme-select");
const systemMedia = window.matchMedia("(prefers-color-scheme: dark)");

function applyTheme(mode) {
  const resolved = mode === "system" ? (systemMedia.matches ? "dark" : "light") : mode;
  document.documentElement.setAttribute("data-theme", resolved);
}

const storedTheme = localStorage.getItem("aegis_theme");
const initialMode = ["light", "dark", "system"].includes(storedTheme) ? storedTheme : "light";
themeSelect.value = initialMode;
applyTheme(initialMode);

themeSelect.addEventListener("change", () => {
  localStorage.setItem("aegis_theme", themeSelect.value);
  applyTheme(themeSelect.value);
});

systemMedia.addEventListener("change", () => {
  if (themeSelect.value === "system") {
    applyTheme("system");
  }
});

// Tab navigation
const TAB_TITLES = {
  upload: ["Upload Raw Logs & Run Analysis", "Upload raw Windows/Linux .log files to automatically parse, split, train AI models, and inspect lateral movement graphs."],
  results: ["Detection Results & Visual Graphs", "Train/Test split summary, test-set lateral movement alerts, evaluation metrics, and generated charts."],
  logs: ["Raw & Parsed Log Explorer", "Inspect raw uploaded .log lines and query normalized parsed events."],
};

function switchTab(tabId) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
  document.querySelector(`.nav-item[data-tab="${tabId}"]`).classList.add("active");
  document.getElementById(`tab-${tabId}`).classList.add("active");
  const [title, sub] = TAB_TITLES[tabId] || ["AegisLM", ""];
  document.getElementById("page-title").textContent = title;
  document.getElementById("page-subtitle").textContent = sub;
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
document.getElementById("btn-go-upload").onclick = () => switchTab("upload");

// Render uploaded files
function renderUploadedFiles(files) {
  const list = document.getElementById("uploaded-files-list");
  const badge = document.getElementById("uploaded-count-badge");
  const startBtn = document.getElementById("btn-start-analysis");
  const rawSel = document.getElementById("raw-file-select");

  badge.textContent = `${files.length} file${files.length === 1 ? "" : "s"} queued`;
  startBtn.disabled = files.length === 0;

  if (!files.length) {
    list.innerHTML = `<li class="empty-row">No files uploaded yet. Ready-to-upload samples are in <code>data/upload_samples/*.log</code> and full 1M+ logs in <code>data/raw/*.log</code>.</li>`;
    rawSel.innerHTML = "";
    document.getElementById("raw-log-preview").textContent = "Upload a .log file first to inspect its raw lines.";
    return;
  }

  list.innerHTML = files
    .map(
      (f) => `<li>
        <span class="mono">${esc(f.name)}</span>
        <span class="file-actions">
          <span class="meta-text">${f.size_mb > 0 ? f.size_mb + " MB" : fmtNum(f.size_bytes) + " B"}</span>
          <button class="btn-mini" onclick="removeUploadedFile('${esc(f.name)}')">Remove</button>
        </span>
      </li>`
    )
    .join("");

  rawSel.innerHTML = files
    .map((f) => `<option value="${esc(f.name)}">${esc(f.name)} (${f.size_mb} MB)</option>`)
    .join("");
}

window.removeUploadedFile = async (name) => {
  const res = await apiPost("/api/session/remove-file", { filename: name });
  renderUploadedFiles(res.uploaded_files || []);
};

// Streaming binary upload
async function uploadFiles(fileList) {
  if (!fileList || !fileList.length) return;
  const progWrap = document.getElementById("upload-progress-wrap");
  const progText = document.getElementById("upload-progress-text");
  const progBar = document.getElementById("upload-progress-bar");
  progWrap.style.display = "block";

  let latestFiles = [];
  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    progText.textContent = `Uploading ${file.name} (${i + 1}/${fileList.length})...`;
    progBar.style.width = `${Math.round(((i + 0.4) / fileList.length) * 100)}%`;

    const res = await fetch("/api/upload-raw", {
      method: "POST",
      headers: {
        "X-Filename": file.name,
        "Content-Type": "application/octet-stream",
      },
      body: file,
    });
    const data = await res.json();
    if (!res.ok) {
      alert(`Upload failed for ${file.name}: ${data.error}`);
    } else {
      latestFiles = data.uploaded_files || [];
    }
    progBar.style.width = `${Math.round(((i + 1) / fileList.length) * 100)}%`;
  }

  progText.textContent = "Upload complete. Ready to split & analyze.";
  renderUploadedFiles(latestFiles);
  document.getElementById("sidebar-job-badge").textContent = `Queued: ${latestFiles.length} file(s)`;
}

const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("file-input");
document.getElementById("btn-browse-files").onclick = () => fileInput.click();
fileInput.onchange = () => uploadFiles(fileInput.files);

dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  uploadFiles(e.dataTransfer.files);
});

// Execution mode switcher (Train & Test vs Direct Test Demo)
const runModeSelect = document.getElementById("run-mode-select");
function syncRunModeUI() {
  const mode = runModeSelect ? runModeSelect.value : "train_and_test";
  const descEl = document.getElementById("run-mode-desc");
  const startBtn = document.getElementById("btn-start-analysis");
  const stepper = document.getElementById("pipeline-stepper");

  if (mode === "test_only") {
    descEl.textContent = "Skips Train/Test splitting and model training; runs Fixed Rules + pre-trained Isolation Forest directly on all uploaded logs.";
    startBtn.textContent = "Run Direct Test Analysis (Demo)";
    stepper.innerHTML = `
      <div class="step-chip" data-step="1">1. Parse Raw Logs</div>
      <div class="step-chip" data-step="2">2. Feature &amp; Graph Eng.</div>
      <div class="step-chip" data-step="3">3. Rules + Pre-trained ML</div>
      <div class="step-chip" data-step="4">4. Build Graphs &amp; Eval</div>
    `;
  } else {
    descEl.textContent = "Splits parsed logs 70/30 chronologically, trains Isolation Forest on Train, and detects lateral movement on Test.";
    startBtn.textContent = "Run Lateral Movement Analysis";
    stepper.innerHTML = `
      <div class="step-chip" data-step="1">1. Parse Raw Logs</div>
      <div class="step-chip" data-step="2">2. Train/Test Split</div>
      <div class="step-chip" data-step="3">3. Feature &amp; Graph Eng.</div>
      <div class="step-chip" data-step="4">4. Train AI on Train</div>
      <div class="step-chip" data-step="5">5. Detect on Test</div>
      <div class="step-chip" data-step="6">6. Build Graphs &amp; Eval</div>
    `;
  }
}
if (runModeSelect) {
  runModeSelect.addEventListener("change", syncRunModeUI);
  syncRunModeUI();
}

// Stepper update from logs
function updateStepperFromLogs(logs, status) {
  const joined = (logs || []).join("\n");
  const isDirectTest = joined.includes("--no-split") || (runModeSelect && runModeSelect.value === "test_only");
  let active = 0;

  if (isDirectTest) {
    if (joined.includes("[Step 1]")) active = 1;
    if (joined.includes("[Step 2]")) active = 2;
    if (joined.includes("[Step 3]") || joined.includes("[Step 4]")) active = 3;
    if (joined.includes("[Step 6]") || joined.includes("[Step 7]") || joined.includes("[Step 8]")) active = 4;
  } else {
    if (joined.includes("[Step 1]")) active = 1;
    if (joined.includes("[Step 2]")) active = 2;
    if (joined.includes("[Step 3]")) active = 3;
    if (joined.includes("[Step 4]")) active = 4;
    if (joined.includes("[Step 5]")) active = 5;
    if (joined.includes("[Step 6]") || joined.includes("[Step 7]") || joined.includes("[Step 8]")) active = 6;
  }

  document.querySelectorAll(".step-chip").forEach((el) => {
    const s = Number(el.dataset.step);
    el.classList.remove("active", "done");
    if (status === "completed") {
      el.classList.add("done");
    } else if (s < active) {
      el.classList.add("done");
    } else if (s === active) {
      el.classList.add("active");
    }
  });
}

async function pollJob() {
  const snap = await apiGet("/api/jobs/status");
  document.getElementById("job-status-badge").textContent = snap.status;
  document.getElementById("sidebar-job-badge").textContent = `Job: ${snap.status}`;
  document.getElementById("job-elapsed").textContent = snap.elapsed_seconds != null ? `${snap.elapsed_seconds}s` : "0.0s";
  const term = document.getElementById("job-terminal");
  if (snap.logs && snap.logs.length) {
    term.textContent = snap.logs.join("\n");
    term.scrollTop = term.scrollHeight;
  }
  updateStepperFromLogs(snap.logs, snap.status);

  if (snap.status !== "running" && jobPollTimer) {
    clearInterval(jobPollTimer);
    jobPollTimer = null;
    if (snap.status === "completed") {
      await loadResults();
      await loadAlerts();
      await queryParsedLogs();
      await previewRaw().catch(() => {});
      switchTab("results");
    }
  }
}

document.getElementById("btn-start-analysis").onclick = async () => {
  try {
    const mode = runModeSelect ? runModeSelect.value : "train_and_test";
    await apiPost("/api/pipeline/analyze", {
      mode,
      train_ratio: 0.70,
      split_mode: "window",
    });
    if (!jobPollTimer) jobPollTimer = setInterval(pollJob, 800);
    await pollJob();
  } catch (err) {
    alert(err.message);
  }
};

document.getElementById("btn-reset-session").onclick = async () => {
  try {
    await apiPost("/api/session/reset", {});
    renderUploadedFiles([]);
    document.getElementById("upload-progress-wrap").style.display = "none";
    document.getElementById("job-terminal").textContent = "Session reset. Upload raw .log file(s) to start a new analysis.";
    document.getElementById("job-status-badge").textContent = "idle";
    document.getElementById("sidebar-job-badge").textContent = "Status: Waiting for upload";
    document.querySelectorAll(".step-chip").forEach((el) => el.classList.remove("active", "done"));
    await loadResults();
    switchTab("upload");
  } catch (err) {
    alert(err.message);
  }
};

async function loadResults() {
  const data = await apiGet("/api/overview");
  const emptyEl = document.getElementById("results-empty-state");
  const contentEl = document.getElementById("results-content");

  if (!data.has_results) {
    emptyEl.style.display = "block";
    contentEl.style.display = "none";
    document.getElementById("session-badge").innerHTML = `<span class="pulse-dot"></span> Clean Session Ready`;
    return;
  }

  emptyEl.style.display = "none";
  contentEl.style.display = "block";
  document.getElementById("session-badge").innerHTML = `<span class="pulse-dot"></span> Results Ready`;

  const sp = data.split || {};
  const totalEvents = sp.total_events || data.parsed_events_count || 0;
  const isDirectTest = sp.split_mode === "none";

  document.getElementById("res-total-events").textContent = fmtNum(totalEvents);
  const trainCard = document.getElementById("res-train-card");
  const testLabel = document.getElementById("res-test-label");

  if (isDirectTest) {
    trainCard.style.display = "none";
    testLabel.textContent = "Analysis Mode";
    document.getElementById("res-test-split").textContent = "Direct Test (No Split — Pre-trained Model)";
    document.getElementById("kpi-alerts-label").textContent = "Alerts Triggered";
    document.getElementById("risk-table-title").textContent = "Prioritized Threat Windows";
    document.getElementById("alert-feed-title").textContent = "Merged Alert Feed";
  } else {
    trainCard.style.display = "";
    testLabel.textContent = "Test Split";
    document.getElementById("res-train-split").textContent = `${fmtNum(sp.train_events || 0)} / ${fmtNum(totalEvents)}`;
    document.getElementById("res-test-split").textContent = `${fmtNum(sp.test_events || 0)} / ${fmtNum(totalEvents)}`;
    document.getElementById("kpi-alerts-label").textContent = "Test Alerts Triggered";
    document.getElementById("risk-table-title").textContent = "Prioritized Test Threat Windows";
    document.getElementById("alert-feed-title").textContent = "Test-Set Merged Alert Feed";
  }

  document.getElementById("kpi-alerts").textContent = fmtNum(data.alert_summary.total);
  const critCount = (data.risk_scores || []).filter((r) => r.priority === "CRITICAL").length;
  document.getElementById("kpi-critical-count").textContent = `${critCount} CRITICAL threat windows`;

  const ens = data.evaluation?.ensemble_at_medium_threshold;
  if (ens) {
    document.getElementById("kpi-f1").textContent = Number(ens.f1).toFixed(3);
    document.getElementById("kpi-prec-rec").textContent = `Precision: ${Number(ens.precision).toFixed(3)} | Recall: ${Number(ens.recall).toFixed(3)}`;
    document.getElementById("kpi-auc").textContent = `${Number(ens.roc_auc ?? 0).toFixed(3)} / ${Number(ens.pr_auc ?? 0).toFixed(3)}`;
    document.getElementById("kpi-cm").textContent = `TP: ${ens.tp} | FP: ${ens.fp} | FN: ${ens.fn}`;
  } else {
    document.getElementById("kpi-f1").textContent = "Unlabeled";
    document.getElementById("kpi-prec-rec").textContent = "No ground truth file for uploaded logs";
    document.getElementById("kpi-auc").textContent = "N/A";
    document.getElementById("kpi-cm").textContent = "Anomaly scoring completed";
  }

  // Charts gallery
  const ts = Date.now();
  const chartsGrid = document.getElementById("charts-grid");
  chartsGrid.innerHTML = data.charts.length
    ? data.charts
        .map(
          (c) => `<div class="chart-card" onclick="openChartModal('/api/visualizations/${encodeURIComponent(c)}?t=${ts}')">
            <h3>${esc(c.replace(/_/g, " ").replace(".png", "").toUpperCase())}</h3>
            <img src="/api/visualizations/${encodeURIComponent(c)}?t=${ts}" alt="${esc(c)}" />
          </div>`
        )
        .join("")
    : `<div class="help-text">No visualization charts generated for this run.</div>`;

  // Risk table
  document.getElementById("risk-window-count").textContent = `${data.risk_scores.length} windows`;
  document.getElementById("risk-table-body").innerHTML = data.risk_scores
    .map(
      (r) => `<tr>
        <td><strong>${esc(r.user)}</strong></td>
        <td class="mono">${esc(r.time_window)}</td>
        <td><strong>${esc(r.risk_score)}</strong></td>
        <td><span class="badge badge-${esc(r.priority)}">${esc(r.priority)}</span></td>
        <td class="mono">${esc(r.detectors_triggered)}</td>
        <td>${esc(r.alert_count)}</td>
      </tr>`
    )
    .join("");

  // Detector breakdown
  const perDet = data.evaluation?.per_detector || {};
  const bySource = data.alert_summary.by_source || {};
  document.getElementById("detector-breakdown").innerHTML = ["Rule-based", "ML"]
    .map((name) => {
      const cnt = bySource[name] || 0;
      const m = perDet[name];
      const statsText = m
        ? `TP:${m.tp} FP:${m.fp} FN:${m.fn} | P:${Number(m.precision).toFixed(2)} R:${Number(m.recall).toFixed(2)} F1:${Number(m.f1).toFixed(2)}`
        : `${fmtNum(cnt)} ${isDirectTest ? "alerts" : "alerts on Test split"}`;
      const pct = m ? Math.round(Number(m.f1) * 100) : Math.min(100, cnt * 5);
      return `<div class="breakdown-row">
        <div class="breakdown-top">
          <span>${esc(name)}</span>
          <span class="mono">${fmtNum(cnt)} alerts — ${esc(statsText)}</span>
        </div>
        <div class="bar-bg"><div class="bar-fill" style="width:${pct}%"></div></div>
      </div>`;
    })
    .join("");
}

async function loadAlerts() {
  const qs = new URLSearchParams({
    priority: document.getElementById("filter-priority").value,
    source: document.getElementById("filter-source").value,
    user: document.getElementById("filter-user").value,
    limit: "200",
  });
  const data = await apiGet(`/api/alerts?${qs}`);
  document.getElementById("alerts-table-body").innerHTML = (data.alerts || [])
    .map(
      (a) => `<tr>
        <td class="mono">${esc(a.timestamp)}</td>
        <td><strong>${esc(a.user)}</strong></td>
        <td class="mono">${esc(a.host || "—")}</td>
        <td>${esc(a.source)}</td>
        <td>${esc(a.alert_type)}</td>
        <td>${esc(a.risk_score)}</td>
        <td><span class="badge badge-${esc(a.priority)}">${esc(a.priority)}</span></td>
        <td class="mono">${esc(a.details)}</td>
      </tr>`
    )
    .join("");
}

async function previewRaw() {
  const fname = document.getElementById("raw-file-select").value;
  if (!fname) return;
  const res = await apiGet(`/api/logs/raw?file=${encodeURIComponent(fname)}&lines=35`);
  document.getElementById("raw-log-preview").textContent = (res.lines || []).join("\n") || "(empty file)";
}

async function queryParsedLogs() {
  const qs = new URLSearchParams({
    source: document.getElementById("parsed-source-filter").value,
    user: document.getElementById("parsed-user-filter").value,
    event_id: document.getElementById("parsed-eid-filter").value,
    limit: "100",
  });
  const res = await apiGet(`/api/logs/parsed?${qs}`);
  document.getElementById("parsed-logs-body").innerHTML = (res.logs || [])
    .map(
      (r) => `<tr>
        <td class="mono">${esc(r.timestamp)}</td>
        <td><span class="badge badge-neutral">${esc(r.log_source)}</span></td>
        <td><strong>${esc(r.user)}</strong></td>
        <td class="mono">${esc(r.host)}</td>
        <td class="mono">${esc(r.event_id)}</td>
        <td class="mono">${esc(r.process_name)}</td>
        <td class="mono">${esc(r.command_line)}</td>
        <td class="mono">${esc(r.source_ip)}</td>
      </tr>`
    )
    .join("");
}

window.openChartModal = (src) => {
  document.getElementById("modal-img").src = src;
  document.getElementById("chart-modal").classList.add("open");
};
document.getElementById("modal-close-btn").onclick = () => document.getElementById("chart-modal").classList.remove("open");
document.getElementById("modal-close-bg").onclick = () => document.getElementById("chart-modal").classList.remove("open");

document.getElementById("btn-apply-alert-filters").onclick = loadAlerts;
document.getElementById("btn-preview-raw").onclick = previewRaw;
document.getElementById("btn-query-parsed").onclick = queryParsedLogs;

// Clean startup init
async function init() {
  const sess = await apiGet("/api/session");
  renderUploadedFiles(sess.uploaded_files || []);
  await loadResults();
  if (sess.has_results) {
    await loadAlerts();
    await queryParsedLogs();
  }
}
init();
