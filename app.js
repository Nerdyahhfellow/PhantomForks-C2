(function () {
  "use strict";

  const state = { apkFile: null, result: null, loading: false, primaryCase: null, viewingDropped: null };

  const el = (id) => document.getElementById(id);

  // ---------------- Theme toggle ----------------

  const THEME_KEY = "third-eye-theme";

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }

  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    applyTheme(saved || (prefersDark ? "dark" : "light"));
  }

  initTheme();

  el("theme-toggle").addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme");
    applyTheme(current === "dark" ? "light" : "dark");
  });

  // ---------------- Intake: dropzones ----------------

  function setupDropzone(zoneId, inputId, filenameId, onFile) {
    const zone = el(zoneId);
    const input = el(inputId);
    const filenameEl = el(filenameId);

    zone.addEventListener("click", () => input.click());

    input.addEventListener("change", () => {
      if (input.files && input.files[0]) handleFile(input.files[0]);
    });

    ["dragenter", "dragover"].forEach((evt) =>
      zone.addEventListener(evt, (e) => {
        e.preventDefault();
        zone.classList.add("drag-over");
      })
    );
    ["dragleave", "drop"].forEach((evt) =>
      zone.addEventListener(evt, (e) => {
        e.preventDefault();
        zone.classList.remove("drag-over");
      })
    );
    zone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) handleFile(file);
    });

    function handleFile(file) {
      filenameEl.textContent = file.name;
      filenameEl.hidden = false;
      zone.classList.add("has-file");
      onFile(file);
      clearError();
      updateDockSummary();
    }
  }

  setupDropzone("apk-dropzone", "apk-input", "apk-filename", (file) => {
    state.apkFile = file;
    updateRunButton();
  });

  function updateRunButton() {
    el("run-analysis-btn").disabled = !state.apkFile || state.loading;
  }

  function setLoading(loading) {
    state.loading = loading;
    const btn = el("run-analysis-btn");
    btn.querySelector(".btn-label").hidden = loading;
    btn.querySelector(".btn-spinner").hidden = !loading;
    btn.disabled = loading || !state.apkFile;
  }

  function showError(msg) {
    const errEl = el("intake-error");
    errEl.textContent = msg;
    errEl.hidden = false;
  }

  function clearError() {
    el("intake-error").hidden = true;
    el("intake-error").textContent = "";
  }

  el("run-analysis-btn").addEventListener("click", () => {
    if (!state.apkFile || state.loading) return;
    clearError();

    const formData = new FormData();
    formData.append("apk", state.apkFile);

    setLoading(true);

    fetch("/api/analyze", { method: "POST", body: formData })
      .then((res) => res.json().then((data) => ({ ok: res.ok, data })))
      .then(({ ok, data }) => {
        setLoading(false);
        if (!ok) {
          showError(data.error || "Analysis failed.");
          return;
        }
        state.result = data;
        state.primaryCase = data;
        state.viewingDropped = null;
        enterResultsView(data);
        if (data.dynamic_job_id) {
          showDynamicProgress();
          pollDynamicJob(data.dynamic_job_id);
        }
      })
      .catch((err) => {
        setLoading(false);
        showError("Could not reach the server: " + err.message);
      });
  });

  el("new-case-btn").addEventListener("click", () => {
    state.apkFile = null;
    state.result = null;
    el("apk-filename").hidden = true;
    el("apk-dropzone").classList.remove("has-file");
    el("apk-input").value = "";
    clearError();
    updateRunButton();
    if (dynamicPollTimer) clearInterval(dynamicPollTimer);
    hideDynamicProgress();
    clearDynamicError();
    exitResultsView();
  });

  function updateDockSummary() {
    const parts = [];
    if (state.apkFile) parts.push(state.apkFile.name);
    el("intake-dock-summary").textContent = parts.length ? parts.join(" · ") : "—";
  }

  function enterResultsView(data) {
    document.body.classList.add("app-has-results");
    el("intake-view").classList.add("intake-minimized");
    el("intake-collapsed-bar").hidden = false;
    updateDockSummary();
    renderDashboard(data);
    el("dashboard-view").hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function exitResultsView() {
    document.body.classList.remove("app-has-results");
    el("intake-view").classList.remove("intake-minimized");
    el("intake-collapsed-bar").hidden = true;
    el("dashboard-view").hidden = true;
    el("case-id-display").hidden = true;
    document.querySelectorAll(".tab-btn").forEach((b, i) => b.classList.toggle("active", i === 0));
    document.querySelectorAll(".tab-panel").forEach((p, i) => p.classList.toggle("active", i === 0));
  }

  el("generate-report-btn").addEventListener("click", () => {
    if (!state.result) return;
    window.location.href = `/api/report/${state.result.case_id}/pdf`;
  });

  // ---------------- Dynamic analysis (emulator-driven) ----------------

  let dynamicPollTimer = null;

  const PROGRESS_STEPS = {
    queued: 5, starting_emulator: 15, installing_apk: 30, capturing_network: 40,
    launching_app: 50, simulating_interaction: 70, stopping_capture: 85,
    analyzing_traffic: 90, pulling_dropped_apk: 92, analyzing_dropped_apk_static: 94,
    analyzing_dropped_apk_dynamic: 96, cleaning_up: 97, resetting_device: 99,
    completed: 100, error: 100,
  };

  const PROGRESS_LABELS = {
    queued: "Queued…", starting_emulator: "Booting emulator…", installing_apk: "Installing APK…",
    capturing_network: "Starting network capture…", launching_app: "Launching app with runtime hooks…",
    simulating_interaction: "Simulating user interaction…", stopping_capture: "Stopping capture…",
    analyzing_traffic: "Analyzing captured traffic…",
    pulling_dropped_apk: "Retrieving dropped APK from device…",
    analyzing_dropped_apk_static: "Analyzing dropped APK (static)…",
    analyzing_dropped_apk_dynamic: "Analyzing dropped APK (dynamic)…",
    cleaning_up: "Cleaning up…",
    resetting_device: "Resetting virtual device…",
    completed: "Done.", error: "Failed.",
  };

  function showDynamicProgress() {
    el("dynamic-progress").hidden = false;
    el("dynamic-progress-fill").style.width = "5%";
    el("dynamic-progress-label").textContent = "Queued…";
    clearDynamicError();
  }

  function hideDynamicProgress() {
    el("dynamic-progress").hidden = true;
  }

  function showDynamicError(msg) {
    const errEl = el("dynamic-error");
    errEl.textContent = msg;
    errEl.hidden = false;
  }

  function clearDynamicError() {
    const errEl = el("dynamic-error");
    errEl.hidden = true;
    errEl.textContent = "";
  }

  function pollDynamicJob(jobId) {
    if (dynamicPollTimer) clearInterval(dynamicPollTimer);
    dynamicPollTimer = setInterval(() => {
      fetch(`/api/dynamic-analyze/status/${jobId}`)
        .then((res) => res.json())
        .then((data) => {
          const pct = PROGRESS_STEPS[data.progress] ?? PROGRESS_STEPS[data.status] ?? 10;
          el("dynamic-progress-fill").style.width = pct + "%";
          el("dynamic-progress-label").textContent = PROGRESS_LABELS[data.progress] || data.progress || "Working…";

          if (data.status === "completed") {
            clearInterval(dynamicPollTimer);
            hideDynamicProgress();
            state.result = data.result;
            state.primaryCase = data.result;
            state.viewingDropped = null;
            renderDashboard(data.result);
          } else if (data.status === "error") {
            clearInterval(dynamicPollTimer);
            hideDynamicProgress();
            console.error("Dynamic analysis job failed:", data.error);
            showDynamicError("Dynamic analysis failed: " + (data.error || "unknown error"));
          }
        })
        .catch((err) => {
          clearInterval(dynamicPollTimer);
          hideDynamicProgress();
          showDynamicError("Lost connection while polling dynamic analysis status: " + err.message);
        });
    }, 2000);
  }

  // ---------------- Tabs ----------------

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      const panel = el("tab-" + btn.dataset.tab);
      // Force a reflow before re-adding the class so the CSS animation
      // reliably restarts on every click, even switching back to a tab
      // whose animation already played once.
      panel.classList.remove("tab-panel-animate");
      void panel.offsetWidth;
      panel.classList.add("active", "tab-panel-animate");
    });
  });

  // ---------------- Rendering ----------------

  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  function renderDashboard(data) {
    const { static: s, network: n, correlation: c, verdict: v, case_id } = data;

    el("case-id-display").hidden = false;
    el("case-id-value").textContent = case_id.toUpperCase();

    const banner = el("dropped-context-banner");
    if (state.viewingDropped) {
      banner.hidden = false;
      el("dropped-context-label").textContent =
        `Viewing full report for dropped APK: ${s.app_name || s.package || "unnamed"}`;
    } else {
      banner.hidden = true;
    }

    // Each tab is rendered independently: a bad/unexpected shape in one
    // tab's data must never prevent the others from rendering. Before this,
    // renderDashboard called these in a single unbroken chain, so a single
    // uncaught exception partway through (e.g. in renderVerdict/Overview/
    // Permissions/etc.) silently aborted everything after it — including
    // renderDropped — leaving tab-dropped stuck at its blank initial
    // <section></section> from index.html with no visible error at all.
    safeRender("verdict", () => renderVerdict(v, s));
    safeRender("overview", () => renderOverview(s, n, c, data.has_pcap));
    safeRender("permissions", () => renderPermissions(s));
    safeRender("filetree", () => renderFileTree(s));
    safeRender("iocs", () => renderIOCs(s));
    safeRender("network", () => renderNetwork(n, data.has_pcap));
    safeRender("correlation", () => renderCorrelation(c, data.has_pcap));
    safeRender("timeline", () => renderTimeline(n, data.has_pcap));
    safeRender("dropped", () => renderDropped(n, data.has_pcap));
  }

  // Runs a single tab's render function; on failure, logs the real error to
  // the console (so it's actually diagnosable) and puts a visible message in
  // that tab instead of leaving it blank or breaking every tab after it.
  function safeRender(tabName, fn) {
    try {
      fn();
    } catch (e) {
      console.error(`Third Eye: rendering tab "${tabName}" failed:`, e);
      const panel = el("tab-" + tabName);
      if (panel) {
        panel.innerHTML = `<div class="panel-box"><div class="empty-state">
          Something went wrong rendering this tab (${esc(e.message || String(e))}).
          Check the browser console for details — other tabs are unaffected.
        </div></div>`;
      }
    }
  }

  // Fallback shapes for a dropped APK entry that's missing a piece the
  // primary case always has (e.g. dynamic analysis errored out, or an
  // older backend hadn't computed correlation/verdict yet), so
  // renderDashboard's destructuring never hits undefined.
  function emptyNetworkReport() {
    return { request_count: 0, destinations: [], beacons: [], timeline: [], network_score: 0, behaviors: [], evasion: {} };
  }
  function emptyCorrelation() {
    return { confirmed: [], dormant: [], unclaimed: [], verdict_notes: [] };
  }
  function emptyVerdict(reason) {
    return { risk_level: "safe", summary: reason || "Not yet scored.", flags: [] };
  }

  // Builds a synthetic "case" object out of one dropped-APK entry, shaped
  // exactly like a top-level case, so it can be run straight through the
  // same renderDashboard()/render* functions used for the primary scan.
  function buildCaseFromDropped(entry, index) {
    const dyn = entry.dynamic && !entry.dynamic.error ? entry.dynamic : null;
    return {
      case_id: `${(state.primaryCase && state.primaryCase.case_id) || "case"}-dropped-${index + 1}`,
      apk_path: entry.local_path,
      has_pcap: Boolean(entry.has_pcap && dyn),
      static: entry.static,
      network: dyn || emptyNetworkReport(),
      correlation: entry.correlation || emptyCorrelation(),
      verdict: entry.verdict || emptyVerdict(entry.verdict_error),
    };
  }

  el("back-to-primary-btn").addEventListener("click", () => {
    if (!state.primaryCase) return;
    state.viewingDropped = null;
    renderDashboard(state.primaryCase);
  });

  // v62's verdict.py (kept untouched, per request) still returns the older
  // verdict shape: { risk_score, risk_level: "low"/"medium"/"high"/"critical",
  // breakdown: [{label, detail, points}], top_flags }. This UI (from v66)
  // expects the newer Safe/Risky shape: { risk_level: "safe"/"risky", flags:
  // [{label, detail}] } — the CSS only defines .stamp.safe/.stamp.risky, and
  // there's no "flags" field on the old shape at all. Without this adapter,
  // every scan silently rendered as "SAFE" with no flags listed, regardless
  // of the actual score, since v.risk_level was never literally "risky" and
  // v.flags was always undefined. This translates old -> new in one place so
  // neither side has to change.
  function normalizeVerdict(v) {
    if (!v || typeof v !== "object") return emptyVerdict();
    if (v.risk_level === "safe" || v.risk_level === "risky") return v; // already new shape
    if (!("breakdown" in v) && !("risk_score" in v)) return v; // unrecognized shape, pass through
    const level = v.risk_level; // "low" | "medium" | "high" | "critical" | undefined
    return {
      risk_level: level && level !== "low" ? "risky" : "safe",
      summary: v.summary,
      flags: [...(v.breakdown || [])].sort((a, b) => (b.points || 0) - (a.points || 0)),
    };
  }

  function renderVerdict(rawV, s) {
    const v = normalizeVerdict(rawV);
    el("verdict-app-name").textContent = s.app_name || s.metadata.filename;
    el("verdict-package").textContent = s.package;
    el("verdict-summary").textContent = v.summary;

    const stamp = el("risk-stamp");
    stamp.textContent = v.risk_level === "risky" ? "RISKY" : "SAFE";
    stamp.className = "stamp " + v.risk_level;

    const flagsEl = el("verdict-flags");
    flagsEl.innerHTML = "";
    const flags = v.flags || [];
    if (!flags.length) {
      flagsEl.innerHTML = `<div class="empty-state">No specific risk indicators to list.</div>`;
      return;
    }
    const list = document.createElement("ul");
    list.className = "flag-list";
    flags.forEach((f) => {
      const li = document.createElement("li");
      li.className = "flag-item";
      li.innerHTML = `${esc(f.label)}${f.detail ? " — " + esc(f.detail) : ""}`;
      list.appendChild(li);
    });
    flagsEl.appendChild(list);
  }

  function renderOverview(s, n, c, hasPcap) {
    const meta = s.metadata;
    const analysisMode = hasPcap
      ? "Static + dynamic (combined)"
      : "Static complete — dynamic analysis running or unavailable";
    const evasion = n.evasion || { attempted: false, confidence: "none" };
    const droppedCount = (n.dropped_apks || []).length;

    const html = `
      <div class="panel-box">
        <h3>Scan Summary</h3>
        <div class="kv-grid">
          <div class="kv-item"><span class="kv-label">Mode</span><span class="kv-value">${esc(analysisMode)}</span></div>
          <div class="kv-item"><span class="kv-label">App name</span><span class="kv-value">${esc(s.app_name)}</span></div>
          <div class="kv-item"><span class="kv-label">Package</span><span class="kv-value">${esc(s.package)}</span></div>
          <div class="kv-item"><span class="kv-label">Version</span><span class="kv-value">${esc(s.version_name)} (code ${esc(s.version_code)})</span></div>
          <div class="kv-item"><span class="kv-label">Min / Target SDK</span><span class="kv-value">${esc(s.min_sdk)} / ${esc(s.target_sdk)}</span></div>
          <div class="kv-item"><span class="kv-label">File size</span><span class="kv-value">${(meta.size_bytes/1024).toFixed(1)} KB</span></div>
          <div class="kv-item kv-wide"><span class="kv-label">SHA-256</span><span class="kv-value">${esc(meta.sha256)}</span></div>
        </div>
      </div>
      <div class="panel-box">
        <h3>Findings at a Glance</h3>
        <div class="stat-cards">
          <div class="stat-card"><span class="stat-value">${s.dangerous_permissions.length}</span><span class="stat-label">Dangerous permissions</span></div>
          <div class="stat-card"><span class="stat-value">${s.exported_components.filter(x=>x.issue).length}</span><span class="stat-label">Unguarded exports</span></div>
          <div class="stat-card"><span class="stat-value">${s.iocs.ips.length + s.iocs.urls.length}</span><span class="stat-label">Embedded IOCs</span></div>
          <div class="stat-card"><span class="stat-value">${n.request_count}</span><span class="stat-label">HTTP requests</span></div>
          <div class="stat-card"><span class="stat-value">${n.beacons.length}</span><span class="stat-label">Beacon patterns</span></div>
          <div class="stat-card"><span class="stat-value">${c.unclaimed.length}</span><span class="stat-label">Unclaimed hosts</span></div>
          <div class="stat-card"><span class="stat-value">${evasion.attempted ? "Yes (" + evasion.confidence + ")" : "No"}</span><span class="stat-label">Emulator/sandbox detection attempted</span></div>
          <div class="stat-card"><span class="stat-value">${droppedCount}</span><span class="stat-label">Dropped APK(s) found</span></div>
        </div>
      </div>`;
    el("tab-overview").innerHTML = html;
  }

  function renderPermissions(s) {
    const rows = s.dangerous_permissions.map(p => `
      <div class="perm-row">
        <span class="perm-name">${esc(p.permission.split(".").pop())}</span>
        <span class="perm-reason">${esc(p.reason)}</span>
      </div>`).join("");

    const mismatch = s.category_mismatch
      ? `<div class="verdict-notes">${esc(s.category_mismatch)}</div>` : "";

    const exported = s.exported_components.filter(f => f.issue).map(f => `
      <div class="perm-row">
        <span class="perm-name">${esc(f.type)}</span>
        <span class="perm-reason">${esc(f.name)} — ${esc(f.issue)}</span>
      </div>`).join("");

    el("tab-permissions").innerHTML = `
      <div class="panel-box">
        <h3>Dangerous Permissions <span class="count-badge">${s.dangerous_permissions.length}</span></h3>
        ${rows || '<div class="empty-state">No dangerous permissions declared.</div>'}
        ${mismatch}
      </div>
      <div class="panel-box">
        <h3>Exported Components Without Permission Guard <span class="count-badge">${s.exported_components.filter(f=>f.issue).length}</span></h3>
        ${exported || '<div class="empty-state">No unguarded exported components found.</div>'}
      </div>
      <div class="panel-box">
        <h3>All Declared Permissions <span class="count-badge">${s.declared_permissions.length}</span></h3>
        <div class="ioc-list">${s.declared_permissions.map(p => `<div class="ioc-item">${esc(p)}</div>`).join("") || '<div class="empty-state">None declared.</div>'}</div>
      </div>`;
  }

  function renderFileTreeNode(node) {
    if (node.type === "file") {
      const risky = /\.(dex|so)$/i.test(node.name);
      return `<li class="ft-file${risky ? ' risky' : ''}">${esc(node.name)} <span class="ft-size">(${node.size} B)</span></li>`;
    }
    const children = (node.children || []).map(renderFileTreeNode).join("");
    return `<li class="ft-dir">${esc(node.name)}<ul>${children}</ul></li>`;
  }

  function renderFileTree(s) {
    el("tab-filetree").innerHTML = `
      <div class="panel-box filetree">
        <h3>Archive Contents</h3>
        <ul>${(s.file_tree.children || []).map(renderFileTreeNode).join("")}</ul>
      </div>`;
  }

  function iocBlock(title, items) {
    return `
      <div class="panel-box">
        <h3>${title} <span class="count-badge">${items.length}</span></h3>
        <div class="ioc-list">${items.map(i => `<div class="ioc-item">${esc(i)}</div>`).join("") || '<div class="empty-state">None found.</div>'}</div>
      </div>`;
  }

  function renderIOCs(s) {
    const i = s.iocs;
    el("tab-iocs").innerHTML =
      iocBlock("Embedded URLs", i.urls) +
      iocBlock("Raw IP Addresses", i.ips) +
      iocBlock("Suspicious Keywords", i.suspicious_keywords) +
      iocBlock("Email Addresses", i.emails) +
      iocBlock("Wallet Addresses", i.wallet_addresses) +
      iocBlock("Tokens / Secrets", i.tokens_secrets) +
      (s.signing.length ? `<div class="panel-box"><h3>Signing Certificate Issues</h3><div class="ioc-list">${s.signing.map(x=>`<div class="ioc-item">${esc(x)}</div>`).join("")}</div></div>` : "");
  }

  function scoreBadgeClass(score) {
    if (score >= 5) return "s-high";
    if (score >= 3) return "s-mid";
    return "s-low";
  }

  function behaviorSeverityClass(sev) {
    if (sev === "critical" || sev === "high") return "s-high";
    if (sev === "medium") return "s-mid";
    return "s-low";
  }

  function renderNetwork(n, hasPcap) {
    if (!hasPcap) {
      el("tab-network").innerHTML = `<div class="panel-box"><div class="empty-state">No network data yet — dynamic analysis runs automatically after the scan and populates this tab once it completes. If it's been a while, check for an error message above.</div></div>`;
      return;
    }
    const destRows = n.destinations.map(d => `
      <tr><td>${esc(d.host)}</td><td>${esc(d.ip)}</td><td>${d.request_count}</td></tr>
    `).join("");

    const beaconRows = n.beacons.map(b => `
      <tr>
        <td>${esc(b.host)}${esc(b.path)}</td>
        <td>${b.hits}</td>
        <td>${b.mean_interval.toFixed(1)}s</td>
        <td>${(b.jitter_ratio*100).toFixed(1)}%</td>
        <td><span class="badge-score ${scoreBadgeClass(b.score)}">${b.score}</span></td>
        <td>${esc(b.reasons.join("; "))}</td>
      </tr>`).join("");

    const behaviors = n.behaviors || [];
    const behaviorRows = behaviors.map(b => `
      <tr>
        <td><span class="badge-score ${behaviorSeverityClass(b.severity)}">${esc(b.severity)}</span></td>
        <td>${esc((b.type || "").replace(/_/g, " "))}</td>
        <td>${esc(b.description)}</td>
      </tr>`).join("");

    const behaviorPanel = behaviors.length ? `
      <div class="panel-box">
        <h3>Runtime Behaviors (Frida) <span class="count-badge">${behaviors.length}</span></h3>
        <div class="table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>${behaviorRows}</tbody></table></div>
      </div>` : "";

    el("tab-network").innerHTML = `
      ${behaviorPanel}
      <div class="panel-box">
        <h3>Beaconing Patterns <span class="count-badge">${n.beacons.length}</span></h3>
        ${n.beacons.length ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Host + Path</th><th>Hits</th><th>Avg Interval</th><th>Jitter</th><th>Score</th><th>Reasons</th></tr></thead><tbody>${beaconRows}</tbody></table></div>` : '<div class="empty-state">No beacon-like patterns detected.</div>'}
      </div>
      <div class="panel-box">
        <h3>All Destinations Contacted <span class="count-badge">${n.destinations.length}</span></h3>
        <div class="table-wrap"><table class="data-table"><thead><tr><th>Host</th><th>IP</th><th>Requests</th></tr></thead><tbody>${destRows || '<tr><td colspan="3" class="empty-state">No HTTP requests captured.</td></tr>'}</tbody></table></div>
      </div>`;
  }

  function renderCorrelation(c, hasPcap) {
    if (!hasPcap) {
      el("tab-correlation").innerHTML = `<div class="panel-box"><div class="empty-state">Correlation compares static IOCs against observed traffic from the dynamic analysis run. This will populate automatically once that run completes.</div></div>`;
      return;
    }
    const section = (cls, title, items, note) => `
      <div class="correlation-section ${cls}">
        <h4>${title} (${items.length})</h4>
        ${items.map(i => `<div class="corr-item"><span class="corr-host">${esc(i.host)}</span>${i.request_count ? ` — ${i.request_count} request(s)` : ""}<span class="corr-note">${esc(i.note)}</span></div>`).join("") || `<div class="empty-state">${note}</div>`}
      </div>`;

    el("tab-correlation").innerHTML = `
      <div class="panel-box">
        <h3>Static vs. Observed Behavior</h3>
        ${section("confirmed", "Confirmed", c.confirmed, "No hardcoded destinations were confirmed contacted.")}
        ${section("dormant", "Dormant", c.dormant, "No dormant hardcoded destinations.")}
        ${section("unclaimed", "Unclaimed", c.unclaimed, "No unclaimed runtime destinations.")}
        ${c.verdict_notes.length ? `<div class="verdict-notes">${c.verdict_notes.map(esc).join("<br>")}</div>` : ""}
      </div>`;
  }

  function renderTimeline(n, hasPcap) {
    if (!hasPcap || !n.timeline.length) {
      el("tab-timeline").innerHTML = `<div class="panel-box"><div class="empty-state">No timeline data available for this case.</div></div>`;
      return;
    }
    const t0 = n.timeline[0].time;
    const rows = n.timeline.map(r => `
      <div class="timeline-item">
        <span class="timeline-time">+${(r.time - t0).toFixed(1)}s</span>
        <span class="timeline-method">${esc(r.method)}</span>
        <span class="timeline-host">${esc(r.host)}</span>
        <span class="timeline-path">${esc(r.path)}</span>
      </div>`).join("");
    el("tab-timeline").innerHTML = `<div class="panel-box"><h3>Request Timeline <span class="count-badge">${n.timeline.length}</span></h3>${rows}</div>`;
  }
  function renderDropped(n, hasPcap) {
    if (!hasPcap) {
      el("tab-dropped").innerHTML = `<div class="panel-box"><div class="empty-state">This tab shows anti-emulator/root checks and any second-stage APK the sample dropped and installed itself. It populates automatically once dynamic analysis completes.</div></div>`;
      return;
    }

    const fridaBanner = n.frida_installed === false ? `
      <div class="panel-box" style="border-left: 3px solid #e0a030;">
        <h3 style="margin-top:0;">⚠ Frida is not installed</h3>
        <p>Runtime instrumentation was skipped for this entire run — no SMS/crypto/emulator-detection
        hooks, and the hook-based half of dropped-APK detection, were never active. The app ran with
        network capture only. On the machine running <code>app.py</code>, install it with:</p>
        <p><code>pip install frida frida-tools</code></p>
        <p>then re-run the scan. (The filesystem sweep for dropped APKs still runs either way — see below.)</p>
      </div>` : "";

    const evasion = n.evasion || { attempted: false, confidence: "none", signals: [] };
    const evasionRows = (evasion.signals || []).map(sig => `
      <tr>
        <td><span class="badge-score ${behaviorSeverityClass(sig.severity)}">${esc(sig.severity)}</span></td>
        <td>${esc((sig.type || "").replace(/_/g, " "))}</td>
        <td>${esc(sig.description)}</td>
      </tr>`).join("");

    const evasionPanel = `
      <div class="panel-box">
        <h3>Real-Device vs. Emulator Detection</h3>
        <p>${evasion.attempted
          ? `This sample actively checked for signs it's running in an emulator or sandbox (confidence: <strong>${esc(evasion.confidence)}</strong>) — a common evasion technique to hide malicious behavior from automated analysis.`
          : `No emulator/sandbox-detection or root-check API calls were observed during this run.`}</p>
        ${evasion.signals && evasion.signals.length
          ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>${evasionRows}</tbody></table></div>`
          : ""}
      </div>`;

    const dropped = n.dropped_apks || [];
    let droppedPanel;
    if (!dropped.length) {
      droppedPanel = `<div class="panel-box"><h3>Dropped / Downloaded APK</h3><div class="empty-state">No file matching a second-stage APK was written to disk during this run.</div></div>`;
    } else {
      droppedPanel = dropped.map((d, i) => {
        if (d.error) {
          return `<div class="panel-box">
            <h3>Dropped APK ${i + 1} — ${esc(d.source_path_on_device)}</h3>
            <div class="empty-state">${esc(d.error)}</div>
          </div>`;
        }
        const st = d.static;
        const dyn = d.dynamic;
        const staticBlock = st ? `
          <div class="kv-grid">
            <div class="kv-item"><span class="kv-label">Package</span><span class="kv-value">${esc(st.package)}</span></div>
            <div class="kv-item"><span class="kv-label">App name</span><span class="kv-value">${esc(st.app_name)}</span></div>
            <div class="kv-item"><span class="kv-label">Static risk score</span><span class="kv-value">${esc(st.risk_score)}/10</span></div>
            <div class="kv-item"><span class="kv-label">Dangerous permissions</span><span class="kv-value">${st.dangerous_permissions.length}</span></div>
            <div class="kv-item"><span class="kv-label">Embedded IOCs</span><span class="kv-value">${st.iocs.ips.length + st.iocs.urls.length}</span></div>
            <div class="kv-item kv-wide"><span class="kv-label">SHA-256</span><span class="kv-value">${esc(st.metadata.sha256)}</span></div>
          </div>` : `<div class="empty-state">${esc(d.static_error || "Static analysis unavailable.")}</div>`;

        let dynBlock = `<div class="empty-state">${esc(d.dynamic_error || "Dynamic analysis unavailable for this dropped APK.")}</div>`;
        if (dyn && !dyn.error) {
          const dynBehaviors = (dyn.behaviors || []).map(b => `
            <tr>
              <td><span class="badge-score ${behaviorSeverityClass(b.severity)}">${esc(b.severity)}</span></td>
              <td>${esc((b.type || "").replace(/_/g, " "))}</td>
              <td>${esc(b.description)}</td>
            </tr>`).join("");
          dynBlock = `
            ${dyn.launch_method ? `<p class="launch-method-note">Started via <strong>${esc(dyn.launch_method)}</strong>${dyn.hooks_attached ? " — runtime hooks attached." : ""}</p>` : ""}
            ${dyn.note ? `<div class="empty-state">${esc(dyn.note)}</div>` : ""}
            <div class="kv-grid">
              <div class="kv-item"><span class="kv-label">HTTP requests</span><span class="kv-value">${dyn.request_count}</span></div>
              <div class="kv-item"><span class="kv-label">Beacon patterns</span><span class="kv-value">${(dyn.beacons || []).length}</span></div>
              <div class="kv-item"><span class="kv-label">Emulator detection attempted</span><span class="kv-value">${dyn.evasion && dyn.evasion.attempted ? "Yes" : "No"}</span></div>
            </div>
            ${dynBehaviors ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Type</th><th>Description</th></tr></thead><tbody>${dynBehaviors}</tbody></table></div>` : ""}`;
        } else if (dyn && dyn.error) {
          dynBlock = `<div class="empty-state">${esc(dyn.error)}</div>`;
        }

        const furtherNote = dyn && dyn.further_dropped_apk_paths && dyn.further_dropped_apk_paths.length
          ? `<div class="empty-state">This dropped APK itself wrote what looks like a further ${dyn.further_dropped_apk_paths.length > 1 ? "third-stage payloads" : "third-stage payload"} to disk (${dyn.further_dropped_apk_paths.map(esc).join(", ")}), but Third Eye caps automatic analysis at one level deep — worth pulling and reviewing manually.</div>`
          : "";

        const canViewFull = Boolean(st);
        const viewFullBtn = canViewFull
          ? `<button class="btn-secondary view-full-dropped-btn" data-dropped-index="${i}">View Full Report →</button>`
          : "";

        return `
          <div class="panel-box">
            <h3>Dropped APK ${i + 1} <span class="count-badge">from ${esc(d.source_path_on_device)}</span></h3>
            <h4>Static Analysis</h4>
            ${staticBlock}
            <h4>Dynamic Analysis (short follow-up run)</h4>
            ${dynBlock}
            ${furtherNote}
            ${viewFullBtn}
          </div>`;
      }).join("");
    }

    el("tab-dropped").innerHTML = fridaBanner + evasionPanel + droppedPanel;

    el("tab-dropped").querySelectorAll(".view-full-dropped-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const idx = Number(btn.dataset.droppedIndex);
        const entry = dropped[idx];
        if (!entry) return;
        state.viewingDropped = { index: idx, entry };
        renderDashboard(buildCaseFromDropped(entry, idx));
        // Land on the overview tab of the drilled-down report, and scroll
        // up so the "you're now viewing a dropped APK" banner is visible.
        el("tabs").querySelector('[data-tab="overview"]').click();
        el("dashboard-view").scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  }
})();
