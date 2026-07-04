(function () {
  "use strict";

  const state = { apkFile: null, pcapFile: null, result: null, loading: false };

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

  setupDropzone("pcap-dropzone", "pcap-input", "pcap-filename", (file) => {
    state.pcapFile = file;
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
    if (state.pcapFile) formData.append("pcap", state.pcapFile);

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
        enterResultsView(data);
      })
      .catch((err) => {
        setLoading(false);
        showError("Could not reach the server: " + err.message);
      });
  });

  el("new-case-btn").addEventListener("click", () => {
    state.apkFile = null;
    state.pcapFile = null;
    state.result = null;
    el("apk-filename").hidden = true;
    el("pcap-filename").hidden = true;
    el("apk-dropzone").classList.remove("has-file");
    el("pcap-dropzone").classList.remove("has-file");
    el("apk-input").value = "";
    el("pcap-input").value = "";
    clearError();
    updateRunButton();
    exitResultsView();
  });

  function updateDockSummary() {
    const parts = [];
    if (state.apkFile) parts.push(state.apkFile.name);
    if (state.pcapFile) parts.push(state.pcapFile.name);
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

  // ---------------- Tabs ----------------

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      el("tab-" + btn.dataset.tab).classList.add("active");
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

    renderVerdict(v, s);
    renderOverview(s, n, c, data.has_pcap);
    renderPermissions(s);
    renderManifest(s);
    renderFileTree(s);
    renderIOCs(s);
    renderNetwork(n, data.has_pcap);
    renderCorrelation(c, data.has_pcap);
    renderTimeline(n, data.has_pcap);
  }

  function renderVerdict(v, s) {
    el("verdict-score").textContent = v.risk_score;
    el("verdict-app-name").textContent = s.app_name || s.metadata.filename;
    el("verdict-package").textContent = s.package;
    el("verdict-summary").textContent = v.summary;

    const stamp = el("risk-stamp");
    stamp.textContent = v.risk_level.toUpperCase() + " RISK";
    stamp.className = "stamp " + v.risk_level;

    const flagsEl = el("verdict-flags");
    flagsEl.innerHTML = "";
    const allFlags = [...v.breakdown].sort((a, b) => b.points - a.points);
    allFlags.forEach((f) => {
      const div = document.createElement("div");
      div.className = "flag-chip";
      div.innerHTML = `<span class="flag-points">+${f.points}</span><span>${esc(f.label)}${f.detail ? " — " + esc(f.detail) : ""}</span>`;
      flagsEl.appendChild(div);
    });
  }

  function renderOverview(s, n, c, hasPcap) {
    const meta = s.metadata;
    const analysisMode = hasPcap
      ? "Static + network (combined)"
      : "Static only — add a capture for network & correlation";

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

  function renderManifest(s) {
    el("tab-manifest").innerHTML = `
      <div class="panel-box">
        <h3>AndroidManifest.xml</h3>
        <pre class="manifest-view">${esc(s.raw_manifest)}</pre>
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

  function renderNetwork(n, hasPcap) {
    if (!hasPcap) {
      el("tab-network").innerHTML = `<div class="panel-box"><div class="empty-state">No network capture was provided. Upload a .pcap or .pcapng alongside the APK to see traffic and beacon analysis here.</div></div>`;
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

    el("tab-network").innerHTML = `
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
      el("tab-correlation").innerHTML = `<div class="panel-box"><div class="empty-state">Correlation compares static IOCs against observed traffic. Add a network capture to enable this tab.</div></div>`;
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
})();
