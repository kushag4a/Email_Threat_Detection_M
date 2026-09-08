(function () {
  "use strict";

  // ============================================================
  // TOAST / ERROR BANNER (replaces alert() calls)
  // ============================================================

  function showToast(message, kind) {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = "toast toast--" + (kind || "error");
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 6000);
  }

  // ============================================================
  // THEME (persisted in localStorage, "system" resolves live)
  // ============================================================

  const THEME_STORAGE_KEY = "eta-theme";

  function resolveSystemTheme() {
    const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    return prefersDark ? "soc-dark" : "professional-light";
  }

  function applyTheme(themeName) {
    const effective = themeName === "system" ? resolveSystemTheme() : themeName;
    document.documentElement.setAttribute("data-theme", effective);
  }

  function initTheme() {
    const stored = localStorage.getItem(THEME_STORAGE_KEY) || "soc-dark";
    applyTheme(stored);

    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
        if (localStorage.getItem(THEME_STORAGE_KEY) === "system") applyTheme("system");
      });
    }
  }

  document.querySelectorAll(".theme-option").forEach((btn) => {
    btn.addEventListener("click", () => {
      const theme = btn.getAttribute("data-theme");
      localStorage.setItem(THEME_STORAGE_KEY, theme);
      applyTheme(theme);
      showToast("Theme updated", "info");
    });
  });

  initTheme();

  // ============================================================
  // SIDEBAR ROUTING (every item switches a real view - none are dead)
  // ============================================================

  const VIEW_LOADERS = {
    scans: loadScansView,
    intel: loadIntelView,
    cases: loadCasesView,
    reports: loadReportsView,
    settings: loadSettingsView,
  };

  function switchView(viewId) {
    document.querySelectorAll(".nav-item").forEach((item) => {
      item.classList.toggle("active", item.getAttribute("data-view") === viewId);
    });

    // "inbox" is an alias for the dashboard view (same table/controls)
    const targetId = viewId === "inbox" ? "dashboard" : viewId;

    document.querySelectorAll(".view").forEach((section) => {
      section.classList.toggle("active", section.getAttribute("data-view-id") === targetId);
    });

    if (VIEW_LOADERS[viewId]) {
      VIEW_LOADERS[viewId]();
    }
  }

  document.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", () => switchView(item.getAttribute("data-view")));
  });

  // ============================================================
  // STATE
  // ============================================================

  const state = {
    provider: null, // "google" | "microsoft" | null
    accountEmail: null,
    pageSize: 5,
    pageTokenStack: [null],
    currentPageIndex: 0,
    nextPageToken: null,
    currentMessageIds: [],
    scanId: null,
    scanPollHandle: null,
    resultsByMessageId: {},
    batchFiles: [],
  };

  const el = {};
  [
    "provider-status-text", "connect-buttons", "connect-google", "connect-microsoft",
    "logout-btn", "refresh-btn", "page-size-select", "scan-btn", "prev-page-btn",
    "next-page-btn", "page-indicator", "scan-progress", "progress-bar-fill",
    "progress-text", "scan-summary", "email-table-body", "count-low", "count-medium",
    "count-high", "count-critical", "detail-panel", "detail-overlay", "detail-subject",
    "detail-panel-body", "close-detail-btn", "connect-prompt", "dropzone",
    "browse-files-btn", "eml-file-input", "selected-files-list", "analyze-batch-btn",
    "batch-summary", "batch-table-body",
  ].forEach((id) => { el[id] = document.getElementById(id); });
  el.providerStatusDot = document.querySelector("#provider-status .status-dot");

  // ============================================================
  // API HELPERS - every call detects non-2xx, surfaces a real error,
  // and never leaves a button permanently disabled on failure.
  // ============================================================

  async function apiGet(url) {
    let res;
    try {
      res = await fetch(url, { credentials: "include" });
    } catch (networkErr) {
      throw { detail: "Network error - is the server running?" };
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: res.statusText }));
      throw body;
    }
    return res.json();
  }

  async function apiPost(url, options) {
    let res;
    try {
      res = await fetch(url, Object.assign({ method: "POST", credentials: "include" }, options || {}));
    } catch (networkErr) {
      throw { detail: "Network error - is the server running?" };
    }
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: res.statusText }));
      throw body;
    }
    return res.json();
  }

  function errText(err) {
    return (err && (err.detail || err.message)) || JSON.stringify(err);
  }

  // ============================================================
  // CONNECTION STATUS / LIFECYCLE
  // ============================================================

  async function refreshConnectionStatus() {
    const [googleStatus, msStatus] = await Promise.all([
      apiGet("/auth/google/status").catch(() => ({ connected: false })),
      apiGet("/auth/microsoft/status").catch(() => ({ connected: false })),
    ]);

    if (googleStatus.connected) {
      state.provider = "google";
      state.accountEmail = googleStatus.email;
    } else if (msStatus.connected) {
      state.provider = "microsoft";
      state.accountEmail = msStatus.email;
    } else {
      state.provider = null;
      state.accountEmail = null;
    }

    renderConnectionStatus();
    renderSettingsAccountArea();
  }

  function renderConnectionStatus() {
    if (state.provider) {
      el.providerStatusDot.classList.remove("status-dot--off");
      el.providerStatusDot.classList.add("status-dot--on");
      el["provider-status-text"].textContent =
        `${state.provider === "google" ? "Gmail" : "Microsoft"} \u2014 ${state.accountEmail}`;
      el["connect-buttons"].hidden = true;
      el["logout-btn"].hidden = false;
      el["scan-btn"].disabled = false;
      el["connect-prompt"].hidden = true;
      loadEmailPage(null, 0);
    } else {
      el.providerStatusDot.classList.remove("status-dot--on");
      el.providerStatusDot.classList.add("status-dot--off");
      el["provider-status-text"].textContent = "No mailbox connected";
      el["connect-buttons"].hidden = false;
      el["logout-btn"].hidden = true;
      el["scan-btn"].disabled = true;
      el["connect-prompt"].hidden = false;
    }
  }

  el["connect-google"].addEventListener("click", () => {
    window.location.href = "/auth/google/login";
  });

  el["connect-microsoft"].addEventListener("click", () => {
    window.location.href = "/auth/microsoft/login";
  });

  async function doLogout() {
    if (!state.provider) return;

    try {
      await apiPost(`/auth/${state.provider}/logout`);
    } catch (err) {
      showToast("Logout request failed: " + errText(err));
      // Fall through and clear client state anyway - a stuck "connected"
      // UI after a failed logout call is worse than an optimistic clear.
    }

    // Full client-state reset, per spec: no stale results/scan state
    // left on screen after logout.
    if (state.scanPollHandle) clearInterval(state.scanPollHandle);
    state.provider = null;
    state.accountEmail = null;
    state.currentMessageIds = [];
    state.resultsByMessageId = {};
    state.scanId = null;
    state.pageTokenStack = [null];
    state.currentPageIndex = 0;
    state.nextPageToken = null;

    el["scan-progress"].hidden = true;
    el["scan-summary"].hidden = true;
    el["page-indicator"].textContent = "Page 1";
    el["prev-page-btn"].disabled = true;
    el["next-page-btn"].disabled = true;

    renderTable([]);
    updateSummaryCards();
    renderConnectionStatus();
    renderSettingsAccountArea();
    showToast("Logged out", "info");
  }

  el["logout-btn"].addEventListener("click", doLogout);

  el["refresh-btn"].addEventListener("click", () => {
    if (state.provider) {
      loadEmailPage(null, 0);
    } else {
      refreshConnectionStatus();
    }
  });

  // ============================================================
  // PAGINATION / MAILBOX LISTING
  // ============================================================

  el["page-size-select"].addEventListener("change", () => {
    state.pageSize = parseInt(el["page-size-select"].value, 10);
    loadEmailPage(null, 0);
  });

  async function loadEmailPage(pageToken, pageIndex) {
    if (!state.provider) return;

    try {
      const params = new URLSearchParams({
        provider: state.provider,
        page_size: String(state.pageSize),
      });
      if (pageToken) params.set("page_token", pageToken);

      const data = await apiGet(`/api/emails?${params.toString()}`);

      state.currentMessageIds = data.messages.map((m) => m.message_id);
      // Cache the metadata itself so the table shows real sender/subject/
      // date immediately, before any scan has run.
      data.messages.forEach((m) => {
        if (!state.resultsByMessageId[m.message_id]) {
          state.resultsByMessageId[m.message_id] = {
            message_id: m.message_id,
            provider: m.provider,
            status: "unscanned",
            email: { sender: m.sender, subject: m.subject, date: m.date },
            attachments: m.has_attachments ? [{ filename: "(attachment)" }] : [],
          };
        }
      });

      state.nextPageToken = data.next_page_token;
      state.currentPageIndex = pageIndex;
      state.pageTokenStack = state.pageTokenStack.slice(0, pageIndex + 1);
      state.pageTokenStack[pageIndex] = pageToken;

      el["page-indicator"].textContent = `Page ${pageIndex + 1}`;
      el["prev-page-btn"].disabled = pageIndex === 0;
      el["next-page-btn"].disabled = !state.nextPageToken;

      renderTable(state.currentMessageIds.map((id) => state.resultsByMessageId[id]));
    } catch (err) {
      showToast("Failed to load inbox: " + errText(err));
    }
  }

  el["prev-page-btn"].addEventListener("click", () => {
    if (state.currentPageIndex === 0) return;
    const prevIndex = state.currentPageIndex - 1;
    loadEmailPage(state.pageTokenStack[prevIndex], prevIndex);
  });

  el["next-page-btn"].addEventListener("click", () => {
    if (!state.nextPageToken) return;
    loadEmailPage(state.nextPageToken, state.currentPageIndex + 1);
  });

  // ============================================================
  // SCANNING
  // ============================================================

  el["scan-btn"].addEventListener("click", async () => {
    if (!state.provider) return;

    el["scan-btn"].disabled = true;
    el["scan-progress"].hidden = false;
    el["scan-summary"].hidden = true;
    el["progress-bar-fill"].style.width = "0%";
    el["progress-text"].textContent = `Scanning 0 / ${state.pageSize}`;

    try {
      const data = await apiPost(`/api/scan?provider=${state.provider}&count=${state.pageSize}`);
      state.scanId = data.scan_id;
      pollScan();
    } catch (err) {
      showToast("Failed to start scan: " + errText(err));
      el["scan-btn"].disabled = false;
      el["scan-progress"].hidden = true;
    }
  });

  function pollScan() {
    if (state.scanPollHandle) clearInterval(state.scanPollHandle);

    state.scanPollHandle = setInterval(async () => {
      try {
        const scan = await apiGet(`/api/scan/${state.scanId}`);

        const total = scan.requested || 1;
        const done = scan.analyzed + scan.failed;
        const pct = Math.min(100, Math.round((done / total) * 100));

        el["progress-bar-fill"].style.width = pct + "%";
        el["progress-text"].textContent = `Scanning ${done} / ${total}`;

        scan.results.forEach((r) => { state.resultsByMessageId[r.message_id] = r; });
        renderTable(state.currentMessageIds.map((id) => state.resultsByMessageId[id]));
        updateSummaryCards();

        if (scan.status === "complete") {
          clearInterval(state.scanPollHandle);
          el["scan-btn"].disabled = false;
          el["scan-summary"].hidden = false;
          el["scan-summary"].textContent =
            `Requested: ${scan.requested}  \u2022  Analyzed: ${scan.analyzed}  \u2022  ` +
            `Failed: ${scan.failed}  \u2022  Skipped: ${scan.skipped}`;
        }
      } catch (err) {
        clearInterval(state.scanPollHandle);
        el["scan-btn"].disabled = false;
        showToast("Lost connection while scanning: " + errText(err));
      }
    }, 700);
  }

  // ============================================================
  // TABLE RENDERING (Dashboard/Inbox)
  // ============================================================

  function riskBadge(risk) {
    if (!risk || !risk.level) {
      return `<span class="risk-badge risk-badge--unknown">NOT SCANNED</span>`;
    }
    const level = risk.level.toLowerCase();
    const labels = { low: "SAFE / LOW RISK", medium: "SUSPICIOUS", high: "HIGH RISK", critical: "CRITICAL" };
    return `<span class="risk-badge risk-badge--${level}">${labels[level] || risk.level}</span>`;
  }

  function renderTable(results) {
    results = results.filter(Boolean);

    if (!results.length) {
      el["email-table-body"].innerHTML = `
        <tr class="empty-state-row"><td colspan="6">
          <div class="empty-state">
            <p><strong>No emails loaded yet.</strong></p>
            <p>Connect a mailbox above to see your inbox.</p>
          </div>
        </td></tr>`;
      return;
    }

    el["email-table-body"].innerHTML = "";

    results.forEach((r) => {
      const tr = document.createElement("tr");
      const email = r.email || {};
      const attachmentCount = (r.attachments || []).length;

      tr.innerHTML = `
        <td>${escapeHtml(email.sender || "\u2014")}</td>
        <td>${escapeHtml(email.subject || "(no subject)")}</td>
        <td>${escapeHtml(email.date || "\u2014")}</td>
        <td>${escapeHtml(r.provider || state.provider || "\u2014")}</td>
        <td>${riskBadge(r.risk)}</td>
        <td>${attachmentCount > 0 ? attachmentCount + " file(s)" : "\u2014"}</td>
      `;

      if (r.status && r.status !== "unscanned") {
        tr.addEventListener("click", () => openDetailPanel(r));
      }

      el["email-table-body"].appendChild(tr);
    });
  }

  function updateSummaryCards() {
    const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    Object.values(state.resultsByMessageId).forEach((r) => {
      const level = r.risk && r.risk.level;
      if (level && counts[level] !== undefined) counts[level]++;
    });

    el["count-low"].textContent = counts.LOW;
    el["count-medium"].textContent = counts.MEDIUM;
    el["count-high"].textContent = counts.HIGH;
    el["count-critical"].textContent = counts.CRITICAL;
  }

  // ============================================================
  // DETAIL PANEL
  // ============================================================

  function openDetailPanel(result) {
    const email = result.email || {};
    const m1 = result.m1 || {};
    const m2 = result.m2 || {};
    const m3 = result.m3 || { phishtank: [], spamhaus: [], local_heuristics: [] };
    const m4 = result.m4 || [];
    const risk = result.risk || {};

    el["detail-subject"].textContent = email.subject || "(no subject)";

    const kv = (label, value) => `<dt>${label}</dt><dd>${escapeHtml(String(value ?? "unknown"))}</dd>`;

    const intelRows = () => {
      const rows = [];
      (m3.phishtank || []).forEach((r) => {
        rows.push(`<li>URL ${escapeHtml(r.url)}: ${r.listed ? "KNOWN PHISHING (PhishTank local feed)" : "Not listed \u2014 PhishTank: no match"}</li>`);
      });
      (m3.spamhaus || []).forEach((r) => {
        rows.push(`<li>IP ${escapeHtml(r.ip)}: ${r.listed ? "LISTED (Spamhaus DROP local feed, network " + escapeHtml(r.network || "") + ")" : "Not listed \u2014 Spamhaus: no match"}</li>`);
      });
      if (!rows.length) rows.push("<li>No indicators were available to check.</li>");
      return rows.join("");
    };

    const geoRows = () =>
      (m4 || []).map((g) =>
        `<li>${escapeHtml(g.ip)}: ${escapeHtml(g.city)}, ${escapeHtml(g.region)}, ${escapeHtml(g.country)} \u2014 ${escapeHtml(g.organization)}<br><em>${escapeHtml(g.note || "")}</em></li>`
      ).join("") || "<li>No public origin IP was available for geolocation.</li>";

    const attachmentAnalysis = result.attachment_analysis || {};
    const attachmentChips = !attachmentAnalysis.scanned
      ? `<p class="muted-note">${escapeHtml(attachmentAnalysis.reason || "No attachments")}</p>`
      : (result.attachments || []).map((a) => {
          const flags = a.flags && a.flags.length ? ` \u2014 ${a.flags.join(", ")}` : "";
          const chipClass = flags ? "attachment-chip attachment-chip--flagged" : "attachment-chip";
          const yara = a.yara || {};
          const yaraLabel = yara.scanned
            ? (yara.matches && yara.matches.length
                ? `YARA: ${yara.matches.map((m) => `${m.rule} (${m.severity})`).join(", ")}`
                : "YARA: no matching rule")
            : `YARA: not scanned (${yara.reason || "unavailable"})`;
          return `<span class="${chipClass}" title="SHA-256: ${escapeHtml(a.sha256 || "n/a")}">${escapeHtml(a.filename || "attachment")} (${escapeHtml(a.extension || "")}, ${a.size_bytes || 0}B)${escapeHtml(flags)}<br><small>${escapeHtml(yaraLabel)}</small></span>`;
        }).join("") || "No attachments.";

    const reasonsList = (risk.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("") || "<li>No reasons recorded.</li>";
    const evidenceList = (result.evidence_sources || []).map((s) => `<li>${escapeHtml(s)}</li>`).join("") || "<li>None</li>";

    el["detail-panel-body"].innerHTML = `
      <div class="detail-section">
        <h3>Email information</h3>
        <dl class="kv-grid">
          ${kv("Sender", email.sender)}
          ${kv("Reply-To", email.reply_to)}
          ${kv("Return-Path", email.return_path)}
          ${kv("Recipient", email.recipient)}
          ${kv("Date", email.date)}
        </dl>
      </div>
      <div class="detail-section">
        <h3>Risk</h3>
        <p>${riskBadge(risk)} <strong>${risk.score ?? "\u2014"}/100</strong></p>
        <ul class="reasons-list">${reasonsList}</ul>
      </div>
      <div class="detail-section">
        <h3>Authentication</h3>
        <dl class="kv-grid">
          ${kv("SPF", m1.spf)}
          ${kv("DKIM", m1.dkim)}
          ${kv("DMARC", m1.dmarc)}
        </dl>
      </div>
      <div class="detail-section">
        <h3>Header / Routing</h3>
        <dl class="kv-grid">
          ${kv("Origin IP", m1.origin_ip || "None found")}
          ${kv("Reply-To mismatch", (result.header_analysis || {}).reply_to_mismatch ? "Yes" : "No")}
          ${kv("Return-Path mismatch", (result.header_analysis || {}).return_path_mismatch ? "Yes" : "No")}
        </dl>
      </div>
      <div class="detail-section">
        <h3>Attachment Security</h3>
        ${attachmentChips}
      </div>
      <div class="detail-section">
        <h3>AI / Body Analysis</h3>
        <dl class="kv-grid">
          ${kv("Phishing probability", (m2.phishing_probability ?? "\u2014") + "%")}
          ${kv("Top classification", (m2.top_classification || {}).label || "\u2014")}
          ${kv("Deeper scan run", m2.forensics_triggered ? "Yes" : "No")}
          ${kv("Forced by attachment", m2.forensics_forced_by_attachment ? "Yes" : "No")}
        </dl>
      </div>
      <div class="detail-section">
        <h3>Geolocation / source infrastructure</h3>
        <ul class="evidence-list">${geoRows()}</ul>
      </div>
      <div class="detail-section">
        <h3>Threat intelligence</h3>
        <ul class="evidence-list">${intelRows()}</ul>
      </div>
      <div class="detail-section">
        <h3>Evidence sources</h3>
        <ul class="evidence-list">${evidenceList}</ul>
      </div>
    `;

    el["detail-panel"].classList.add("open");
    el["detail-panel"].setAttribute("aria-hidden", "false");
    el["detail-overlay"].hidden = false;
  }

  function closeDetailPanel() {
    el["detail-panel"].classList.remove("open");
    el["detail-panel"].setAttribute("aria-hidden", "true");
    el["detail-overlay"].hidden = true;
  }

  el["close-detail-btn"].addEventListener("click", closeDetailPanel);
  el["detail-overlay"].addEventListener("click", closeDetailPanel);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetailPanel(); });

  // ============================================================
  // SCANS VIEW
  // ============================================================

  async function loadScansView() {
    const historyList = document.getElementById("history-list");
    const badSourcesList = document.getElementById("bad-sources-list");
    const trendBars = document.getElementById("trend-bars");
    const trendEmptyNote = document.getElementById("trend-empty-note");
    const countLabel = document.getElementById("history-count-label");

    if (!state.provider) {
      historyList.innerHTML = `<p class="muted-note">Connect a mailbox and run a scan to build history.</p>`;
      badSourcesList.innerHTML = "";
      trendBars.innerHTML = "";
      return;
    }

    try {
      const history = await apiGet("/api/scans/history");
      countLabel.textContent = `(${history.count} of up to ${history.requested_max} shown)`;

      historyList.innerHTML = history.items.length
        ? `<table class="email-table"><thead><tr><th>Date</th><th>Sender</th><th>Subject</th><th>Risk</th><th>Why flagged</th></tr></thead><tbody>` +
          history.items.map((i) => `
            <tr>
              <td>${escapeHtml(i.date || "\u2014")}</td>
              <td>${escapeHtml(i.sender || "\u2014")}</td>
              <td>${escapeHtml(i.subject || "(no subject)")}</td>
              <td>${riskBadge(i.risk)}</td>
              <td>${escapeHtml((i.risk && i.risk.reasons && i.risk.reasons[0]) || "\u2014")}</td>
            </tr>`).join("") + `</tbody></table>`
        : `<p class="muted-note">No high-risk emails recorded yet in this session.</p>`;

      if (history.trend.length) {
        trendEmptyNote.hidden = true;
        const maxVal = Math.max(...history.trend.map((p) => p.total_suspicious), 1);
        trendBars.innerHTML = history.trend.map((p) => `
          <div class="trend-bar" title="${p.date}: ${p.total_suspicious} suspicious, ${p.critical} critical, ${p.distinct_senders} distinct senders">
            <div class="trend-bar-fill" style="height:${(p.total_suspicious / maxVal) * 100}%"></div>
            <span class="trend-bar-label">${p.date.slice(5)}</span>
          </div>`).join("");
      } else {
        trendEmptyNote.hidden = false;
        trendBars.innerHTML = "";
      }

      const sources = await apiGet("/api/scans/bad-sources");
      badSourcesList.innerHTML = sources.sources.length
        ? sources.sources.map((s) => `
            <div class="source-card">
              <strong>${escapeHtml(s.domain)}</strong>
              <span>${s.suspicious_count} suspicious message(s), ${s.critical_count} critical</span>
              ${s.note ? `<p class="muted-note">${escapeHtml(s.note)}</p>` : ""}
              ${s.reasons.length ? `<ul class="reasons-list">${s.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>` : ""}
            </div>`).join("")
        : `<p class="muted-note">Not enough data yet.</p>`;
    } catch (err) {
      showToast("Failed to load Scans data: " + errText(err));
    }
  }

  // ============================================================
  // THREAT INTELLIGENCE VIEW
  // ============================================================

  async function loadIntelView() {
    const container = document.getElementById("intel-cards");
    if (!state.provider) {
      container.innerHTML = `<p class="muted-note">Connect a mailbox and run a scan to see live threat-intel matches.</p>`;
      return;
    }
    try {
      const data = await apiGet("/api/threat-intel/summary");
      container.innerHTML = data.sources.map((s) => `
        <div class="intel-card">
          <h3>${escapeHtml(s.name)}</h3>
          <div class="intel-matches">${s.matches}</div>
          <div class="muted-note">matches out of ${s.indicators_checked} indicator(s) checked</div>
          <div class="muted-note">Status: ${escapeHtml(s.status)}${s.last_feed_update ? " \u2022 feed file updated " + escapeHtml(s.last_feed_update) : ""}</div>
        </div>`).join("");
    } catch (err) {
      showToast("Failed to load Threat Intelligence data: " + errText(err));
    }
  }

  // ============================================================
  // CASES VIEW
  // ============================================================

  async function loadCasesView() {
    const container = document.getElementById("cases-list");
    if (!state.provider) {
      container.innerHTML = `<p class="muted-note">Connect a mailbox and run a scan to build cases.</p>`;
      return;
    }
    try {
      const data = await apiGet("/api/cases");
      container.innerHTML = data.cases.length
        ? data.cases.map((c) => `
            <div class="case-card">
              <h3>${c.case_id} \u2014 ${escapeHtml(c.domain)}</h3>
              <p>${c.message_count} message(s) \u2022 ${c.distinct_senders} distinct sender(s) \u2022
                 ${c.distinct_ips} distinct IP(s) \u2022 Highest risk: ${riskBadge({ level: c.highest_risk })}</p>
              <p class="muted-note">First seen: ${escapeHtml(c.first_seen || "\u2014")} \u2022 Last seen: ${escapeHtml(c.last_seen || "\u2014")}</p>
              ${c.threat_categories.length ? `<p class="muted-note">Categories: ${c.threat_categories.map(escapeHtml).join(", ")}</p>` : ""}
            </div>`).join("")
        : `<p class="muted-note">No cases yet \u2014 high-risk detections will appear here.</p>`;
    } catch (err) {
      showToast("Failed to load Cases: " + errText(err));
    }
  }

  // ============================================================
  // REPORTS VIEW
  // ============================================================

  async function loadReportsView() {
    const container = document.getElementById("reports-summary");
    if (!state.provider) {
      container.innerHTML = `<p class="muted-note">Connect a mailbox and run a scan to generate a report.</p>`;
      return;
    }
    try {
      const r = await apiGet("/api/reports/summary");
      const list = (items, keyName, labelFn) =>
        items.length ? `<ul class="reasons-list">${items.map((i) => `<li>${labelFn(i)}: ${i.count}</li>`).join("")}</ul>` : `<p class="muted-note">No data yet.</p>`;

      container.innerHTML = `
        <h3>Overview</h3>
        <dl class="kv-grid">
          <dt>Total analyzed</dt><dd>${r.total_analyzed}</dd>
          <dt>Low / Safe</dt><dd>${r.risk_breakdown.LOW || 0}</dd>
          <dt>Medium / Suspicious</dt><dd>${r.risk_breakdown.MEDIUM || 0}</dd>
          <dt>High</dt><dd>${r.risk_breakdown.HIGH || 0}</dd>
          <dt>Critical</dt><dd>${r.risk_breakdown.CRITICAL || 0}</dd>
        </dl>
        <h3 style="margin-top:20px;">Top suspicious domains</h3>
        ${list(r.top_domains, "domain", (i) => escapeHtml(i.domain))}
        <h3 style="margin-top:20px;">Top suspicious senders</h3>
        ${list(r.top_senders, "sender", (i) => escapeHtml(i.sender))}
        <h3 style="margin-top:20px;">Top threat categories</h3>
        ${list(r.top_categories, "category", (i) => escapeHtml(i.category))}
        <h3 style="margin-top:20px;">Top attachment types</h3>
        ${list(r.top_attachment_types, "extension", (i) => escapeHtml(i.extension || "(none)"))}
        <h3 style="margin-top:20px;">Authentication failures</h3>
        ${Object.keys(r.auth_failures).length
          ? `<ul class="reasons-list">${Object.entries(r.auth_failures).map(([k, v]) => `<li>${k}: ${v}</li>`).join("")}</ul>`
          : `<p class="muted-note">No authentication failures recorded.</p>`}
      `;
    } catch (err) {
      showToast("Failed to load Reports: " + errText(err));
    }
  }

  // ============================================================
  // SETTINGS VIEW (Accounts section)
  // ============================================================

  function loadSettingsView() {
    renderSettingsAccountArea();
  }

  function renderSettingsAccountArea() {
    const area = document.getElementById("settings-account-area");
    if (!area) return;

    if (state.provider) {
      area.innerHTML = `
        <p><strong>Account:</strong> ${escapeHtml(state.accountEmail)}</p>
        <p><strong>Provider:</strong> ${state.provider === "google" ? "Google" : "Microsoft"}</p>
        <button class="btn btn-secondary" id="settings-logout-btn">Logout</button>
      `;
      document.getElementById("settings-logout-btn").addEventListener("click", doLogout);
    } else {
      area.innerHTML = `
        <p class="muted-note">No account connected.</p>
        <button class="btn btn-secondary" id="settings-connect-google">Connect Gmail</button>
        <button class="btn btn-secondary" id="settings-connect-microsoft">Connect Microsoft</button>
      `;
      document.getElementById("settings-connect-google").addEventListener("click", () => {
        window.location.href = "/auth/google/login";
      });
      document.getElementById("settings-connect-microsoft").addEventListener("click", () => {
        window.location.href = "/auth/microsoft/login";
      });
    }
  }

  // ============================================================
  // CUSTOM EMAIL VIEW (multi-file, up to 10)
  // ============================================================

  const MAX_BATCH_FILES = 10;

  function renderSelectedFiles() {
    const list = el["selected-files-list"];
    if (!state.batchFiles.length) {
      list.innerHTML = "";
      el["analyze-batch-btn"].disabled = true;
      return;
    }
    list.innerHTML = state.batchFiles.map((f, i) => `
      <span class="attachment-chip">${escapeHtml(f.name)} <button data-idx="${i}" class="remove-file-btn" aria-label="Remove ${escapeHtml(f.name)}">&times;</button></span>
    `).join("");
    list.querySelectorAll(".remove-file-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.batchFiles.splice(parseInt(btn.getAttribute("data-idx"), 10), 1);
        renderSelectedFiles();
      });
    });
    el["analyze-batch-btn"].disabled = false;
  }

  function addFiles(fileList) {
    const incoming = Array.from(fileList).filter((f) => /\.(eml|txt)$/i.test(f.name));
    const room = MAX_BATCH_FILES - state.batchFiles.length;
    if (incoming.length > room) {
      showToast(`Only ${MAX_BATCH_FILES} files allowed per batch \u2014 added the first ${Math.max(room, 0)}.`, "info");
    }
    state.batchFiles = state.batchFiles.concat(incoming.slice(0, room));
    renderSelectedFiles();
  }

  el["browse-files-btn"].addEventListener("click", () => el["eml-file-input"].click());
  el["eml-file-input"].addEventListener("change", (e) => addFiles(e.target.files));

  ["dragover", "dragenter"].forEach((evt) => {
    el.dropzone.addEventListener(evt, (e) => { e.preventDefault(); el.dropzone.classList.add("dropzone--active"); });
  });
  ["dragleave", "drop"].forEach((evt) => {
    el.dropzone.addEventListener(evt, (e) => { e.preventDefault(); el.dropzone.classList.remove("dropzone--active"); });
  });
  el.dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer && e.dataTransfer.files) addFiles(e.dataTransfer.files);
  });

  el["analyze-batch-btn"].addEventListener("click", async () => {
    if (!state.batchFiles.length) return;

    el["analyze-batch-btn"].disabled = true;
    el["batch-summary"].hidden = true;
    el["batch-table-body"].innerHTML = "";

    const formData = new FormData();
    state.batchFiles.forEach((f) => formData.append("files", f));

    try {
      const data = await apiPost("/api/analyze/batch", { body: formData });

      el["batch-table-body"].innerHTML = data.results.map((r) => `
        <tr class="${r.status === 'analyzed' ? '' : 'row-failed'}">
          <td>${escapeHtml(r.source_filename || r.message_id || "\u2014")}</td>
          <td>${escapeHtml((r.email && r.email.sender) || "\u2014")}</td>
          <td>${escapeHtml((r.email && r.email.subject) || r.error || "\u2014")}</td>
          <td>${riskBadge(r.risk)}</td>
        </tr>`).join("");

      el["batch-summary"].hidden = false;
      el["batch-summary"].textContent =
        `${data.requested} uploaded \u2022 ${data.analyzed} analyzed \u2022 ${data.failed} failed \u2022 ${data.skipped} skipped`;

      state.batchFiles = [];
      renderSelectedFiles();
    } catch (err) {
      showToast("Batch analysis failed: " + errText(err));
    } finally {
      el["analyze-batch-btn"].disabled = state.batchFiles.length === 0;
    }
  });

  // ============================================================
  // UTIL
  // ============================================================

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // ============================================================
  // INIT
  //
  // Runs on every page load, including the redirect FastAPI sends
  // back to "/" after a successful OAuth callback - so a successful
  // login is reflected immediately with no second click and no
  // manual refresh required.
  // ============================================================

  refreshConnectionStatus();
})();
