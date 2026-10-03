/* =========================================================
   ValorProtects — Production Frontend (Polished UI + Real API)
   ==========================================================
   This file combines the polished ValorProtects UI design with
   the real backend API. NO mock data, NO fake scanning, NO
   generated emails. Every piece of data comes from the real
   FastAPI backend.
   ========================================================= */

(function () {
  "use strict";

  // ============================================================
  // API HELPERS — real backend communication
  // ============================================================

  async function apiGet(url) {
    let res;
    try {
      res = await fetch(url, { credentials: "include" });
    } catch (networkErr) {
      throw { detail: "Network error — is the server running?" };
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
      throw { detail: "Network error — is the server running?" };
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
  // UTILITY
  // ============================================================

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmtDate(d) {
    if (!d) return "—";
    if (typeof d === "string") return d;
    return d.toLocaleDateString(undefined, { weekday: "short", day: "2-digit", month: "short" }) +
      ", " + d.getFullYear() + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }

  function timeAgo(d) {
    if (!d) return "";
    const date = typeof d === "string" ? new Date(d) : d;
    if (isNaN(date.getTime())) return d;
    const mins = Math.round((Date.now() - date.getTime()) / 60000);
    if (mins < 0) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.round(hrs / 24)}d ago`;
  }

  function formatRelativeTime(d) {
    const mins = Math.floor((Date.now() - d.getTime()) / 60000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins} min ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs} hour${hrs === 1 ? "" : "s"} ago`;
    const days = Math.floor(hrs / 24);
    if (days === 1) return "Yesterday";
    return `${days} days ago`;
  }

  // ============================================================
  // ICON HELPERS (uses icons.js ICONS dict)
  // ============================================================

  function ic(name, cls) {
    const body = (typeof ICONS !== "undefined" && ICONS[name]) || "";
    if (!body) return "";
    return `<svg class="icon${cls ? " " + cls : ""}" viewBox="0 0 24 24" aria-hidden="true" focusable="false">${body}</svg>`;
  }

  // ============================================================
  // TOAST SYSTEM
  // ============================================================

  function toast(msg, icon) {
    const wrap = document.getElementById("toastWrap");
    if (!wrap) return;
    const el = document.createElement("div");
    el.className = "toast";
    el.innerHTML = `${ic(icon || "circle-check")}<span>${escapeHtml(msg)}</span>`;
    wrap.appendChild(el);
    setTimeout(() => { el.style.opacity = "0"; el.style.transition = "opacity .3s"; setTimeout(() => el.remove(), 300); }, 3200);
  }

  // ============================================================
  // THEME SYSTEM
  // ============================================================

  const THEME_LABELS = { default: "Default", dark: "Dark", light: "Light", purple: "Purple" };

  function applyTheme(name) {
    state.theme = name;
    if (name === "default") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", name);
    localStorage.setItem("vp_theme", name);
    const label = document.getElementById("currentThemeLabel");
    if (label) label.textContent = `Current: ${THEME_LABELS[name] || "Default"}`;
  }

  // ============================================================
  // STATE
  // ============================================================

  const state = {
    // Connection
    provider: null,       // "google" | "microsoft" | null
    accountEmail: null,
    googleStatus: { connected: false, email: null },
    microsoftStatus: { connected: false, email: null },

    // Pagination (real backend token-based)
    pageSize: 20,
    pageTokenStack: [null],
    currentPageIndex: 0,
    nextPageToken: null,
    currentMessageIds: [],

    // Results cache
    resultsByMessageId: {},
    scanId: null,
    scanPollHandle: null,

    // Custom analysis
    customAnalyses: [],
    chosenFile: null,

    // Filters (client-side over loaded results)
    search: "",
    filters: { severity: "all", threat: "all", trust: "all", read: "all" },

    // Trusted senders (localStorage persistence)
    trustedSenders: JSON.parse(localStorage.getItem("vp_trustedSenders") || "{}"),

    // Theme
    theme: localStorage.getItem("vp_theme") || "default",

    // Settings (UI toggles, persisted locally)
    settings: JSON.parse(localStorage.getItem("vp_settings") || '{"digest":true,"autorefresh":true,"spamassassin":true,"deepscan":true}'),

    // Refresh tracking
    lastRefreshedAt: null,
    refreshing: false,
    scanning: false,

    // Dashboard data cache
    dashboardData: null,
  };

  // Apply persisted theme
  applyTheme(state.theme);

  // ============================================================
  // SIDEBAR NAVIGATION
  // ============================================================

  const navItems = document.querySelectorAll(".nav-links li[data-view]");
  const views = document.querySelectorAll(".view");

  function setActiveView(name) {
    views.forEach(v => v.classList.toggle("active", v.id === "view-" + name));
    navItems.forEach(li => li.classList.toggle("active", li.getAttribute("data-view") === name));
    if (name === "home") renderHome();
    if (name === "inbox") renderInbox();
    if (name === "dashboard") renderDashboard();
    if (name === "reports") renderReports();
    if (name === "custom") renderCustom();
    if (name === "user") renderUser();
    if (name === "settings") initSettings();
  }

  navItems.forEach(li => {
    li.addEventListener("click", () => setActiveView(li.getAttribute("data-view")));
  });

  // Sidebar collapse
  const sidebar = document.getElementById("sidebar");
  const toggleBtn = document.getElementById("toggleBtn");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("collapsed");
    });
  }

  // ============================================================
  // CONNECTION STATUS / LIFECYCLE
  // ============================================================

  async function refreshConnectionStatus() {
    const [googleStatus, msStatus] = await Promise.all([
      apiGet("/auth/google/status").catch(() => ({ connected: false })),
      apiGet("/auth/microsoft/status").catch(() => ({ connected: false })),
    ]);

    state.googleStatus = googleStatus;
    state.microsoftStatus = msStatus;

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

    updateUserProfileShortcut();

    if (state.provider) {
      loadEmailPage(null, 0);
    }
  }

  function updateUserProfileShortcut() {
    const el = document.getElementById("userProfileShortcut");
    if (!el) return;
    if (state.provider && state.accountEmail) {
      const providerName = state.provider === "google" ? "Gmail" : "Microsoft";
      el.innerHTML = `
        <img id="userAvatar" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Ccircle cx='12' cy='8' r='4' fill='%2368D391'/%3E%3Cpath d='M4 20c0-4 3.5-6 8-6s8 2 8 6' fill='%2368D391'/%3E%3C/svg%3E" alt="User">
        <div class="user-info">
          <strong>${escapeHtml(providerName)}</strong>
          <span>${escapeHtml(state.accountEmail)}</span>
        </div>`;
    } else {
      el.innerHTML = `
        <div class="user-info">
          <strong>Not connected</strong>
          <span>Connect a mailbox</span>
        </div>`;
    }
  }

  // ============================================================
  // REFRESH (real mailbox refresh via page reload)
  // ============================================================

  function refreshMailbox(triggerBtn, onDone) {
    if (state.refreshing || !state.provider) return;
    state.refreshing = true;
    if (triggerBtn) triggerBtn.classList.add("syncing");

    loadEmailPage(null, 0).then(() => {
      state.lastRefreshedAt = new Date();
      localStorage.setItem("vp_lastRefreshedAt", state.lastRefreshedAt.toISOString());
      renderRefreshLabels();
      if (triggerBtn) triggerBtn.classList.remove("syncing");
      state.refreshing = false;
      toast("Mailbox refreshed");
      if (onDone) onDone();
    }).catch(err => {
      if (triggerBtn) triggerBtn.classList.remove("syncing");
      state.refreshing = false;
      toast("Refresh failed: " + errText(err));
    });
  }

  function loadLastRefreshedAt() {
    const saved = localStorage.getItem("vp_lastRefreshedAt");
    if (saved) {
      const d = new Date(saved);
      if (!isNaN(d)) return d;
    }
    return null;
  }

  function renderRefreshLabels() {
    const text = state.lastRefreshedAt
      ? `Last refreshed ${formatRelativeTime(state.lastRefreshedAt)}`
      : "Not yet refreshed";
    ["dashboardRefreshedLine", "homeRefreshedLine", "inboxRefreshedLine"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.textContent = text;
    });
  }

  state.lastRefreshedAt = loadLastRefreshedAt();

  // ============================================================
  // PAGINATION / MAILBOX LISTING (real backend)
  // ============================================================

  async function loadEmailPage(pageToken, pageIndex) {
    if (!state.provider) return;

    try {
      const params = new URLSearchParams({
        provider: state.provider,
        page_size: String(state.pageSize),
      });
      if (pageToken) params.set("page_token", pageToken);

      const data = await apiGet(`/api/emails?${params.toString()}`);

      state.currentMessageIds = data.messages.map(m => m.message_id);
      // Cache metadata for table display before scan
      data.messages.forEach(m => {
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

      if (!state.lastRefreshedAt) {
        state.lastRefreshedAt = new Date();
        localStorage.setItem("vp_lastRefreshedAt", state.lastRefreshedAt.toISOString());
      }

      renderInboxTable();
      updateSummaryCards();
      renderRefreshLabels();
    } catch (err) {
      toast("Failed to load inbox: " + errText(err));
    }
  }

  // ============================================================
  // INBOX TABLE RENDERING
  // ============================================================

  function getFilteredResults() {
    let list = state.currentMessageIds.map(id => state.resultsByMessageId[id]).filter(Boolean);
    const q = state.search.trim().toLowerCase();
    if (q) {
      list = list.filter(r => {
        const email = r.email || {};
        const sender = (email.sender || "").toLowerCase();
        const subject = (email.subject || "").toLowerCase();
        const threats = (r.threat_types || []).join(" ").toLowerCase();
        return sender.includes(q) || subject.includes(q) || threats.includes(q);
      });
    }
    if (state.filters.severity !== "all") {
      const map = { safe: "LOW", medium: "MEDIUM", high: "HIGH", critical: "CRITICAL" };
      const target = map[state.filters.severity] || state.filters.severity.toUpperCase();
      list = list.filter(r => (r.risk && r.risk.level) === target);
    }
    if (state.filters.threat !== "all") {
      list = list.filter(r => (r.threat_types || []).includes(state.filters.threat));
    }
    if (state.filters.trust === "trusted") {
      list = list.filter(r => {
        const sender = (r.email || {}).sender || "";
        return state.trustedSenders[sender];
      });
    }
    if (state.filters.trust === "untrusted") {
      list = list.filter(r => {
        const sender = (r.email || {}).sender || "";
        return !state.trustedSenders[sender];
      });
    }
    return list;
  }

  function severityLabel(level) {
    if (!level) return "NOT SCANNED";
    const labels = { LOW: "SAFE", MEDIUM: "MEDIUM", HIGH: "HIGH", CRITICAL: "CRITICAL" };
    return labels[level] || level;
  }

  function severityClass(level) {
    if (!level) return "unscanned";
    const map = { LOW: "safe", MEDIUM: "medium", HIGH: "high", CRITICAL: "critical" };
    return map[level] || "unscanned";
  }

  function renderInboxTable() {
    const list = getFilteredResults();
    const inboxTbody = document.getElementById("inboxTbody");
    const wrap = document.getElementById("inboxTableWrap");
    const pageLabel = document.getElementById("pageLabel");
    const pageRangeLabel = document.getElementById("pageRangeLabel");
    const inboxSubtitle = document.getElementById("inboxSubtitle");
    const prevBtn = document.getElementById("prevPageBtn");
    const nextBtn = document.getElementById("nextPageBtn");

    if (inboxSubtitle) {
      const scannedCount = Object.values(state.resultsByMessageId).filter(r => r.status && r.status !== "unscanned").length;
      inboxSubtitle.textContent = `${state.currentMessageIds.length} messages loaded · ${scannedCount} scanned`;
    }

    if (pageLabel) pageLabel.textContent = `Page ${state.currentPageIndex + 1}`;
    if (pageRangeLabel) pageRangeLabel.textContent = list.length ? `Showing ${list.length} message(s)` : "No matches";
    if (prevBtn) prevBtn.disabled = state.currentPageIndex === 0;
    if (nextBtn) nextBtn.disabled = !state.nextPageToken;

    if (!list.length) {
      if (wrap) wrap.innerHTML = `<div class="empty-state" style="height:100%;">${ic("inbox")}<span>${state.provider ? "No emails match current filters" : "Connect a mailbox to see your inbox"}</span></div>`;
      return;
    }

    // Ensure table structure
    if (wrap && !wrap.querySelector("table")) {
      wrap.innerHTML = `<table class="mail-table"><thead><tr><th>Sender</th><th>Subject</th><th>Date</th><th>Risk</th><th>Threat Type</th><th>Status</th></tr></thead><tbody id="inboxTbody"></tbody></table>`;
    }

    const tbody = document.getElementById("inboxTbody");
    if (!tbody) return;

    tbody.innerHTML = list.map(r => {
      const email = r.email || {};
      const risk = r.risk || {};
      const level = risk.level;
      const score = risk.score;
      const sev = severityClass(level);
      const threats = (r.threat_types || []);
      const sender = email.sender || "—";
      const senderEmail = sender.includes("<") ? sender : "";
      const senderName = sender.replace(/<.*>/, "").trim() || sender;
      const isTrusted = state.trustedSenders[sender];
      const isScanned = r.status && r.status !== "unscanned";

      return `<tr class="${!isScanned ? "unscanned-row" : ""}" data-id="${escapeHtml(r.message_id)}">
        <td><div class="sender-cell"><span>${escapeHtml(senderName)}</span>${senderEmail ? `<span class="addr">${escapeHtml(senderEmail)}</span>` : ""}</div></td>
        <td>${escapeHtml(email.subject || "(no subject)")}</td>
        <td>${escapeHtml(email.date || "—")}</td>
        <td>${isScanned ? `<span class="badge ${sev}">${severityLabel(level)}${score != null ? " · " + score : ""}</span>` : `<span class="badge unscanned">NOT SCANNED</span>`}</td>
        <td>${threats.length ? threats.map(t => `<span class="threat-tag">${escapeHtml(t)}</span>`).join("") : '<span style="color:var(--surface-muted);font-size:11px;">—</span>'}</td>
        <td>${isTrusted ? '<span class="badge trusted">User-trusted</span>' : `<span style="font-size:12px;color:var(--surface-muted);">${isScanned ? "Scanned" : "Pending"}</span>`}</td>
      </tr>`;
    }).join("");

    tbody.querySelectorAll("tr").forEach(row => {
      row.addEventListener("click", () => {
        const mid = row.getAttribute("data-id");
        const result = state.resultsByMessageId[mid];
        if (result && result.status !== "unscanned") {
          openEmailWorkspace(result);
        }
      });
    });
  }

  function updateSummaryCards() {
    const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    Object.values(state.resultsByMessageId).forEach(r => {
      const level = r.risk && r.risk.level;
      if (level && counts[level] !== undefined) counts[level]++;
    });
    return counts;
  }

  // ============================================================
  // SCANNING (real backend)
  // ============================================================

  async function startScan() {
    if (!state.provider || state.scanning) return;
    if (!state.currentMessageIds.length) {
      toast("No messages loaded to scan.", "warning");
      return;
    }

    state.scanning = true;
    const scanBtn = document.getElementById("scanInboxBtn");
    const progress = document.getElementById("scanProgress");
    const fill = document.getElementById("scanProgressFill");
    const text = document.getElementById("scanProgressText");
    const detail = document.getElementById("scanProgressDetail");

    if (scanBtn) scanBtn.disabled = true;
    if (progress) progress.classList.add("active");
    if (fill) fill.style.width = "0%";
    if (text) text.textContent = `Scanning 0 / ${state.currentMessageIds.length}`;
    if (detail) detail.textContent = `Requested: ${state.currentMessageIds.length} · Analyzed: 0 · Failed: 0 · Skipped: 0`;

    try {
      const data = await apiPost(`/api/scan?provider=${state.provider}`, {
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message_ids: state.currentMessageIds }),
      });
      state.scanId = data.scan_id;
      pollScan();
    } catch (err) {
      toast("Failed to start scan: " + errText(err));
      if (scanBtn) scanBtn.disabled = false;
      if (progress) progress.classList.remove("active");
      state.scanning = false;
    }
  }

  function pollScan() {
    if (state.scanPollHandle) clearInterval(state.scanPollHandle);
    const POLL_TIMEOUT_MS = 15 * 60 * 1000;
    const pollStart = Date.now();

    state.scanPollHandle = setInterval(async () => {
      try {
        if (Date.now() - pollStart > POLL_TIMEOUT_MS) {
          clearInterval(state.scanPollHandle);
          const scanBtn = document.getElementById("scanInboxBtn");
          if (scanBtn) scanBtn.disabled = false;
          state.scanning = false;
          toast("Scan polling timed out after 15 minutes.", "warning");
          return;
        }

        const scan = await apiGet(`/api/scan/${state.scanId}`);
        const total = scan.requested || 1;
        const done = scan.analyzed + scan.failed;
        const pct = Math.min(100, Math.round((done / total) * 100));

        const fill = document.getElementById("scanProgressFill");
        const text = document.getElementById("scanProgressText");
        const detail = document.getElementById("scanProgressDetail");
        if (fill) fill.style.width = pct + "%";
        if (text) text.textContent = `Scanning ${done} / ${total}`;
        if (detail) detail.textContent = `Requested: ${scan.requested} · Analyzed: ${scan.analyzed} · Failed: ${scan.failed} · Skipped: ${scan.skipped}`;

        scan.results.forEach(r => { state.resultsByMessageId[r.message_id] = r; });
        renderInboxTable();
        updateSummaryCards();

        if (scan.status === "complete") {
          clearInterval(state.scanPollHandle);
          const scanBtn = document.getElementById("scanInboxBtn");
          if (scanBtn) scanBtn.disabled = false;
          const progress = document.getElementById("scanProgress");
          if (progress) setTimeout(() => progress.classList.remove("active"), 1500);
          state.scanning = false;
          state.lastRefreshedAt = new Date();
          localStorage.setItem("vp_lastRefreshedAt", state.lastRefreshedAt.toISOString());
          renderRefreshLabels();
          toast("Scan complete — inbox up to date");
        }
      } catch (err) {
        clearInterval(state.scanPollHandle);
        const scanBtn = document.getElementById("scanInboxBtn");
        if (scanBtn) scanBtn.disabled = false;
        state.scanning = false;
        toast("Lost connection while scanning: " + errText(err));
      }
    }, 700);
  }

  // ============================================================
  // EMAIL ANALYSIS WORKSPACE (centered modal, real data)
  // ============================================================

  const drawerOverlay = document.getElementById("drawerOverlay");
  const drawer = document.getElementById("drawer");

  function closeDrawer() {
    if (drawerOverlay) drawerOverlay.classList.remove("open");
    if (drawer) drawer.classList.remove("open");
  }

  if (document.getElementById("drawerClose")) {
    document.getElementById("drawerClose").addEventListener("click", closeDrawer);
  }
  if (drawerOverlay) {
    drawerOverlay.addEventListener("click", e => { if (e.target === drawerOverlay) closeDrawer(); });
  }
  document.addEventListener("keydown", e => { if (e.key === "Escape") { closeDrawer(); closeModal(); } });

  function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function sevColor(sev) { return cssVar("--risk-" + sev + "-text"); }
  function authBadge(v) {
    if (!v || v === "unknown") return `<span style="color:var(--surface-muted);">Unknown</span>`;
    const pass = v.toLowerCase().includes("pass");
    return pass
      ? `<span style="color:${cssVar("--risk-safe-text")};">Pass</span>`
      : `<span style="color:${cssVar("--risk-critical-text")};">${escapeHtml(v)}</span>`;
  }

  async function openEmailWorkspace(result) {
    // Re-fetch latest analysis if possible
    if (result && result.provider && result.account_id && result.message_id) {
      try {
        const fresh = await apiGet(
          `/api/analysis/${encodeURIComponent(result.provider)}/${encodeURIComponent(result.account_id)}/${encodeURIComponent(result.message_id)}`
        );
        result = fresh || result;
        state.resultsByMessageId[result.message_id] = result;
      } catch (_) { /* keep existing result */ }
    }

    const email = result.email || {};
    const m1 = result.m1 || {};
    const m2 = result.m2 || {};
    const m3 = result.m3 || { phishtank: [], spamhaus: [], local_heuristics: [] };
    const m4 = result.m4 || [];
    const risk = result.risk || {};
    const headerAnalysis = result.header_analysis || {};
    const attachmentAnalysis = result.attachment_analysis || {};
    const bec = result.bec_analysis || {};
    const sev = severityClass(risk.level);
    const sender = email.sender || "—";
    const isTrusted = state.trustedSenders[sender];

    // Set header
    const subjectEl = document.getElementById("drawerSubject");
    const fromEl = document.getElementById("drawerFrom");
    if (subjectEl) subjectEl.textContent = email.subject || "(no subject)";
    if (fromEl) fromEl.textContent = sender;

    // User disposition
    const dispositionHtml = isTrusted
      ? `<div class="disposition-box trusted"><strong>USER DISPOSITION:</strong> Trusted by user on ${escapeHtml(state.trustedSenders[sender].dateTrusted || "a previous session")}. This does not change the automated analysis below.</div>`
      : `<div class="disposition-box none"><strong>USER DISPOSITION:</strong> None — treated per automated analysis.</div>`;

    // BEC section
    const becHtml = (bec.detected || (result.threat_types || []).some(t => t.toLowerCase().includes("bec")))
      ? `<div class="kv-row"><span class="k">BEC detected</span><span class="v">Yes</span></div>
         ${bec.matched_phrases ? `<div class="kv-row"><span class="k">Matched phrases</span><span class="v">${escapeHtml(bec.matched_phrases.join(", "))}</span></div>` : ""}
         ${bec.urgency_score != null ? `<div class="kv-row"><span class="k">Urgency score</span><span class="v">${bec.urgency_score}</span></div>` : ""}`
      : `<div style="color:var(--surface-muted);font-size:12.5px;">No BEC indicators found.</div>`;

    // URL analysis
    const urls = result.detected_urls || [];
    const urlHtml = urls.length
      ? urls.map(u => `<div class="link-card"><div class="link-card-top">${ic("link")} <span class="link-url">${escapeHtml(typeof u === "string" ? u : u.url || u)}</span></div></div>`).join("")
      : `<div style="color:var(--surface-muted);font-size:12.5px;">No links detected.</div>`;

    // Attachments
    const attachments = result.attachments || [];
    const attachHtml = !attachmentAnalysis.scanned
      ? `<div style="color:var(--surface-muted);font-size:12.5px;">${escapeHtml(attachmentAnalysis.reason || "No attachments")}</div>`
      : attachments.map(a => {
          const flags = a.flags && a.flags.length ? ` — ${a.flags.join(", ")}` : "";
          const yara = a.yara || {};
          const yaraLabel = yara.scanned
            ? (yara.matches && yara.matches.length
              ? `YARA: ${yara.matches.map(m => `${m.rule} (${m.severity})`).join(", ")}`
              : "YARA: no matching rule")
            : `YARA: not scanned (${yara.reason || "unavailable"})`;
          return `<div class="kv-row"><span class="k">File</span><span class="v">${escapeHtml(a.filename || "attachment")} (${escapeHtml(a.extension || "")}, ${a.size_bytes || 0}B)${escapeHtml(flags)}</span></div>
            <div class="kv-row"><span class="k">Magic-byte</span><span class="v">${escapeHtml(a.detected_type || "—")}</span></div>
            <div class="kv-row"><span class="k">YARA</span><span class="v">${escapeHtml(yaraLabel)}</span></div>
            <div class="kv-row"><span class="k">SHA-256</span><span class="v" style="font-size:10.5px;">${escapeHtml(a.sha256 || "—")}</span></div>`;
        }).join('<hr style="border:none;border-top:1px dashed var(--surface-border);margin:6px 0;">') || '<div style="color:var(--surface-muted);font-size:12.5px;">No attachments.</div>';

    // Geolocation
    const geoHtml = (() => {
      const rows = (m4 || []).map(g =>
        `<div class="kv-row"><span class="k">IP</span><span class="v">${escapeHtml(g.ip)}</span></div>
         <div class="kv-row"><span class="k">Location</span><span class="v">${escapeHtml(g.city || "")}, ${escapeHtml(g.region || "")}, ${escapeHtml(g.country || "")}</span></div>
         <div class="kv-row"><span class="k">Organization</span><span class="v">${escapeHtml(g.organization || "—")}</span></div>
         ${g.note ? `<div style="color:var(--surface-muted);font-size:11px;font-style:italic;">${escapeHtml(g.note)}</div>` : ""}`
      ).join('<hr style="border:none;border-top:1px dashed var(--surface-border);margin:6px 0;">');
      if (rows) return rows;
      const status = result.geo_status || "not_applicable";
      if (status === "pending") return '<div style="color:var(--surface-muted);font-size:12.5px;">Geolocation enrichment in progress…</div>';
      if (status === "failed") return '<div style="color:var(--surface-muted);font-size:12.5px;">Geolocation lookup failed.</div>';
      return m1.origin_ip
        ? '<div style="color:var(--surface-muted);font-size:12.5px;">No globally routable origin IP was available for geolocation.</div>'
        : '<div style="color:var(--surface-muted);font-size:12.5px;">No origin IP could be extracted from the received headers.</div>';
    })();

    // Threat Intel
    const intelHtml = (() => {
      const rows = [];
      (m3.phishtank || []).forEach(r => {
        rows.push(`<div class="kv-row"><span class="k">PhishTank: ${escapeHtml(r.url || "")}</span><span class="v">${r.listed ? "KNOWN PHISHING" : "No match"}</span></div>`);
      });
      (m3.spamhaus || []).forEach(r => {
        rows.push(`<div class="kv-row"><span class="k">Spamhaus: ${escapeHtml(r.ip || "")}</span><span class="v">${r.listed ? `LISTED (${escapeHtml(r.network || "")})` : "Not listed"}</span></div>`);
      });
      if (!rows.length) return '<div style="color:var(--surface-muted);font-size:12.5px;">No indicators were available to check.</div>';
      return rows.join("");
    })();

    // Evidence sources
    const evidenceHtml = (result.evidence_sources || []).map(s => `<span class="threat-tag">${escapeHtml(s)}</span>`).join("") || '<span style="color:var(--surface-muted);font-size:12.5px;">None</span>';

    // Threat types
    const threatTypeChips = (result.threat_types || []).map(t => `<span class="threat-tag">${escapeHtml(t)}</span>`).join("") || '<span style="color:var(--surface-muted);font-size:12.5px;">No specific threat types identified.</span>';

    // Risk calculation
    const calc = (risk.calculation || {});
    const overrides = calc.overrides_applied || [];
    const overridesNote = overrides.length
      ? `<div style="color:var(--risk-high-text);font-size:12px;margin-top:6px;"><strong>Deterministic evidence controlled the final severity:</strong> ${overrides.map(o => escapeHtml(o.evidence)).join("; ")}.</div>`
      : "";

    // Reasons
    const reasonsHtml = (risk.reasons || []).map(r => `<div style="color:var(--surface-muted);font-size:12px;margin-top:2px;">• ${escapeHtml(r)}</div>`).join("") || "";

    // Build drawer body
    const drawerBody = document.getElementById("drawerBody");
    if (!drawerBody) return;

    drawerBody.innerHTML = `
      <!-- 1. Risk -->
      <div class="drawer-section">
        <h4>${ic("gauge")} Risk</h4>
        <div style="display:flex;align-items:center;gap:14px;">
          <span class="score-badge" style="color:${sevColor(sev)};">${risk.score != null ? risk.score : "—"}</span>
          <span class="badge ${sev}">${severityLabel(risk.level)}</span>
        </div>
        <div class="kv-row"><span class="k">Threat types</span><span class="v">${threatTypeChips}</span></div>
        ${overridesNote}
        ${reasonsHtml}
      </div>

      <!-- 2. User Disposition -->
      ${dispositionHtml}

      <!-- 3. Email Information -->
      <div class="drawer-section">
        <h4>${ic("mail")} Email information</h4>
        <div class="kv-row"><span class="k">Sender</span><span class="v">${escapeHtml(email.sender || "—")}</span></div>
        <div class="kv-row"><span class="k">Reply-To</span><span class="v">${escapeHtml(email.reply_to || "—")}</span></div>
        <div class="kv-row"><span class="k">Return-Path</span><span class="v">${escapeHtml(email.return_path || "—")}</span></div>
        <div class="kv-row"><span class="k">Recipient</span><span class="v">${escapeHtml(email.recipient || "—")}</span></div>
        <div class="kv-row"><span class="k">Date</span><span class="v">${escapeHtml(email.date || "—")}</span></div>
      </div>

      <!-- 4. Authentication -->
      <div class="drawer-section">
        <h4>${ic("key")} Authentication</h4>
        <div class="kv-row"><span class="k">SPF</span><span class="v">${authBadge(m1.spf)}</span></div>
        <div class="kv-row"><span class="k">DKIM</span><span class="v">${authBadge(m1.dkim)}</span></div>
        <div class="kv-row"><span class="k">DMARC</span><span class="v">${authBadge(m1.dmarc)}</span></div>
      </div>

      <!-- 5. Header / Routing -->
      <div class="drawer-section">
        <h4>${ic("route")} Header / Routing</h4>
        <div class="kv-row"><span class="k">Origin IP</span><span class="v">${escapeHtml(m1.origin_ip || "None found")}</span></div>
        <div class="kv-row"><span class="k">Reply-To mismatch</span><span class="v">${headerAnalysis.reply_to_mismatch ? "Detected" : "None"}</span></div>
        <div class="kv-row"><span class="k">Return-Path mismatch</span><span class="v">${headerAnalysis.return_path_mismatch ? "Detected" : "None"}</span></div>
      </div>

      <!-- 6. AI / Body Analysis -->
      <div class="drawer-section">
        <h4>${ic("bot")} AI / Body analysis</h4>
        <div class="kv-row"><span class="k">Phishing probability</span><span class="v">${m2.phishing_probability != null ? Math.round(m2.phishing_probability) + "%" : "—"}</span></div>
        <div class="kv-row"><span class="k">Top classification</span><span class="v">${escapeHtml((m2.top_classification || {}).label || "—")}</span></div>
        <div class="kv-row"><span class="k">Deeper scan run</span><span class="v">${m2.forensics_triggered ? "Yes" : "No"}</span></div>
        <div class="kv-row"><span class="k">Forced by attachment</span><span class="v">${m2.forensics_forced_by_attachment ? "Yes" : "No"}</span></div>
      </div>

      <!-- 7. BEC / Financial Fraud -->
      <div class="drawer-section">
        <h4>${ic("dollar")} BEC / Financial fraud</h4>
        ${becHtml}
      </div>

      <!-- 8. URL Analysis -->
      <div class="drawer-section">
        <h4>${ic("link")} URL analysis</h4>
        ${urlHtml}
      </div>

      <!-- 9. Attachment Security -->
      <div class="drawer-section">
        <h4>${ic("paperclip")} Attachment security</h4>
        ${attachHtml}
      </div>

      <!-- 10. Geolocation / Infrastructure -->
      <div class="drawer-section">
        <h4>${ic("globe")} Geolocation / infrastructure ${
          result.geo_status === "pending" ? '<span class="badge medium">ENRICHING…</span>'
          : result.geo_status === "failed" ? '<span class="badge high">LOOKUP FAILED</span>'
          : ""
        }</h4>
        ${geoHtml}
      </div>

      <!-- 11. Threat Intelligence -->
      <div class="drawer-section">
        <h4>${ic("satellite")} Threat intelligence</h4>
        ${intelHtml}
      </div>

      <!-- 12. Evidence Sources -->
      <div class="drawer-section">
        <h4>${ic("layers")} Evidence sources</h4>
        <div>${evidenceHtml}</div>
      </div>

      <!-- 13. Risk Calculation -->
      <div class="drawer-section">
        <h4>${ic("gauge")} Risk calculation</h4>
        <button class="btn btn-outline score-explain-btn" id="explainScoreBtn">${ic("help")} How was this score calculated?</button>
        <div id="scoreExplainBox" style="display:none;margin-top:10px;"></div>
      </div>
    `;

    // Risk calculation expand
    const explainBtn = document.getElementById("explainScoreBtn");
    if (explainBtn) {
      explainBtn.addEventListener("click", () => {
        const box = document.getElementById("scoreExplainBox");
        const isHidden = box.style.display === "none";
        box.style.display = isHidden ? "block" : "none";
        if (isHidden) {
          const modules = risk.contributing_modules || [];
          const reasons = risk.reasons || [];
          box.innerHTML = `
            <div class="kv-row"><span class="k">Final score</span><span class="v" style="font-weight:700;">${risk.score != null ? risk.score : "—"}/100</span></div>
            <div class="kv-row"><span class="k">Severity</span><span class="v">${escapeHtml(risk.level || "—")}</span></div>
            ${modules.length ? `<div style="margin-top:8px;font-weight:600;font-size:12px;">Contributing modules:</div>${modules.map(m => `<div style="font-size:12px;color:var(--surface-muted);margin-top:2px;">• ${escapeHtml(m)}</div>`).join("")}` : ""}
            ${reasons.length ? `<div style="margin-top:8px;font-weight:600;font-size:12px;">Reasons:</div>${reasons.map(r => `<div style="font-size:12px;color:var(--surface-muted);margin-top:2px;">• ${escapeHtml(r)}</div>`).join("")}` : ""}
          `;
        }
      });
    }

    // Drawer actions
    const actions = document.getElementById("drawerActions");
    if (actions) {
      actions.innerHTML = `
        ${isTrusted
          ? `<button class="btn btn-ghost" id="removeTrustDrawerBtn">${ic("shield")} Remove Trust</button>`
          : `<button class="btn btn-outline" id="markSafeBtn">${ic("shield")} Mark Safe</button>`}
        ${(risk.level === "HIGH" || risk.level === "CRITICAL") ? `<button class="btn btn-danger" id="reportThreatBtn">${ic("flag")} Report Threat</button>` : ""}
      `;
      const markBtn = document.getElementById("markSafeBtn");
      if (markBtn) markBtn.addEventListener("click", () => confirmMarkSafe(result));
      const removeBtn = document.getElementById("removeTrustDrawerBtn");
      if (removeBtn) removeBtn.addEventListener("click", () => removeTrust(sender, true));
      const reportBtn = document.getElementById("reportThreatBtn");
      if (reportBtn) reportBtn.addEventListener("click", () => openReportThreatModal(result));
    }

    if (drawerOverlay) drawerOverlay.classList.add("open");
    if (drawer) drawer.classList.add("open");
  }

  // ============================================================
  // TRUSTED SENDERS (localStorage persistence)
  // ============================================================

  function saveTrusted() {
    localStorage.setItem("vp_trustedSenders", JSON.stringify(state.trustedSenders));
  }

  function confirmMarkSafe(result) {
    const sender = (result.email || {}).sender || "";
    if (!sender) return;
    openModal(`
      <h3>${ic("shield")} Mark sender as safe?</h3>
      <p>This is a <strong>user disposition only</strong>. The original automated analysis and risk score will be preserved unchanged.</p>
      <p><strong>Sender:</strong> ${escapeHtml(sender)}</p>
      <div class="modal-actions">
        <button class="btn btn-ghost" id="cancelMarkSafe">Cancel</button>
        <button class="btn btn-primary" id="confirmMarkSafe">${ic("shield")} Confirm</button>
      </div>
    `);
    document.getElementById("cancelMarkSafe").addEventListener("click", closeModal);
    document.getElementById("confirmMarkSafe").addEventListener("click", () => {
      state.trustedSenders[sender] = {
        dateTrusted: new Date().toLocaleDateString(),
        account: state.accountEmail || "unknown",
      };
      saveTrusted();
      closeModal();
      toast("Sender marked as trusted", "shield");
      openEmailWorkspace(result); // Re-render workspace
    });
  }

  function removeTrust(senderEmail, reopenDrawer) {
    delete state.trustedSenders[senderEmail];
    saveTrusted();
    toast("Trust removed — sender treated per automated analysis");
    renderInboxTable();
    if (reopenDrawer) {
      const result = Object.values(state.resultsByMessageId).find(r => (r.email || {}).sender === senderEmail);
      if (result) openEmailWorkspace(result);
    }
  }

  function openReportThreatModal(result) {
    const email = result.email || {};
    const risk = result.risk || {};
    openModal(`
      <h3>${ic("flag")} Report this threat?</h3>
      <p><strong>Subject:</strong> ${escapeHtml(email.subject || "—")}</p>
      <p><strong>Sender:</strong> ${escapeHtml(email.sender || "—")}</p>
      <p><strong>Risk:</strong> ${escapeHtml(risk.level || "—")} (${risk.score || "—"}/100)</p>
      <p style="color:var(--surface-muted);font-size:12px;">This would flag the message for organizational review. Feature placeholder in current build.</p>
      <div class="modal-actions">
        <button class="btn btn-ghost" id="cancelReport">Cancel</button>
        <button class="btn btn-danger" id="confirmReport">${ic("flag")} Report</button>
      </div>
    `);
    document.getElementById("cancelReport").addEventListener("click", closeModal);
    document.getElementById("confirmReport").addEventListener("click", () => {
      closeModal();
      toast("Threat reported (placeholder)", "flag");
    });
  }

  // ============================================================
  // MODAL SYSTEM
  // ============================================================

  const modalOverlay = document.getElementById("modalOverlay");

  function openModal(html) {
    const box = document.getElementById("modalBox");
    if (box) box.innerHTML = html;
    if (modalOverlay) modalOverlay.classList.add("open");
  }

  function closeModal() {
    if (modalOverlay) modalOverlay.classList.remove("open");
  }

  if (modalOverlay) {
    modalOverlay.addEventListener("click", e => { if (e.target === modalOverlay) closeModal(); });
  }

  // ============================================================
  // HOME VIEW
  // ============================================================

  async function renderHome() {
    const counts = updateSummaryCards();
    const homeStats = document.getElementById("homeStats");
    const mailboxLine = document.getElementById("homeMailboxLine");

    if (mailboxLine) {
      mailboxLine.textContent = state.provider
        ? `Connected · ${state.provider === "google" ? "Gmail" : "Microsoft"} · ${state.accountEmail}`
        : "No mailbox connected";
    }

    if (homeStats) {
      const totalScanned = Object.values(state.resultsByMessageId).filter(r => r.status && r.status !== "unscanned").length;
      homeStats.innerHTML = `
        <div class="stat-card mailbox"><div class="label">Mailbox</div><div class="value" style="font-size:16px;">${state.provider ? (state.provider === "google" ? "Gmail" : "Microsoft") + " Connected" : "No mailbox connected"}</div><div class="sub">${totalScanned} emails scanned</div></div>
        <div class="stat-card" data-severity="safe"><div class="label">Safe</div><div class="value">${counts.LOW}</div><div class="sub">No action needed</div></div>
        <div class="stat-card medium" data-severity="medium"><div class="label">Medium Risk</div><div class="value">${counts.MEDIUM}</div><div class="sub">Review recommended</div></div>
        <div class="stat-card high" data-severity="high"><div class="label">High Risk</div><div class="value">${counts.HIGH}</div><div class="sub">Likely malicious</div></div>
        <div class="stat-card critical" data-severity="critical"><div class="label">Critical</div><div class="value">${counts.CRITICAL}</div><div class="sub">Blocked automatically</div></div>
      `;
    }

    // Recent detections from scan history
    const detections = document.getElementById("recentDetections");
    if (detections) {
      const risky = Object.values(state.resultsByMessageId)
        .filter(r => r.risk && (r.risk.level === "HIGH" || r.risk.level === "CRITICAL"))
        .sort((a, b) => (b.risk.score || 0) - (a.risk.score || 0))
        .slice(0, 6);
      detections.innerHTML = risky.length ? risky.map(r => {
        const email = r.email || {};
        const sev = severityClass(r.risk.level);
        return `<div class="detection-item" data-mid="${escapeHtml(r.message_id)}">
          <span class="sev-dot ${sev}"></span>
          <div style="flex-grow:1;"><div style="font-weight:600;">${escapeHtml(email.sender || "—")}</div><div class="detection-subject">${escapeHtml(email.subject || "")}</div></div>
          <span class="meta">${r.risk.score || "—"}/100<br>${timeAgo(r.analyzed_at || email.date)}</span>
        </div>`;
      }).join("") : '<div style="color:var(--surface-muted);font-size:13px;padding:14px 0;">No risky detections yet. Scan your inbox to start.</div>';
      detections.querySelectorAll(".detection-item").forEach(el => {
        el.addEventListener("click", () => {
          const mid = el.getAttribute("data-mid");
          const result = state.resultsByMessageId[mid];
          if (result) { setActiveView("inbox"); openEmailWorkspace(result); }
        });
      });
    }

    // Recent activity
    const activity = document.getElementById("recentActivity");
    if (activity) {
      const totalScanned = Object.values(state.resultsByMessageId).filter(r => r.status && r.status !== "unscanned").length;
      const critCount = Object.values(state.resultsByMessageId).filter(r => r.risk && r.risk.level === "CRITICAL").length;
      const trustedCount = Object.keys(state.trustedSenders).length;
      const items = [];
      if (totalScanned > 0) items.push({ icon: "scan", text: `${totalScanned} message(s) analyzed this session` });
      if (trustedCount > 0) items.push({ icon: "shield", text: `${trustedCount} sender(s) currently marked user-trusted` });
      if (critCount > 0) items.push({ icon: "warning", text: `${critCount} critical threat(s) detected` });
      items.push({ icon: "plug", text: state.provider ? `${state.provider === "google" ? "Gmail" : "Microsoft"} connected via OAuth` : "No account currently connected" });
      activity.innerHTML = items.map(a => `<div class="activity-item">${ic(a.icon)}<span>${a.text}</span></div>`).join("");
    }

    renderRefreshLabels();
  }

  // ============================================================
  // INBOX VIEW (wrapper)
  // ============================================================

  function renderInbox() {
    const pageSizeSelect = document.getElementById("pageSizeSelect");
    if (pageSizeSelect) pageSizeSelect.value = String(state.pageSize);
    const inboxSearch = document.getElementById("inboxSearch");
    if (inboxSearch) inboxSearch.value = state.search;
    const headerSearch = document.getElementById("inboxHeaderSearch");
    if (headerSearch) headerSearch.value = state.search;
    renderRefreshLabels();
    renderInboxTable();
  }

  // ============================================================
  // DASHBOARD VIEW (real data)
  // ============================================================

  async function renderDashboard() {
    renderRefreshLabels();

    // Bottom widgets
    const bottomWidgets = document.getElementById("bottomWidgets");
    if (bottomWidgets) {
      const trustedCount = Object.keys(state.trustedSenders).length;
      bottomWidgets.innerHTML = `
        <div class="bw-card" id="trustedSendersCard" role="button" tabindex="0">
          <div class="bw-top">${ic("shield", "bw-icon")}<span class="bw-label">Trusted senders</span></div>
          <span class="bw-value">${trustedCount}</span>
          <span class="bw-sub">Senders trusted by the user</span>
          <span class="bw-link">Manage ${ic("chevron-right")}</span>
        </div>
        <div class="bw-card" id="openCasesCard" role="button" tabindex="0">
          <div class="bw-top">${ic("mail", "bw-icon")}<span class="bw-label">Open cases</span></div>
          <span class="bw-value">—</span>
          <span class="bw-sub">Cases requiring attention</span>
          <span class="bw-link">View cases ${ic("chevron-right")}</span>
        </div>
      `;
      const tsCard = document.getElementById("trustedSendersCard");
      if (tsCard) tsCard.addEventListener("click", () => setActiveView("user"));
      const caseCard = document.getElementById("openCasesCard");
      if (caseCard) caseCard.addEventListener("click", () => {
        const pillBtn = document.querySelector('.pill-btn[data-index="1"]');
        if (pillBtn) pillBtn.click();
      });
    }

    // Threat vectors (real)
    if (state.provider) {
      try {
        const intel = await apiGet("/api/threat-intel/summary");
        const threatList = document.getElementById("threatVectorList");
        if (threatList) {
          threatList.innerHTML = intel.sources.map(s => `
            <div class="threat-bar">
              <span class="threat-bar-left">${ic(s.name.includes("PhishTank") ? "satellite" : s.name.includes("Spamhaus") ? "globe" : "warning", "threat-icon")}<span>${escapeHtml(s.name)}</span></span>
              <span class="count">${s.matches} match${s.matches !== 1 ? "es" : ""}</span>
            </div>
          `).join("") || `<div class="threat-bar"><span class="threat-bar-left">${ic("shield", "threat-icon")}<span>No threats detected yet</span></span></div>`;
        }
      } catch (err) {
        const threatList = document.getElementById("threatVectorList");
        if (threatList) threatList.innerHTML = `<div style="color:var(--surface-muted);font-size:12.5px;">Failed to load threat data.</div>`;
      }

      // Cases widget
      try {
        const casesData = await apiGet("/api/cases");
        const casesPage = document.getElementById("casesPage");
        if (casesPage) {
          casesPage.innerHTML = casesData.cases.length
            ? `<h2 style="margin-bottom:10px;color:var(--surface-text);">Open cases</h2>` +
              casesData.cases.slice(0, 5).map(c => `
                <div class="detection-item">
                  <span class="sev-dot ${c.highest_risk === "CRITICAL" ? "critical" : "high"}"></span>
                  <div style="flex-grow:1;">
                    <div style="font-weight:600;">${escapeHtml(c.domain)}</div>
                    <div style="color:var(--surface-muted);font-size:11px;">${c.message_count} message(s) · ${c.distinct_senders} sender(s)</div>
                  </div>
                  <span class="badge ${c.highest_risk === "CRITICAL" ? "critical" : "high"}">${escapeHtml(c.highest_risk)}</span>
                </div>
              `).join("")
            : '<div style="color:var(--surface-muted);font-size:12.5px;padding:20px;">No cases yet.</div>';
          // Update open cases count
          const ocCard = document.getElementById("openCasesCard");
          if (ocCard) {
            const val = ocCard.querySelector(".bw-value");
            if (val) val.textContent = casesData.cases.length;
          }
        }
      } catch (_) {}

      // Risky mails widget
      try {
        const history = await apiGet("/api/scans/history");
        const riskyPage = document.getElementById("riskyPage");
        if (riskyPage) {
          riskyPage.innerHTML = `<h2 style="margin-bottom:10px;color:var(--surface-text);">Risky mail snapshot</h2>
            <div style="font-size:13px;color:var(--surface-muted);margin-bottom:14px;">High and critical severity mail from recent scans.</div>
            <div style="overflow-y:auto;">${
              history.items.slice(0, 6).map(i => `
                <div class="detection-item"><span class="sev-dot ${severityClass((i.risk || {}).level)}"></span>
                  <span>${escapeHtml(i.sender || "—")} — ${escapeHtml(i.subject || "")}</span>
                  <span class="meta">${(i.risk || {}).score || "—"}</span>
                </div>
              `).join("") || '<div style="color:var(--surface-muted);font-size:12.5px;">No risky mails yet.</div>'
            }</div>`;
        }
      } catch (_) {}

      // Geo widget
      try {
        const geo = await apiGet("/api/threat-geo/summary");
        const geoPage = document.getElementById("geoPage");
        if (geoPage) {
          geoPage.innerHTML = `<h2 style="margin-bottom:10px;color:var(--surface-text);">Top origin countries</h2>
            <div style="overflow-y:auto;">${
              geo.locations.slice(0, 6).map(l => `
                <div class="geo-row">${ic("pin", "geo-pin")}<span style="flex-grow:1;">${escapeHtml(l.country)}</span><span style="font-weight:700;">${l.suspicious_count}</span></div>
              `).join("") || '<div style="color:var(--surface-muted);font-size:12.5px;">No geolocation data yet.</div>'
            }</div>`;
        }
      } catch (_) {}
    }

    // Chart.js (graceful degradation)
    renderDashboardChart();
  }

  function renderDashboardChart() {
    if (typeof Chart === "undefined") return;
    const canvas = document.getElementById("analysisChart");
    if (!canvas) return;

    // Destroy existing chart
    if (canvas._chartInstance) {
      canvas._chartInstance.destroy();
    }

    if (!state.provider) return;

    apiGet("/api/threat-geo/trend?period=day").then(data => {
      const labels = data.trend.map(t => t.period);
      const suspicious = data.trend.map(t => t.suspicious_count);
      const critical = data.trend.map(t => t.critical_count);
      const high = data.trend.map(t => t.high_count);

      try {
        canvas._chartInstance = new Chart(canvas, {
          type: "line",
          data: {
            labels,
            datasets: [
              { label: "Suspicious", data: suspicious, borderColor: cssVar("--warning") || "#FFC107", tension: 0.3, fill: false },
              { label: "High", data: high, borderColor: cssVar("--high") || "#d39999", tension: 0.3, fill: false },
              { label: "Critical", data: critical, borderColor: cssVar("--danger") || "#E81123", tension: 0.3, fill: false },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: cssVar("--surface-text") || "#fff" } } },
            scales: {
              x: { ticks: { color: cssVar("--surface-muted") || "#888" } },
              y: { ticks: { color: cssVar("--surface-muted") || "#888" }, beginAtZero: true },
            },
          },
        });
      } catch (_) { /* Chart.js failure is non-fatal */ }
    }).catch(() => {});
  }

  // ============================================================
  // REPORTS VIEW (real data)
  // ============================================================

  async function renderReports() {
    if (!state.provider) {
      const dist = document.getElementById("riskDistribution");
      if (dist) dist.innerHTML = '<div style="color:var(--surface-muted);font-size:12.5px;">Connect a mailbox and run a scan to generate reports.</div>';
      return;
    }

    try {
      const r = await apiGet("/api/reports/summary");
      const reportRange = document.getElementById("reportRangeLine");
      if (reportRange) reportRange.textContent = `${r.total_analyzed} emails analyzed`;

      // Risk distribution
      const dist = document.getElementById("riskDistribution");
      if (dist) {
        const total = r.total_analyzed || 1;
        const breakdown = r.risk_breakdown || {};
        dist.innerHTML = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(level => {
          const count = breakdown[level] || 0;
          const pct = Math.round((count / total) * 100);
          const sev = severityClass(level);
          return `<div style="margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;font-weight:600;"><span style="text-transform:capitalize;color:${sevColor(sev)};">${severityLabel(level)}</span><span style="color:var(--surface-text);">${count} (${pct}%)</span></div>
            <div style="background:var(--surface-border);border-radius:6px;height:8px;overflow:hidden;"><div style="width:${pct}%;height:100%;background:${sev === "safe" ? cssVar("--safe") : sevColor(sev)};"></div></div>
          </div>`;
        }).join("");
      }

      // Threat types
      const threatBreak = document.getElementById("threatTypeBreakdown");
      if (threatBreak) {
        const cats = r.top_categories || [];
        threatBreak.innerHTML = cats.length
          ? cats.map(c => `<div class="kv-row"><span class="k">${escapeHtml(c.category)}</span><span class="v">${c.count}</span></div>`).join("")
          : '<div style="color:var(--surface-muted);font-size:12.5px;">No threats detected yet.</div>';
      }

      // Scan history
      const history = await apiGet("/api/scans/history");
      const historyTbody = document.querySelector("#scanHistoryTable tbody");
      if (historyTbody) {
        historyTbody.innerHTML = history.items.length
          ? history.items.slice(0, 20).map((item, i) => `
            <tr>
              <td>Scan #${i + 1}</td>
              <td>${escapeHtml(item.date || "—")}</td>
              <td>1</td>
              <td><span class="badge ${severityClass((item.risk || {}).level)}">${severityLabel((item.risk || {}).level)}</span></td>
              <td></td>
            </tr>
          `).join("")
          : '<tr><td colspan="5" style="color:var(--surface-muted);padding:14px 10px;">No scan history yet.</td></tr>';
      }
    } catch (err) {
      toast("Failed to load reports: " + errText(err));
    }
  }

  // ============================================================
  // CUSTOM EMAIL VIEW (real .eml upload)
  // ============================================================

  function renderCustom() {
    const list = document.getElementById("customAnalysesList");
    if (!list) return;
    if (!state.customAnalyses.length) {
      list.innerHTML = `<div class="empty-state" style="height:160px;">${ic("file-question")}<span>No custom analyses yet</span></div>`;
      return;
    }
    list.innerHTML = state.customAnalyses.map((r, i) => {
      const email = r.email || {};
      const risk = r.risk || {};
      const sev = severityClass(risk.level);
      return `<div class="detection-item" data-idx="${i}" style="cursor:pointer;">
        <span class="sev-dot ${sev}"></span>
        <div style="flex-grow:1;"><div style="font-weight:600;">${escapeHtml(r.source_filename || email.subject || "—")}</div><div style="color:var(--surface-muted);font-size:11px;">Risk ${risk.score || "—"}/100</div></div>
        <span class="badge ${sev}">${severityLabel(risk.level)}</span>
      </div>`;
    }).join("");
    list.querySelectorAll(".detection-item").forEach(el => {
      el.addEventListener("click", () => {
        const idx = parseInt(el.getAttribute("data-idx"), 10);
        const result = state.customAnalyses[idx];
        if (result) openEmailWorkspace(result);
      });
    });
  }

  // Custom upload setup
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("fileInput");
  const analyzeCustomBtn = document.getElementById("analyzeCustomBtn");
  const chooseFileBtn = document.getElementById("chooseFileBtn");

  if (chooseFileBtn && fileInput) {
    chooseFileBtn.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", () => {
      if (fileInput.files[0]) selectCustomFile(fileInput.files[0]);
    });
  }

  if (dropzone) {
    ["dragenter", "dragover"].forEach(evt => dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.add("drag"); }));
    ["dragleave", "drop"].forEach(evt => dropzone.addEventListener(evt, e => { e.preventDefault(); dropzone.classList.remove("drag"); }));
    dropzone.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) selectCustomFile(f); });
  }

  function selectCustomFile(f) {
    state.chosenFile = f;
    const nameEl = document.getElementById("chosenFileName");
    if (nameEl) nameEl.textContent = `Selected: ${f.name}`;
    if (analyzeCustomBtn) analyzeCustomBtn.disabled = false;
  }

  if (analyzeCustomBtn) {
    analyzeCustomBtn.addEventListener("click", async () => {
      if (!state.chosenFile) return;
      analyzeCustomBtn.disabled = true;
      analyzeCustomBtn.innerHTML = ic("spinner", "icon-spin") + " Analyzing...";

      const formData = new FormData();
      formData.append("file", state.chosenFile);

      try {
        const result = await apiPost("/api/analyze", { body: formData });
        result.source_filename = state.chosenFile.name;
        state.customAnalyses.unshift(result);
        renderCustom();
        toast("Custom email analyzed");
      } catch (err) {
        toast("Analysis failed: " + errText(err));
      } finally {
        analyzeCustomBtn.innerHTML = "Analyze";
        analyzeCustomBtn.disabled = true;
        const nameEl = document.getElementById("chosenFileName");
        if (nameEl) nameEl.textContent = "";
        state.chosenFile = null;
      }
    });
  }

  // ============================================================
  // USER VIEW (real accounts + trusted senders)
  // ============================================================

  function renderUser() {
    // Connected accounts
    const accountsEl = document.getElementById("connectedAccounts");
    if (accountsEl) {
      const accounts = [
        { id: "google", provider: "Gmail", status: state.googleStatus },
        { id: "microsoft", provider: "Microsoft", status: state.microsoftStatus },
      ];

      accountsEl.innerHTML = accounts.map(acc => {
        const connected = acc.status.connected;
        const email = acc.status.email;
        const isActive = state.provider === acc.id;
        let actionBtn;
        if (!connected) {
          actionBtn = `<button class="btn btn-outline btn-sm" data-connect="${acc.id}">Connect</button>`;
        } else {
          actionBtn = `<button class="btn btn-ghost btn-sm" data-disconnect="${acc.id}">Disconnect</button>`;
        }

        return `<div class="connected-account ${connected ? "" : "disconnected"}">
          <span class="dot ${isActive ? "active" : ""}"></span>
          <div style="flex-grow:1;">
            <strong>${escapeHtml(acc.provider)}</strong> ${isActive ? '<span class="active-badge">ACTIVE</span>' : ""}
            <div style="font-size:11px;color:var(--surface-muted);">${connected ? escapeHtml(email || "") : "Not connected"}</div>
          </div>
          <div style="display:flex;gap:8px;">${actionBtn}</div>
        </div>`;
      }).join("");

      accountsEl.querySelectorAll("[data-connect]").forEach(btn => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-connect");
          window.location.href = `/auth/${id === "google" ? "google" : "microsoft"}/login`;
        });
      });
      accountsEl.querySelectorAll("[data-disconnect]").forEach(btn => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-disconnect");
          doLogout(id);
        });
      });
    }

    // Trusted senders table
    const entries = Object.entries(state.trustedSenders);
    const tbody = document.querySelector("#trustedSendersTable tbody");
    const emptyState = document.getElementById("trustedEmptyState");
    if (tbody) {
      if (!entries.length) {
        tbody.innerHTML = "";
        if (emptyState) emptyState.style.display = "flex";
      } else {
        if (emptyState) emptyState.style.display = "none";
        tbody.innerHTML = entries.map(([sender, info]) => `
          <tr><td>${escapeHtml(sender)}</td><td>${escapeHtml(info.dateTrusted || "—")}</td><td>${escapeHtml(info.account || "—")}</td>
          <td><button class="btn btn-ghost btn-sm remove-trust-row" data-sender="${escapeHtml(sender)}">Remove Trust</button></td></tr>
        `).join("");
        tbody.querySelectorAll(".remove-trust-row").forEach(b => {
          b.addEventListener("click", () => {
            removeTrust(b.getAttribute("data-sender"), false);
            renderUser();
          });
        });
      }
    }

    // Session information
    const sessionStart = document.getElementById("sessionStartedVal");
    if (sessionStart) sessionStart.textContent = state.lastRefreshedAt ? fmtDate(state.lastRefreshedAt) : "Current session";
    const sessionDevice = document.getElementById("sessionDeviceVal");
    if (sessionDevice) {
      const ua = navigator.userAgent;
      let browser = "Browser";
      if (ua.includes("Chrome")) browser = "Chrome";
      else if (ua.includes("Firefox")) browser = "Firefox";
      else if (ua.includes("Safari")) browser = "Safari";
      let os = "";
      if (ua.includes("Windows")) os = " · Windows";
      else if (ua.includes("Mac")) os = " · macOS";
      else if (ua.includes("Linux")) os = " · Linux";
      sessionDevice.textContent = browser + os;
    }
    const sessionIp = document.getElementById("sessionIpVal");
    if (sessionIp) sessionIp.textContent = "Local session";
    const sessionRetention = document.getElementById("sessionRetentionVal");
    if (sessionRetention) sessionRetention.textContent = "Session-scoped (in-memory)";

    // Recent activity
    const activityEl = document.getElementById("userRecentActivity");
    if (activityEl) {
      const totalScanned = Object.values(state.resultsByMessageId).filter(r => r.status && r.status !== "unscanned").length;
      const items = [];
      if (totalScanned > 0) items.push({ icon: "scan", text: `${totalScanned} message(s) analyzed this session` });
      items.push({ icon: "shield", text: `${Object.keys(state.trustedSenders).length} sender(s) currently marked user-trusted` });
      items.push({ icon: "plug", text: state.provider ? `${state.provider === "google" ? "Gmail" : "Microsoft"} connected` : "No account connected" });
      activityEl.innerHTML = items.map(a => `<div class="activity-item">${ic(a.icon)}<span>${a.text}</span></div>`).join("");
    }
  }

  // ============================================================
  // SETTINGS VIEW
  // ============================================================

  function saveSettings() {
    localStorage.setItem("vp_settings", JSON.stringify(state.settings));
  }

  function initSettings() {
    // Toggle switches
    document.querySelectorAll(".switch[data-setting]").forEach(sw => {
      const key = sw.getAttribute("data-setting");
      sw.classList.toggle("on", !!state.settings[key]);
    });

    // Theme label
    const label = document.getElementById("currentThemeLabel");
    if (label) label.textContent = `Current: ${THEME_LABELS[state.theme] || "Default"}`;
  }

  // Settings switch handlers
  document.querySelectorAll(".switch[data-setting]").forEach(sw => {
    const key = sw.getAttribute("data-setting");
    if (state.settings[key]) sw.classList.add("on");
    sw.addEventListener("click", () => {
      state.settings[key] = !state.settings[key];
      sw.classList.toggle("on", state.settings[key]);
      saveSettings();
      toast(`${key} ${state.settings[key] ? "enabled" : "disabled"}`);
    });
  });

  // Theme modal
  function themeSwatchHtml(name, label) {
    return `<button class="theme-swatch ${state.theme === name ? "active" : ""}" data-theme-choice="${name}">
      <div class="swatch-preview ${name}"></div>
      <span>${label}</span>
    </button>`;
  }

  const changeThemeBtn = document.getElementById("changeThemeBtn");
  if (changeThemeBtn) {
    changeThemeBtn.addEventListener("click", () => {
      openModal(`
        <h3>${ic("palette")} Choose theme</h3>
        <div class="theme-swatches">
          ${themeSwatchHtml("default", "Default")}
          ${themeSwatchHtml("dark", "Dark")}
          ${themeSwatchHtml("light", "Light")}
          ${themeSwatchHtml("purple", "Purple")}
        </div>
        <div class="modal-actions">
          <button class="btn btn-ghost" id="closeThemeModal">Close</button>
        </div>
      `);
      document.getElementById("closeThemeModal").addEventListener("click", closeModal);
      document.querySelectorAll("[data-theme-choice]").forEach(btn => {
        btn.addEventListener("click", () => {
          applyTheme(btn.getAttribute("data-theme-choice"));
          closeModal();
          toast("Theme updated", "palette");
          renderDashboardChart(); // Re-render chart with new theme colors
        });
      });
    });
  }

  // Go to trusted senders from settings
  const goToTrustedBtn = document.getElementById("goToTrustedBtn");
  if (goToTrustedBtn) {
    goToTrustedBtn.addEventListener("click", () => {
      setActiveView("user");
      setTimeout(() => {
        const table = document.getElementById("trustedSendersTable");
        if (table) table.scrollIntoView({ behavior: "smooth", block: "center" });
      }, 80);
    });
  }

  // ============================================================
  // LOGOUT
  // ============================================================

  async function doLogout(providerToLogout) {
    const provider = providerToLogout || state.provider;
    if (!provider) return;

    try {
      await apiPost(`/auth/${provider}/logout`);
    } catch (err) {
      toast("Logout request failed: " + errText(err));
    }

    // Client state reset
    if (state.scanPollHandle) clearInterval(state.scanPollHandle);
    if (provider === state.provider) {
      state.provider = null;
      state.accountEmail = null;
      state.currentMessageIds = [];
      state.resultsByMessageId = {};
      state.scanId = null;
      state.pageTokenStack = [null];
      state.currentPageIndex = 0;
      state.nextPageToken = null;
    }

    await refreshConnectionStatus();
    renderInboxTable();
    updateSummaryCards();
    renderHome();
    toast("Logged out", "logout");
  }

  const logoutBtn = document.getElementById("logoutBtn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      openModal(`
        <h3>Are you sure you want to log out?</h3>
        <p>Your session will end. Trusted senders and settings stay saved on this device.</p>
        <div class="modal-actions">
          <button class="btn btn-ghost" id="cancelLogoutBtn">Cancel</button>
          <button class="btn btn-danger" id="confirmLogoutBtn">Log Out</button>
        </div>
      `);
      document.getElementById("cancelLogoutBtn").addEventListener("click", closeModal);
      document.getElementById("confirmLogoutBtn").addEventListener("click", () => {
        closeModal();
        doLogout();
      });
    });
  }

  // ============================================================
  // INBOX EVENT HANDLERS
  // ============================================================

  // Search
  let searchDebounce;
  const inboxSearch = document.getElementById("inboxSearch");
  if (inboxSearch) {
    inboxSearch.addEventListener("input", e => {
      clearTimeout(searchDebounce);
      const headerSearch = document.getElementById("inboxHeaderSearch");
      if (headerSearch) headerSearch.value = e.target.value;
      searchDebounce = setTimeout(() => { state.search = e.target.value; renderInboxTable(); }, 250);
    });
  }
  let headerSearchDebounce;
  const headerSearch = document.getElementById("inboxHeaderSearch");
  if (headerSearch) {
    headerSearch.addEventListener("input", e => {
      clearTimeout(headerSearchDebounce);
      const inboxSearch2 = document.getElementById("inboxSearch");
      if (inboxSearch2) inboxSearch2.value = e.target.value;
      headerSearchDebounce = setTimeout(() => { state.search = e.target.value; renderInboxTable(); }, 250);
    });
  }

  // Filters
  ["filterSeverity", "filterThreat", "filterTrust", "filterRead"].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", e => {
        const key = id.replace("filter", "").toLowerCase();
        state.filters[key] = e.target.value;
        renderInboxTable();
      });
    }
  });

  // Page size
  const pageSizeSelect = document.getElementById("pageSizeSelect");
  if (pageSizeSelect) {
    pageSizeSelect.addEventListener("change", e => {
      state.pageSize = parseInt(e.target.value, 10);
      loadEmailPage(null, 0);
    });
  }

  // Pagination
  const prevPageBtn = document.getElementById("prevPageBtn");
  if (prevPageBtn) {
    prevPageBtn.addEventListener("click", () => {
      if (state.currentPageIndex === 0) return;
      const prevIndex = state.currentPageIndex - 1;
      loadEmailPage(state.pageTokenStack[prevIndex], prevIndex);
    });
  }
  const nextPageBtn = document.getElementById("nextPageBtn");
  if (nextPageBtn) {
    nextPageBtn.addEventListener("click", () => {
      if (!state.nextPageToken) return;
      loadEmailPage(state.nextPageToken, state.currentPageIndex + 1);
    });
  }

  // Scan button
  const scanInboxBtn = document.getElementById("scanInboxBtn");
  if (scanInboxBtn) scanInboxBtn.addEventListener("click", startScan);

  // Sync buttons
  const syncBtn = document.getElementById("syncBtn");
  if (syncBtn) syncBtn.addEventListener("click", () => refreshMailbox(syncBtn));
  const homeSyncBtn = document.getElementById("homeSyncBtn");
  if (homeSyncBtn) homeSyncBtn.addEventListener("click", () => refreshMailbox(homeSyncBtn, renderHome));
  const inboxSyncBtn = document.getElementById("inboxSyncBtn");
  if (inboxSyncBtn) inboxSyncBtn.addEventListener("click", () => refreshMailbox(inboxSyncBtn));

  // Quick actions
  document.querySelectorAll(".quick-action-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const action = btn.getAttribute("data-action");
      if (action === "scan-inbox") { setActiveView("inbox"); startScan(); }
      else if (action === "custom-email") { setActiveView("custom"); }
      else if (action === "risky-mails") {
        state.filters.severity = "high";
        setActiveView("inbox");
        const sel = document.getElementById("filterSeverity");
        if (sel) sel.value = "high";
      }
      else if (action === "reports") { setActiveView("reports"); }
    });
  });

  // Dashboard pill navigation
  const pillNav = document.getElementById("pillNav");
  if (pillNav) {
    const pillBtns = pillNav.querySelectorAll(".pill-btn");
    const pillIndicator = document.getElementById("pillIndicator");
    const widgetContainer = document.getElementById("widgetContainer");

    function updatePillIndicator(activeBtn) {
      if (pillIndicator && activeBtn) {
        pillIndicator.style.width = activeBtn.offsetWidth + "px";
        pillIndicator.style.left = activeBtn.offsetLeft + "px";
      }
    }

    pillBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        pillBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        const idx = parseInt(btn.getAttribute("data-index"), 10);
        if (widgetContainer) widgetContainer.style.transform = `translateX(-${idx * 100}%)`;
        updatePillIndicator(btn);
      });
    });

    // Initial pill indicator position
    setTimeout(() => {
      const activeBtn = pillNav.querySelector(".pill-btn.active");
      if (activeBtn) updatePillIndicator(activeBtn);
    }, 100);
  }

  // Time toggle buttons for chart
  document.querySelectorAll(".time-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".time-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      // Could re-fetch with different period but keeping simple
    });
  });

  // Export report
  const exportBtn = document.getElementById("exportReportBtn");
  if (exportBtn) {
    exportBtn.addEventListener("click", () => toast("Report export is a planned feature", "file-export"));
  }

  // Report range
  const changeRangeBtn = document.getElementById("changeRangeBtn");
  if (changeRangeBtn) {
    changeRangeBtn.addEventListener("click", () => toast("Date range filtering uses real backend data", "calendar"));
  }

  // ============================================================
  // INIT — runs on every page load (including OAuth callback redirect)
  // ============================================================

  setActiveView("home");
  refreshConnectionStatus();

})();
