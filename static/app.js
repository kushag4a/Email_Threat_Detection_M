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
    // Which OAuth providers this server has credentials for (from /auth/status).
    // null = unknown yet; the UI then treats the provider as available.
    providersConfigured: { google: null, microsoft: null },

    // "booting" -> "welcome" (first launch, nothing chosen) | "anonymous" | "connected"
    authPhase: "booting",
    activeView: "home",

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

    // Dashboard data (real backend data only)
    dashboardData: null,
    chartPeriod: "daily",     // daily | weekly | monthly -> day | week | month
    threatData: null,         // /api/dashboard/threat-vectors payload
  };

  // Apply persisted theme
  applyTheme(state.theme);

  // ============================================================
  // SIDEBAR NAVIGATION
  // ============================================================

  const navItems = document.querySelectorAll(".nav-links li[data-view]");
  const views = document.querySelectorAll(".view");

  // Views that need a connected mailbox. In anonymous mode they are
  // disabled in the sidebar and guarded here, so no code path (quick
  // action, deep link from a card, keyboard) can land on them.
  const MAILBOX_VIEWS = new Set(["inbox", "dashboard", "reports"]);
  const VIEW_LABELS = { inbox: "Inbox", dashboard: "Dashboard", reports: "Reports" };

  function setActiveView(name) {
    if (MAILBOX_VIEWS.has(name) && !state.provider) {
      toast(`Sign in or connect a mailbox to use ${VIEW_LABELS[name] || name}.`, "plug");
      return false;
    }
    state.activeView = name;
    views.forEach(v => v.classList.toggle("active", v.id === "view-" + name));
    navItems.forEach(li => li.classList.toggle("active", li.getAttribute("data-view") === name));
    renderActiveView();
    if (name === "dashboard") requestAnimationFrame(() => updatePillIndicator());
    return true;
  }

  function renderActiveView() {
    const name = state.activeView;
    if (name === "home") renderHome();
    if (name === "inbox") renderInbox();
    if (name === "dashboard") renderDashboard();
    if (name === "reports") renderReports();
    if (name === "custom") renderCustom();
    if (name === "user") renderUser();
    if (name === "settings") initSettings();
  }

  navItems.forEach(li => {
    li.addEventListener("click", () => {
      if (li.classList.contains("disabled")) {
        setActiveView(li.getAttribute("data-view")); // shows the explanatory toast
        return;
      }
      setActiveView(li.getAttribute("data-view"));
    });
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
  //
  // BUG FIX ("must log in twice"): the old startup rendered Home from
  // `state.provider === null`, THEN fired the status requests without
  // awaiting them, and when the answers arrived it updated only the
  // sidebar and the inbox table - never Home/Dashboard. So after a
  // successful OAuth round trip the sidebar said "Gmail ..." while Home
  // still said "No mailbox connected", and the user logged in again.
  // Now: bootstrap() waits for the real status ONCE, decides the auth
  // phase, and renders exactly once with the right state. Any later
  // status change goes through the same applyAuthPhase() +
  // renderActiveView() path.
  // ============================================================

  const AUTH_CHOICE_KEY = "vp_auth_choice"; // sessionStorage: "skipped" = anonymous this launch
  const DEFAULT_AVATAR = "/assets/default-avatar.svg";
  const PROVIDER_LABELS = { google: "Gmail", microsoft: "Microsoft" };

  function readAuthChoice() {
    try { return sessionStorage.getItem(AUTH_CHOICE_KEY); } catch (_) { return null; }
  }
  function writeAuthChoice(value) {
    try {
      if (value) sessionStorage.setItem(AUTH_CHOICE_KEY, value);
      else sessionStorage.removeItem(AUTH_CHOICE_KEY);
    } catch (_) { /* storage unavailable: choice just isn't remembered */ }
  }

  async function fetchAuthStatus() {
    // Preferred: one combined request (also reports which providers are configured).
    try {
      const data = await apiGet("/auth/status");
      return {
        google: Object.assign({ connected: false, email: null }, data.google),
        microsoft: Object.assign({ connected: false, email: null }, data.microsoft),
      };
    } catch (_) {
      // Older server / transient error: fall back to the per-provider endpoints.
      const [g, m] = await Promise.all([
        apiGet("/auth/google/status").catch(() => ({ connected: false })),
        apiGet("/auth/microsoft/status").catch(() => ({ connected: false })),
      ]);
      return { google: g, microsoft: m };
    }
  }

  async function refreshConnectionStatus() {
    const { google, microsoft } = await fetchAuthStatus();

    state.googleStatus = google;
    state.microsoftStatus = microsoft;
    if (typeof google.configured === "boolean") state.providersConfigured.google = google.configured;
    if (typeof microsoft.configured === "boolean") state.providersConfigured.microsoft = microsoft.configured;

    if (google.connected) {
      state.provider = "google";
      state.accountEmail = google.email;
    } else if (microsoft.connected) {
      state.provider = "microsoft";
      state.accountEmail = microsoft.email;
    } else {
      state.provider = null;
      state.accountEmail = null;
    }
    return state.provider;
  }

  function computeAuthPhase() {
    if (state.provider) return "connected";
    return readAuthChoice() === "skipped" ? "anonymous" : "welcome";
  }

  // Single place that makes the shell reflect the auth phase.
  function applyAuthPhase() {
    state.authPhase = computeAuthPhase();
    const phase = state.authPhase;
    const connected = phase === "connected";
    document.documentElement.setAttribute("data-auth", phase);

    // Welcome / authentication landing
    const welcome = document.getElementById("welcomeOverlay");
    if (welcome) welcome.hidden = phase !== "welcome";

    // Sidebar: Log Out only when authenticated, Sign in / Connect only when not
    const logout = document.getElementById("logoutBtn");
    const signIn = document.getElementById("signInBtn");
    if (logout) logout.hidden = !connected;
    if (signIn) signIn.hidden = connected;

    // Mailbox-dependent navigation
    navItems.forEach(li => {
      if (li.getAttribute("data-requires-mailbox") !== "true") return;
      li.classList.toggle("disabled", !connected);
      li.setAttribute("aria-disabled", connected ? "false" : "true");
      li.title = connected ? "" : "Sign in or connect a mailbox to use this";
    });

    // Mailbox actions
    ["syncBtn", "homeSyncBtn", "inboxSyncBtn", "scanInboxBtn"].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      if (id === "scanInboxBtn" && state.scanning) return; // scan lifecycle owns this one
      el.disabled = !connected;
      el.title = connected ? (id === "scanInboxBtn" ? "" : "Sync mailbox") : "Connect a mailbox first";
    });
    document.querySelectorAll('.quick-action-btn[data-action="scan-inbox"], .quick-action-btn[data-action="risky-mails"], .quick-action-btn[data-action="reports"]')
      .forEach(btn => {
        btn.disabled = !connected;
        btn.title = connected ? "" : "Connect a mailbox first";
      });

    updateUserProfileShortcut();
    renderRefreshLabels();
  }

  function updateUserProfileShortcut() {
    const img = document.getElementById("userAvatar");
    const nameEl = document.getElementById("userProfileName");
    const subEl = document.getElementById("userProfileSub");
    if (!img || !nameEl || !subEl) return;

    img.onerror = () => { img.onerror = null; img.src = DEFAULT_AVATAR; };
    if (state.provider && state.accountEmail) {
      // Provider profile imagery is used when the status payload carries a
      // `picture`; otherwise (and on load failure) the default avatar.
      const status = state.provider === "google" ? state.googleStatus : state.microsoftStatus;
      img.src = (status && status.picture) || DEFAULT_AVATAR;
      nameEl.textContent = PROVIDER_LABELS[state.provider] || state.provider;
      subEl.textContent = state.accountEmail;
      subEl.title = state.accountEmail;
    } else {
      img.src = DEFAULT_AVATAR;
      nameEl.textContent = "Not connected";
      subEl.textContent = "Anonymous mode";
      subEl.title = "";
    }
  }

  // ---------- sign-in UI (shared by the welcome screen and the connect modal)

  const GOOGLE_SVG = '<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>';
  const MICROSOFT_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="1" y="1" width="10" height="10" fill="#F25022"/><rect x="13" y="1" width="10" height="10" fill="#7FBA00"/><rect x="1" y="13" width="10" height="10" fill="#00A4EF"/><rect x="13" y="13" width="10" height="10" fill="#FFB900"/></svg>';

  function providerButtonsHtml() {
    return ["google", "microsoft"].map(id => {
      const label = id === "google" ? "Continue with Google" : "Continue with Microsoft";
      const unavailable = state.providersConfigured[id] === false;
      return `<button type="button" class="provider-btn" data-oauth="${id}"${unavailable ? ' disabled title="Not configured on this server (see .env.example)"' : ""}>
        ${id === "google" ? GOOGLE_SVG : MICROSOFT_SVG}
        <span>${label}${unavailable ? ' <span class="provider-sub">· not configured</span>' : ""}</span>
      </button>`;
    }).join("");
  }

  function startOAuth(providerId) {
    if (state.providersConfigured[providerId] === false) {
      toast(`${PROVIDER_LABELS[providerId]} sign-in is not configured on this server.`, "warning");
      return;
    }
    // Full-page redirect to the existing OAuth login route. Buttons are
    // disabled so a second click can't start a second, competing flow.
    document.querySelectorAll("[data-oauth]").forEach(b => { b.disabled = true; });
    window.location.href = `/auth/${providerId}/login`;
  }

  function bindProviderButtons(root) {
    root.querySelectorAll("[data-oauth]").forEach(btn => {
      btn.addEventListener("click", () => startOAuth(btn.getAttribute("data-oauth")));
    });
  }

  function renderWelcome() {
    const box = document.getElementById("welcomeProviderButtons");
    if (!box) return;
    box.innerHTML = providerButtonsHtml();
    bindProviderButtons(box);
  }

  function openConnectModal() {
    openModal(`
      <h3>${ic("plug")} Sign in / Connect</h3>
      <p>Connect a mailbox with read-only OAuth to scan your inbox and unlock the Dashboard and Reports.</p>
      <div class="welcome-actions">${providerButtonsHtml()}</div>
      <div class="modal-actions"><button class="btn btn-ghost" id="closeConnectModal">Not now</button></div>
    `);
    bindProviderButtons(document.getElementById("modalBox"));
    document.getElementById("closeConnectModal").addEventListener("click", closeModal);
  }

  function skipForNow() {
    writeAuthChoice("skipped");
    state.activeView = "home";
    applyAuthPhase();
    setActiveView("home");
  }

  (function wireAuthUi() {
    const skipBtn = document.getElementById("welcomeSkipBtn");
    if (skipBtn) skipBtn.addEventListener("click", skipForNow);
    const signIn = document.getElementById("signInBtn");
    if (signIn) signIn.addEventListener("click", openConnectModal);
    const profile = document.getElementById("userProfileShortcut");
    if (profile) {
      profile.addEventListener("click", () => {
        if (state.provider) setActiveView("user");
        else openConnectModal();
      });
    }
  })();

  // Browser Back from the provider's consent screen can restore this page
  // from the back/forward cache with the OAuth buttons still disabled.
  // Reload so state and buttons are rebuilt from the real session.
  window.addEventListener("pageshow", e => { if (e.persisted) window.location.reload(); });

  // Everything the first render needs, in order, exactly once.
  async function bootstrap() {
    try {
      await refreshConnectionStatus();
    } catch (_) { /* treated as not connected; welcome screen is shown */ }

    renderWelcome();
    applyAuthPhase();
    setActiveView("home");
    document.documentElement.classList.remove("vp-booting");

    // Mailbox contents load AFTER the shell is correct, then the visible
    // view is re-rendered with the real data.
    if (state.provider) {
      await loadEmailPage(null, 0);
      renderActiveView();
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
      renderActiveView();
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

  function paintScanProgress(done, total, detailText) {
    const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
    const fill = document.getElementById("scanProgressFill");
    const text = document.getElementById("scanProgressText");
    const pctEl = document.getElementById("scanProgressPct");
    const detail = document.getElementById("scanProgressDetail");
    if (fill) fill.style.width = pct + "%";
    if (text) text.textContent = `Scanning ${done} / ${total}`;
    if (pctEl) pctEl.textContent = pct + "%";
    if (detail) detail.textContent = detailText;
  }

  async function startScan() {
    if (!state.provider || state.scanning) return;
    if (!state.currentMessageIds.length) {
      toast("No messages loaded to scan.", "warning");
      return;
    }

    state.scanning = true;
    const scanBtn = document.getElementById("scanInboxBtn");
    const progress = document.getElementById("scanProgress");

    if (scanBtn) scanBtn.disabled = true;
    if (progress) progress.classList.add("active");
    paintScanProgress(0, state.currentMessageIds.length,
      `Requested: ${state.currentMessageIds.length} · Analyzed: 0 · Failed: 0 · Skipped: 0`);

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
        paintScanProgress(done, total,
          `Requested: ${scan.requested} · Analyzed: ${scan.analyzed} · Failed: ${scan.failed} · Skipped: ${scan.skipped}`);

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

  // ---------- structured links section (email modal)

  const LINK_STATUS_BADGE = { malicious: "critical", suspicious: "medium", safe: "safe", unknown: "unknown" };
  const LINK_STATUS_LABEL = { malicious: "Malicious", suspicious: "Suspicious", safe: "Safe", unknown: "Unknown" };
  const LINKS_PAGE = 25;

  function linksSectionHtml(model) {
    const c = model.counts;
    if (!c.total) return '<div style="color:var(--surface-muted);font-size:12.5px;">No links detected.</div>';
    const flaggedSub = `${c.suspicious} suspicious · ${c.malicious} malicious`;
    return `
      <div class="link-summary">
        <div class="link-stat"><span class="n">${c.total}</span><span class="l">Total links</span></div>
        <div class="link-stat safe"><span class="n">${c.safe}</span><span class="l">Safe</span><span class="sub">no threat indicators</span></div>
        <div class="link-stat flagged${c.malicious ? " has-malicious" : ""}"><span class="n">${c.flagged}</span><span class="l">Suspicious / bad</span><span class="sub">${flaggedSub}</span></div>
        <div class="link-stat"><span class="n">${c.unknown}</span><span class="l">Unknown</span><span class="sub">not checked</span></div>
      </div>
      <div class="link-note">“Safe” means the local PhishTank feed and URL heuristics found nothing — not a guarantee. Links are shown as text and are never clickable.</div>
      <button type="button" class="link-toggle" id="toggleLinksBtn" aria-expanded="false" aria-controls="linksList">Show links (${c.total})</button>
      <div class="link-list" id="linksList" hidden></div>`;
  }

  function linkItemHtml(item, index) {
    const evidence = [];
    if (item.phishtank) evidence.push(`<span>PhishTank: ${item.phishtank.listed ? "KNOWN PHISHING" : "no match"}</span>`);
    if (item.local) {
      evidence.push(`<span>Heuristics: ${item.flags.length ? escapeHtml(item.flags.join(", ")) : "no flags"} (score ${item.score})</span>`);
    }
    if (!evidence.length) evidence.push("<span>No check result available for this link.</span>");
    return `
      <div class="link-item ${item.status}">
        <div class="link-item-main">
          <div class="link-item-text">
            <div class="link-host">${ic("link")}<span class="host-text" title="${escapeHtml(item.host)}">${escapeHtml(item.host)}</span><span class="badge ${LINK_STATUS_BADGE[item.status]}">${LINK_STATUS_LABEL[item.status]}</span></div>
            ${item.pathPreview ? `<div class="link-path" title="${escapeHtml(item.pathPreview)}">${escapeHtml(item.pathPreview)}</div>` : ""}
          </div>
          <button type="button" class="link-toggle small" data-link-idx="${index}" aria-expanded="false">Details</button>
        </div>
        <div class="link-details" hidden>
          <code class="link-full">${escapeHtml(item.url)}</code>
          <div class="link-evidence">${evidence.join("")}</div>
        </div>
      </div>`;
  }

  function wireLinksSection(root, model) {
    const toggle = root.querySelector("#toggleLinksBtn");
    const list = root.querySelector("#linksList");
    if (!toggle || !list) return;
    let shown = 0;

    function renderMore() {
      const next = model.items.slice(shown, shown + LINKS_PAGE);
      const old = list.querySelector(".link-more");
      if (old) old.remove();
      list.insertAdjacentHTML("beforeend", next.map((item, i) => linkItemHtml(item, shown + i)).join(""));
      shown += next.length;
      if (shown < model.items.length) {
        list.insertAdjacentHTML("beforeend",
          `<button type="button" class="link-toggle link-more">Show ${Math.min(LINKS_PAGE, model.items.length - shown)} more (${model.items.length - shown} remaining)</button>`);
        list.querySelector(".link-more").addEventListener("click", renderMore);
      }
      list.querySelectorAll("button[data-link-idx]").forEach(btn => {
        if (btn._wired) return;
        btn._wired = true;
        btn.addEventListener("click", () => {
          const details = btn.closest(".link-item").querySelector(".link-details");
          const open = details.hidden;
          details.hidden = !open;
          btn.setAttribute("aria-expanded", String(open));
          btn.textContent = open ? "Hide" : "Details";
        });
      });
    }

    toggle.addEventListener("click", () => {
      const open = list.hidden;
      if (open && shown === 0) renderMore();
      list.hidden = !open;
      toggle.setAttribute("aria-expanded", String(open));
      toggle.textContent = open ? "Hide links" : `Show links (${model.counts.total})`;
    });
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
      ? `<div class="disposition-box trusted">${ic("shield", "disposition-icon")}<div><span class="disposition-label">User disposition</span><span class="disposition-value">Trusted by user on ${escapeHtml(state.trustedSenders[sender].dateTrusted || "a previous session")}. This does not change the automated analysis below.</span></div></div>`
      : `<div class="disposition-box none">${ic("shield", "disposition-icon")}<div><span class="disposition-label">User disposition</span><span class="disposition-value">None — treated per automated analysis.</span></div></div>`;

    // BEC section
    const becHtml = (bec.detected || (result.threat_types || []).some(t => t.toLowerCase().includes("bec")))
      ? `<div class="kv-row"><span class="k">BEC detected</span><span class="v">Yes</span></div>
         ${bec.matched_phrases ? `<div class="kv-row"><span class="k">Matched phrases</span><span class="v">${escapeHtml(bec.matched_phrases.join(", "))}</span></div>` : ""}
         ${bec.urgency_score != null ? `<div class="kv-row"><span class="k">Urgency score</span><span class="v">${bec.urgency_score}</span></div>` : ""}`
      : `<div style="color:var(--surface-muted);font-size:12.5px;">No BEC indicators found.</div>`;

    // URL analysis: structured summary + expandable list (see vp-links.js).
    // BUG FIX: this used to read `result.detected_urls`, a field the
    // backend never sets (it returns `urls`), so the section always said
    // "No links detected" while the raw URLs leaked into Threat Intel rows.
    const linkModel = (window.VPLinks || { buildLinkModel: () => ({ items: [], counts: { total: 0, safe: 0, suspicious: 0, malicious: 0, unknown: 0, flagged: 0 } }) }).buildLinkModel(result);
    const urlHtml = linksSectionHtml(linkModel);

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

    // Threat Intel: per-source summary rows. The per-URL PhishTank / heuristic
    // evidence is NOT dropped - it is attached to each link in the URL
    // analysis section (expand a link's details to see it).
    const intelHtml = (() => {
      const rows = [];
      const pt = m3.phishtank || [];
      const sh = m3.spamhaus || [];
      const lh = (m3.local_heuristics || []);
      if (pt.length) {
        const listed = pt.filter(r => r.listed).length;
        rows.push(`<div class="kv-row"><span class="k">PhishTank (local feed)</span><span class="v">${listed ? `${listed} of ${pt.length} URL${pt.length === 1 ? "" : "s"} KNOWN PHISHING` : `No match · ${pt.length} URL${pt.length === 1 ? "" : "s"} checked`}</span></div>`);
      }
      sh.forEach(r => {
        rows.push(`<div class="kv-row"><span class="k">Spamhaus DROP: ${escapeHtml(r.ip || "")}</span><span class="v">${r.listed ? `LISTED (${escapeHtml(r.network || "")})` : "Not listed"}</span></div>`);
      });
      if (lh.length) {
        const flagged = lh.filter(r => (r.flags || []).length).length;
        rows.push(`<div class="kv-row"><span class="k">Local heuristics</span><span class="v">${flagged} of ${lh.length} indicator${lh.length === 1 ? "" : "s"} flagged</span></div>`);
      }
      if (!rows.length) return '<div style="color:var(--surface-muted);font-size:12.5px;">No indicators were available to check.</div>';
      if (pt.length) rows.push('<div class="link-note" style="margin-top:6px;margin-bottom:0;">Per-link results are listed under URL analysis.</div>');
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

    wireLinksSection(drawerBody, linkModel);

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
        : "Anonymous mode · not connected";
    }

    if (homeStats) {
      const totalScanned = Object.values(state.resultsByMessageId).filter(r => r.status && r.status !== "unscanned").length;
      homeStats.innerHTML = `
        <div class="stat-card mailbox"><div class="label">Mailbox</div><div class="value" style="font-size:16px;">${state.provider ? (state.provider === "google" ? "Gmail" : "Microsoft") + " Connected" : "Not connected"}</div><div class="sub">${state.provider ? `${totalScanned} emails scanned` : "Sign in to scan a mailbox"}</div></div>
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
      detections.innerHTML = !state.provider
        ? `<div class="anon-note"><div>Mailbox scanning is off while you are not signed in. <strong>Custom Mails</strong> still lets you upload and analyze .eml files locally.<br><button class="btn btn-primary btn-sm" id="homeSignInBtn">Sign in / Connect</button></div></div>`
        : risky.length ? risky.map(r => {
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
      const homeSignIn = document.getElementById("homeSignInBtn");
      if (homeSignIn) homeSignIn.addEventListener("click", openConnectModal);
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
    if (state.provider) hydrateHomeFromBackend();
  }

  // The in-page result cache only knows what was scanned since this page
  // loaded; the backend remembers every analysis for the session (SQLite).
  // Use it so Home's counters and detections are correct after a reload or
  // an OAuth round trip, instead of showing zeros for already-scanned mail.
  let homeHydrateSeq = 0;
  async function hydrateHomeFromBackend() {
    const seq = ++homeHydrateSeq;
    let summary, history;
    try {
      [summary, history] = await Promise.all([
        apiGet("/api/reports/summary"),
        apiGet("/api/scans/history"),
      ]);
    } catch (_) { return; }
    if (seq !== homeHydrateSeq || state.activeView !== "home" || !state.provider) return;

    const b = summary.risk_breakdown || {};
    const set = (sel, v) => { const el = document.querySelector(sel + " .value"); if (el) el.textContent = v; };
    set('.stat-card[data-severity="safe"]', b.LOW || 0);
    set('.stat-card[data-severity="medium"]', b.MEDIUM || 0);
    set('.stat-card[data-severity="high"]', b.HIGH || 0);
    set('.stat-card[data-severity="critical"]', b.CRITICAL || 0);
    const mailboxSub = document.querySelector(".stat-card.mailbox .sub");
    if (mailboxSub) mailboxSub.textContent = `${summary.total_analyzed || 0} emails scanned`;

    const detections = document.getElementById("recentDetections");
    const items = (history.items || []).slice(0, 6);
    if (detections && items.length && !detections.querySelector(".detection-item")) {
      detections.innerHTML = items.map(i => {
        const sev = severityClass((i.risk || {}).level);
        return `<div class="detection-item" style="cursor:default;" data-hmid="${escapeHtml(i.message_id || "")}">
          <span class="sev-dot ${sev}"></span>
          <div style="flex-grow:1;min-width:0;"><div style="font-weight:600;overflow-wrap:anywhere;">${escapeHtml(i.sender || "—")}</div><div class="detection-subject">${escapeHtml(i.subject || "")}</div></div>
          <span class="meta">${(i.risk || {}).score || "—"}/100</span>
        </div>`;
      }).join("");
    }
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

    if (state.provider) {
      // Threat vectors (real): categories ranked, intel sources separate
      closeThreatDetail();
      await loadThreatVectors();

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

  // ============================================================
  // DASHBOARD: THREAT VECTORS (categories) + INTEL SOURCES
  //
  // "Top threat vectors" ranks threat CATEGORIES (Authentication
  // Spoofing, Credential Phishing, ...). PhishTank / Spamhaus / local
  // heuristics are evidence SOURCES, listed in their own section below the
  // ranking. Every entry - category or source - is clickable and opens the
  // same detail panel of real analyzed detections.
  // ============================================================

  const THREAT_ICONS = {
    "Authentication Spoofing": "key",
    "Malware Attachment": "paperclip",
    "BEC / Financial Fraud": "dollar",
    "Malicious Redirect": "route",
    "Credential Phishing": "mail",
    "Brand Impersonation": "flag",
    "Threat Intelligence Match": "satellite",
    "Suspicious Infrastructure": "globe",
    "Spam": "warning",
  };
  const SOURCE_ICONS = { phishtank: "satellite", spamhaus: "globe", local_heuristics: "warning" };

  function plural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

  async function loadThreatVectors() {
    const list = document.getElementById("threatVectorList");
    if (!list) return;
    try {
      state.threatData = await apiGet("/api/dashboard/threat-vectors");
      renderThreatVectorList();
    } catch (err) {
      state.threatData = null;
      list.innerHTML = '<div class="threat-empty">Failed to load threat data.</div>';
    }
  }

  function threatRowHtml(kind, key, icon, label, countText) {
    return `<div class="threat-bar" role="button" tabindex="0" data-kind="${kind}" data-key="${escapeHtml(key)}" aria-label="${escapeHtml(label)}, ${escapeHtml(countText)}. Show detections">
      <span class="threat-bar-left">${ic(icon, "threat-icon")}<span>${escapeHtml(label)}</span></span>
      <span class="count">${escapeHtml(countText)}</span>
    </div>`;
  }

  function renderThreatVectorList() {
    const list = document.getElementById("threatVectorList");
    const data = state.threatData;
    if (!list || !data) return;

    const vectorRows = (data.vectors || []).map(v =>
      threatRowHtml("vector", v.name, THREAT_ICONS[v.name] || "shield", v.name, plural(v.count, "email", "emails"))
    ).join("") || '<div class="threat-empty">No threat categories detected yet. Scan your inbox to populate this list.</div>';

    const sourceRows = (data.sources || []).map(src =>
      threatRowHtml("source", src.key, SOURCE_ICONS[src.key] || "shield", src.name, plural(src.matches, "match", "matches"))
    ).join("");

    list.innerHTML = vectorRows +
      (sourceRows ? `<div class="threat-section-label">Threat intelligence sources</div>${sourceRows}` : "");

    list.querySelectorAll(".threat-bar").forEach(row => {
      const open = () => openThreatDetail(row.getAttribute("data-kind"), row.getAttribute("data-key"));
      row.addEventListener("click", open);
      row.addEventListener("keydown", e => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
      });
    });
  }

  function findThreatEntry(kind, key) {
    const data = state.threatData || {};
    if (kind === "vector") return (data.vectors || []).find(v => v.name === key) || null;
    return (data.sources || []).find(src => src.key === key) || null;
  }

  function openThreatDetail(kind, key) {
    const entry = findThreatEntry(kind, key);
    const detail = document.getElementById("threatDetailView");
    const listView = document.getElementById("threatListView");
    if (!entry || !detail || !listView) return;

    const label = kind === "vector" ? entry.name : entry.name;
    const dets = entry.detections || [];
    const emailCount = kind === "vector" ? entry.count : entry.message_count;
    const sevChips = kind === "vector"
      ? ["critical", "high", "medium", "safe"].filter(k => (entry.severity || {})[k])
          .map(k => `<span class="sev-chip ${k}">${entry.severity[k]} ${k === "safe" ? "SAFE" : k.toUpperCase()}</span>`).join("")
      : "";
    const countLine = kind === "vector"
      ? `${plural(emailCount, "related detection", "related detections")}`
      : `${plural(entry.matches, "match", "matches")} across ${plural(emailCount, "email", "emails")}`;

    detail.innerHTML = `
      <button type="button" class="threat-detail-back" id="threatBackBtn">${ic("chevron-left")} Back</button>
      <div class="threat-detail-title">${escapeHtml(label)}</div>
      <div class="threat-detail-count">${escapeHtml(countLine)}</div>
      ${sevChips ? `<div class="threat-detail-sev">${sevChips}</div>` : ""}
      <div class="threat-detail-list">
        ${dets.length ? dets.map((d, i) => {
          const sev = severityClass(d.risk_level);
          const evidence = (d.evidence || []).length ? `<div class="evidence-line">${escapeHtml(d.evidence.join(" · "))}</div>` : "";
          return `<div class="threat-email-row" role="button" tabindex="0" data-det="${i}">
            <div class="sev-line"><span class="sev-chip ${sev}">${escapeHtml(severityLabel(d.risk_level))}${d.risk_score != null ? " · " + d.risk_score : ""}</span><span class="row-meta">${escapeHtml(d.date || "")}</span></div>
            <div class="sender-name">${escapeHtml(d.sender || "—")}</div>
            <div class="subject-line">${escapeHtml(d.subject || "(no subject)")}</div>
            ${evidence}
          </div>`;
        }).join("") : '<div class="threat-empty">No analyzed emails matched.</div>'}
        ${entry.truncated ? '<div class="threat-empty">Showing the highest-risk detections only.</div>' : ""}
      </div>`;

    listView.classList.remove("active");
    detail.classList.add("active");
    document.getElementById("threatBackBtn").addEventListener("click", closeThreatDetail);
    detail.querySelectorAll(".threat-email-row").forEach(row => {
      const open = () => openDetectionEmail(dets[parseInt(row.getAttribute("data-det"), 10)]);
      row.addEventListener("click", open);
      row.addEventListener("keydown", e => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
      });
    });
  }

  function closeThreatDetail() {
    const detail = document.getElementById("threatDetailView");
    const listView = document.getElementById("threatListView");
    if (detail) { detail.classList.remove("active"); detail.innerHTML = ""; }
    if (listView) listView.classList.add("active");
  }

  // Open the full email analysis for a detection: use the full result this
  // page already holds, otherwise fetch the stored analysis from
  // /api/analysis/... (never render a partial stand-in).
  async function openDetectionEmail(det) {
    if (!det) return;
    const cached = state.resultsByMessageId[det.message_id];
    if (cached && cached.status === "analyzed" && cached.m1) { openEmailWorkspace(cached); return; }
    try {
      const full = await apiGet(
        `/api/analysis/${encodeURIComponent(det.provider)}/${encodeURIComponent(det.account_id)}/${encodeURIComponent(det.message_id)}`
      );
      state.resultsByMessageId[full.message_id] = full;
      openEmailWorkspace(full);
    } catch (err) {
      toast("Could not load the stored analysis: " + errText(err), "warning");
    }
  }

  // ============================================================
  // DASHBOARD: ANALYSIS REPORT CHART (real risk classifications)
  //
  // Data: GET /api/dashboard/risk-trend?period=day|week|month - counts of
  // the session's actually analyzed mail by Safe / Medium / High /
  // Critical. Zero-count periods are plotted as zero; nothing is
  // fabricated. (The previous chart used /api/threat-geo/trend, which is
  // geolocation analytics over suspicious mail only.)
  // ============================================================

  const CHART_PERIODS = { daily: "day", weekly: "week", monthly: "month" };
  const CHART_X_TITLES = { day: "Day", week: "Week starting", month: "Month" };
  const CHART_SERIES = [
    { key: "safe", label: "Safe", cssVar: "--safe", fallback: "#00C4D3" },
    { key: "medium", label: "Medium Risk", cssVar: "--warning", fallback: "#FFC107" },
    { key: "high", label: "High Risk", cssVar: "--high", fallback: "#d39999" },
    { key: "critical", label: "Critical", cssVar: "--danger", fallback: "#E81123" },
  ];
  let chartRequestSeq = 0;

  function setChartEmpty(message) {
    const el = document.getElementById("chartEmpty");
    if (!el) return;
    el.hidden = !message;
    el.textContent = message || "";
  }

  function renderChartSummary(data) {
    const el = document.getElementById("chartSummary");
    if (!el) return;
    const t = data.totals || {};
    let line = `<strong>${t.total || 0}</strong> scanned · <strong>${t.safe || 0}</strong> safe · <strong>${t.medium || 0}</strong> medium · <strong>${t.high || 0}</strong> high · <strong>${t.critical || 0}</strong> critical`;
    if (data.outside_window) line += ` · ${data.outside_window} older not shown`;
    if (data.undated) line += ` · ${data.undated} undated`;
    el.innerHTML = line;
  }

  async function renderDashboardChart() {
    const canvas = document.getElementById("analysisChart");
    if (!canvas) return;
    const seq = ++chartRequestSeq;

    if (canvas._chartInstance) { canvas._chartInstance.destroy(); canvas._chartInstance = null; }
    if (!state.provider) { setChartEmpty(""); return; }

    const period = CHART_PERIODS[state.chartPeriod] || "day";
    let data;
    try {
      data = await apiGet(`/api/dashboard/risk-trend?period=${period}`);
    } catch (err) {
      if (seq !== chartRequestSeq) return;
      setChartEmpty("Could not load chart data: " + errText(err));
      return;
    }
    if (seq !== chartRequestSeq) return; // a newer request (e.g. another period click) superseded this one

    state.dashboardData = data;
    renderChartSummary(data);

    const total = (data.totals || {}).total || 0;
    setChartEmpty(total ? "" : "No analyzed mail in this period yet. Scan your inbox to populate the chart.");

    if (typeof Chart === "undefined") {
      setChartEmpty("Chart library could not be loaded (offline?). The counts above are still accurate.");
      return;
    }
    if (canvas._chartInstance) canvas._chartInstance.destroy();

    const text = cssVar("--surface-text") || "#fff";
    const muted = cssVar("--surface-muted") || "#888";
    const grid = cssVar("--surface-border") || "rgba(128,128,128,.25)";
    const buckets = data.buckets || [];

    try {
      canvas._chartInstance = new Chart(canvas, {
        type: "bar",
        data: {
          labels: buckets.map(b => b.label),
          datasets: CHART_SERIES.map(series => ({
            label: series.label,
            data: buckets.map(b => b[series.key]),
            backgroundColor: cssVar(series.cssVar) || series.fallback,
            borderRadius: 3,
            maxBarThickness: 38,
          })),
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: "index", intersect: false },
          plugins: {
            legend: { position: "top", labels: { color: text, usePointStyle: true, boxWidth: 8, boxHeight: 8 } },
            tooltip: {
              callbacks: {
                footer: items => `Total scanned: ${items.reduce((sum, it) => sum + it.parsed.y, 0)}`,
              },
            },
          },
          scales: {
            x: {
              stacked: true,
              grid: { display: false },
              ticks: { color: muted, maxRotation: 0, autoSkip: true },
              title: { display: true, text: CHART_X_TITLES[period], color: muted },
            },
            y: {
              stacked: true,
              beginAtZero: true,
              ticks: { color: muted, precision: 0 },
              grid: { color: grid },
              title: { display: true, text: "Emails", color: muted },
            },
          },
        },
      });
    } catch (_) { /* Chart.js failure is non-fatal */ }
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
        btn.addEventListener("click", () => startOAuth(btn.getAttribute("data-connect")));
      });
      accountsEl.querySelectorAll("[data-disconnect]").forEach(btn => {
        btn.addEventListener("click", () => {
          const id = btn.getAttribute("data-disconnect");
          doLogout(id);
        });
      });
    }

    const nameEl = document.getElementById("userViewName");
    const emailEl = document.getElementById("userViewEmail");
    const avatarEl = document.getElementById("userViewAvatar");
    if (nameEl) nameEl.textContent = state.provider ? (PROVIDER_LABELS[state.provider] || state.provider) : "Not connected";
    if (emailEl) emailEl.textContent = state.provider ? (state.accountEmail || "") : "Anonymous mode";
    if (avatarEl) { avatarEl.src = DEFAULT_AVATAR; avatarEl.style.display = "block"; }

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

    if (state.scanPollHandle) clearInterval(state.scanPollHandle);
    state.scanning = false;
    if (provider === state.provider) {
      state.provider = null;
      state.accountEmail = null;
      state.currentMessageIds = [];
      state.resultsByMessageId = {};
      state.scanId = null;
      state.pageTokenStack = [null];
      state.currentPageIndex = 0;
      state.nextPageToken = null;
      state.threatData = null;
      state.dashboardData = null;
    }
    closeDrawer();
    closeThreatDetail();

    await refreshConnectionStatus();
    // Logging out lands in anonymous mode (not the first-launch welcome).
    if (!state.provider) writeAuthChoice("skipped");
    applyAuthPhase();
    // Another provider may still be connected (user disconnected only one):
    // make it the active mailbox and load it, as the original flow did.
    if (state.provider && !state.currentMessageIds.length) await loadEmailPage(null, 0);
    setActiveView(state.provider && MAILBOX_VIEWS.has(state.activeView) ? state.activeView : "home");
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
  //
  // BUG FIX (initial active pill): the sliding indicator is positioned from
  // offsetWidth/offsetLeft, which are 0 while the dashboard view is
  // display:none - and it was measured once, 100ms after load, while the
  // dashboard was hidden. So the first visit had a zero-width indicator and
  // no selected state until another pill was clicked. Now the indicator is
  // (re)measured whenever the dashboard becomes visible, on window resize
  // and once web fonts settle; until it has a real measurement the active
  // pill paints its own background (see .pill-nav-container:not(.ready)).
  const pillNav = document.getElementById("pillNav");
  function updatePillIndicator() {
    if (!pillNav) return;
    const activeBtn = pillNav.querySelector(".pill-btn.active");
    const pillIndicator = document.getElementById("pillIndicator");
    if (!activeBtn || !pillIndicator || !activeBtn.offsetWidth) return; // hidden: try again when shown
    const firstMeasure = !pillNav.classList.contains("ready");
    if (firstMeasure) pillIndicator.style.transition = "none"; // no slide-in from 0: avoids a flash
    pillIndicator.style.width = activeBtn.offsetWidth + "px";
    pillIndicator.style.left = activeBtn.offsetLeft + "px";
    if (firstMeasure) {
      void pillIndicator.offsetWidth; // commit the un-animated position
      pillIndicator.style.transition = "";
      pillNav.classList.add("ready");
    }
  }
  if (pillNav) {
    const pillBtns = pillNav.querySelectorAll(".pill-btn");
    const widgetContainer = document.getElementById("widgetContainer");
    pillBtns.forEach(btn => {
      btn.addEventListener("click", () => {
        pillBtns.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        const idx = parseInt(btn.getAttribute("data-index"), 10);
        if (widgetContainer) widgetContainer.style.transform = `translateX(-${idx * 100}%)`;
        updatePillIndicator();
      });
    });
    window.addEventListener("resize", updatePillIndicator);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(updatePillIndicator);
    if (typeof ResizeObserver !== "undefined") new ResizeObserver(updatePillIndicator).observe(pillNav);
  }

  // Time toggle buttons for chart: each one re-fetches REAL data for its period
  document.querySelectorAll(".time-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const period = btn.getAttribute("data-time");
      document.querySelectorAll(".time-btn").forEach(b => {
        const on = b === btn;
        b.classList.toggle("active", on);
        b.setAttribute("aria-pressed", String(on));
      });
      if (period === state.chartPeriod && state.dashboardData) return;
      state.chartPeriod = period;
      renderDashboardChart();
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

  bootstrap();

})();
