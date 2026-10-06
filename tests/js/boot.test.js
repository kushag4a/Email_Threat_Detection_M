// Boots the REAL static/app.js against a minimal DOM stub and a scripted fetch.
// Smoke-tests startup/auth phases, anonymous-mode gating, the one-flow login
// recognition, and that chart-period buttons / dashboard hit the real endpoints.
// Run: node tests/js/boot.test.js
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

const ROOT = path.resolve(__dirname, "..", "..");
const HTML = fs.readFileSync(path.join(ROOT, "static", "index.html"), "utf8");
const APP = fs.readFileSync(path.join(ROOT, "static", "app.js"), "utf8");
const LINKS = fs.readFileSync(path.join(ROOT, "static", "vp-links.js"), "utf8");

class El {
  constructor(id, attrs = {}, classes = []) {
    this.id = id; this._attrs = Object.assign({}, attrs); this._cls = new Set(classes);
    this._h = {}; this.style = {}; this.hidden = /\bhidden\b/.test(attrs.__raw || "");
    this.innerHTML = ""; this.textContent = ""; this.disabled = false; this.title = ""; this.src = ""; this.offsetWidth = 0;
    this.children = [];
    const self = this;
    this.classList = {
      add: c => self._cls.add(c), remove: c => self._cls.delete(c), contains: c => self._cls.has(c),
      toggle: (c, f) => { const on = f === undefined ? !self._cls.has(c) : !!f; on ? self._cls.add(c) : self._cls.delete(c); return on; },
    };
  }
  setAttribute(k, v) { this._attrs[k] = String(v); }
  getAttribute(k) { return k in this._attrs ? this._attrs[k] : null; }
  removeAttribute(k) { delete this._attrs[k]; }
  addEventListener(t, f) { (this._h[t] = this._h[t] || []).push(f); }
  click() { (this._h.click || []).forEach(f => f({ target: this })); }
  querySelector() { return null; }
  querySelectorAll() { return []; }
  closest() { return this; }
  insertAdjacentHTML() {}
  appendChild() {}
  remove() {}
  scrollIntoView() {}
  get className() { return [...this._cls].join(" "); }
  set className(v) { this._cls = new Set(String(v).split(/\s+/).filter(Boolean)); }
}

function buildDom() {
  const byId = {};
  // every element with an id="" in the real index.html
  for (const m of HTML.matchAll(/<([a-z0-9]+)([^>]*?)\sid="([^"]+)"([^>]*)>/gi)) {
    const raw = m[2] + " " + m[4];
    const cls = (/class="([^"]*)"/.exec(raw) || [, ""])[1].split(/\s+/).filter(Boolean);
    byId[m[3]] = new El(m[3], { __raw: raw }, cls);
  }
  const navLis = [...HTML.matchAll(/<li([^>]*data-view="([^"]+)"[^>]*)>/g)].map(m => {
    const cls = (/class="([^"]*)"/.exec(m[1]) || [, ""])[1].split(/\s+/).filter(Boolean);
    const li = new El(null, { "data-view": m[2], "data-requires-mailbox": /data-requires-mailbox="true"/.test(m[1]) ? "true" : null }, cls);
    if (li._attrs["data-requires-mailbox"] === null) delete li._attrs["data-requires-mailbox"];
    return li;
  });
  const viewEls = [...HTML.matchAll(/<section class="view[^"]*" id="(view-[^"]+)"/g)].map(m => { const e = new El(m[1]); byId[m[1]] = e; return e; });
  const timeBtns = [...HTML.matchAll(/<button class="time-btn[^"]*" data-time="(\w+)"/g)].map(m => new El(null, { "data-time": m[1] }, ["time-btn"]));
  const root = new El("html", {}, ["vp-booting"]);

  const document = {
    documentElement: root,
    getElementById: id => byId[id] || null,
    querySelector: () => null,
    querySelectorAll: sel => {
      if (sel === ".nav-links li[data-view]") return navLis;
      if (sel === ".view") return viewEls;
      if (sel === ".time-btn") return timeBtns;
      return [];
    },
    addEventListener() {}, createElement: () => new El(null),
  };
  return { document, byId, navLis, timeBtns, root };
}

function makeEnv({ status, routes, choice }) {
  const dom = buildDom();
  const calls = [];
  const store = () => { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) }; };
  const sessionStorage = store(), localStorage = store();
  if (choice) sessionStorage.setItem("vp_auth_choice", choice);

  const fetch = async url => {
    calls.push(url);
    const key = Object.keys(routes).find(k => url.startsWith(k));
    if (url.startsWith("/auth/status")) return { ok: true, json: async () => status };
    if (!key) return { ok: false, statusText: "not found", json: async () => ({ detail: "not found" }) };
    return { ok: true, json: async () => (typeof routes[key] === "function" ? routes[key](url) : routes[key]) };
  };
  const ctx = {
    document: dom.document, fetch, sessionStorage, localStorage, console,
    navigator: { userAgent: "node-test" }, location: { href: "/" }, setTimeout, clearTimeout, setInterval, clearInterval,
    getComputedStyle: () => ({ getPropertyValue: () => "" }), requestAnimationFrame: f => f(),
    URL, URLSearchParams, JSON, Date, Promise,
  };
  ctx.window = ctx; ctx.self = ctx; ctx.addEventListener = () => {};
  vm.createContext(ctx);
  vm.runInContext(LINKS, ctx);
  vm.runInContext(APP, ctx);
  return { ctx, calls, ...dom, sessionStorage };
}
const tick = (n = 25) => new Promise(r => setTimeout(r, n));

const OFF = { google: { configured: true, connected: false, email: null }, microsoft: { configured: true, connected: false, email: null }, connected: false };
const ON = { google: { configured: true, connected: true, email: "me@gmail.com" }, microsoft: { configured: true, connected: false, email: null }, connected: true, active_provider: "google" };
const ROUTES = {
  "/api/emails": { provider: "google", messages: [{ message_id: "m1", provider: "google", sender: "A <a@x.com>", subject: "Hi", date: "d", has_attachments: false }], next_page_token: null },
  "/api/dashboard/risk-trend": url => ({ period_type: /period=(\w+)/.exec(url)[1], buckets: [], totals: { safe: 0, medium: 0, high: 0, critical: 0, total: 0 }, window: {} }),
  "/api/dashboard/threat-vectors": { total_analyzed: 3, vectors: [{ name: "Authentication Spoofing", count: 2, severity: { safe: 0, medium: 2, high: 0, critical: 0 }, detections: [] }],
    sources: [{ key: "phishtank", name: "PhishTank (local feed)", matches: 0, message_count: 0, detections: [] }, { key: "local_heuristics", name: "Local heuristics", matches: 380, message_count: 5, detections: [] }] },
  "/api/cases": { cases: [] }, "/api/scans/history": { items: [] }, "/api/threat-geo/summary": { locations: [] },
  "/api/reports/summary": { total_analyzed: 3, risk_breakdown: { LOW: 1, MEDIUM: 2 } },
};

(async () => {
  // A. Fresh anonymous startup -> welcome screen, nothing mailbox-related requested
  let e = makeEnv({ status: OFF, routes: ROUTES });
  await tick();
  assert.strictEqual(e.byId.welcomeOverlay.hidden, false, "welcome shown on first launch");
  assert.ok(!e.root.classList.contains("vp-booting"), "boot veil removed once state known");
  assert.strictEqual(e.byId.logoutBtn.hidden, true, "no Log Out when anonymous");
  assert.strictEqual(e.byId.signInBtn.hidden, false, "Sign in / Connect shown");
  assert.strictEqual(e.byId.userProfileName.textContent, "Not connected");
  assert.ok(/default-avatar\.svg/.test(e.byId.userAvatar.src));
  assert.ok(!e.calls.some(u => u.startsWith("/api/")), "no mailbox API calls while signed out: " + e.calls);
  assert.ok(/data-oauth="google"/.test(e.byId.welcomeProviderButtons.innerHTML) && /data-oauth="microsoft"/.test(e.byId.welcomeProviderButtons.innerHTML));
  console.log("ok - A fresh anonymous startup");

  // B. Skip for now -> anonymous mode
  e.byId.welcomeSkipBtn.click(); await tick();
  assert.strictEqual(e.byId.welcomeOverlay.hidden, true);
  assert.strictEqual(e.root.getAttribute("data-auth"), "anonymous");
  const nav = v => e.navLis.find(li => li.getAttribute("data-view") === v);
  for (const v of ["inbox", "dashboard", "reports"]) assert.ok(nav(v).classList.contains("disabled"), v + " disabled");
  for (const v of ["custom", "settings", "home", "user"]) assert.ok(!nav(v).classList.contains("disabled"), v + " enabled");
  assert.strictEqual(e.byId.scanInboxBtn.disabled, true);
  assert.strictEqual(e.byId.homeSyncBtn.disabled, true);
  assert.strictEqual(e.byId.logoutBtn.hidden, true);
  nav("inbox").click(); await tick();
  assert.ok(!nav("inbox").classList.contains("active"), "clicking a disabled view does not navigate");
  nav("custom").click(); await tick();
  assert.ok(nav("custom").classList.contains("active"), "Custom Mails still reachable");
  nav("settings").click(); await tick();
  assert.ok(nav("settings").classList.contains("active"), "Settings still reachable");
  assert.ok(!e.calls.some(u => u.startsWith("/api/")), "still no mailbox calls");
  assert.strictEqual(e.sessionStorage.getItem("vp_auth_choice"), "skipped");
  console.log("ok - B skip for now / anonymous gating");

  // B2. A reload in the same tab after skipping stays anonymous (no welcome again)
  e = makeEnv({ status: OFF, routes: ROUTES, choice: "skipped" }); await tick();
  assert.strictEqual(e.byId.welcomeOverlay.hidden, true);
  assert.strictEqual(e.root.getAttribute("data-auth"), "anonymous");
  console.log("ok - B2 skip survives reload in same tab");

  // C/D/E. Return from OAuth callback: status already connected on first load -> ONE flow
  e = makeEnv({ status: ON, routes: ROUTES }); await tick(60);
  assert.strictEqual(e.byId.welcomeOverlay.hidden, true, "no welcome/login prompt after successful callback");
  assert.strictEqual(e.root.getAttribute("data-auth"), "connected");
  assert.strictEqual(e.byId.logoutBtn.hidden, false, "Log Out shown when connected");
  assert.strictEqual(e.byId.signInBtn.hidden, true);
  assert.strictEqual(e.byId.userProfileName.textContent, "Gmail");
  assert.strictEqual(e.byId.userProfileSub.textContent, "me@gmail.com");
  assert.ok(/Connected · Gmail · me@gmail\.com/.test(e.byId.homeMailboxLine.textContent), "Home reflects the session on first render: " + e.byId.homeMailboxLine.textContent);
  assert.ok(/Gmail Connected/.test(e.byId.homeStats.innerHTML), "Home stat card not stuck on 'No mailbox connected'");
  const nav2 = v => e.navLis.find(li => li.getAttribute("data-view") === v);
  for (const v of ["inbox", "dashboard", "reports"]) assert.ok(!nav2(v).classList.contains("disabled"));
  assert.strictEqual(e.calls.filter(u => u.startsWith("/api/emails")).length, 1, "mailbox loaded exactly once");
  assert.strictEqual(e.byId.scanInboxBtn.disabled, false);
  console.log("ok - C/D/E OAuth return recognised in a single flow");

  // I. Dashboard: real endpoints, daily default; period buttons refetch
  nav2("dashboard").click(); await tick(60);
  assert.ok(e.calls.some(u => u === "/api/dashboard/risk-trend?period=day"), "daily default fetches period=day: " + e.calls);
  assert.ok(!e.calls.some(u => u.includes("threat-geo/trend")), "geo trend never used for the chart");
  const tv = e.byId.threatVectorList.innerHTML;
  assert.ok(/Authentication Spoofing/.test(tv) && /data-kind="vector"/.test(tv));
  assert.ok(/Local heuristics/.test(tv) && /data-kind="source" data-key="local_heuristics"/.test(tv), "Local heuristics is a clickable row");
  assert.ok(tv.indexOf("Authentication Spoofing") < tv.indexOf("Threat intelligence sources") && tv.indexOf("Threat intelligence sources") < tv.indexOf("Local heuristics"), "sources are separate from categories");
  assert.ok(!/PhishTank[^<]*<\/span><span class="count">0 emails/.test(tv));
  const timeBtn = d => e.timeBtns.find(b => b.getAttribute("data-time") === d);
  timeBtn("weekly").click(); await tick();
  timeBtn("monthly").click(); await tick();
  timeBtn("daily").click(); await tick();
  assert.ok(e.calls.includes("/api/dashboard/risk-trend?period=week"), "Weekly fetches real week data");
  assert.ok(e.calls.includes("/api/dashboard/risk-trend?period=month"), "Monthly fetches real month data");
  assert.ok(timeBtn("daily").classList.contains("active") && !timeBtn("weekly").classList.contains("active"));
  console.log("ok - dashboard endpoints, threat vectors, daily/weekly/monthly");

  console.log("all boot tests passed");
})().catch(err => { console.error(err); process.exit(1); });
