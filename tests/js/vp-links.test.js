// Run with: node tests/js/vp-links.test.js   (also invoked from pytest)
"use strict";
const assert = require("assert");
const { buildLinkModel, classify } = require("../../static/vp-links.js");

const LONG = "https://www.pinterest.com/email/click/?user_id=MTA4NjA3MTQwMzc5Njc5NDM1NA%3D%3D&od=" + "x".repeat(400);

function t(name, fn) { fn(); console.log("ok - " + name); }

t("empty result -> zero counts", () => {
  const m = buildLinkModel({});
  assert.deepStrictEqual(m.counts, { total: 0, safe: 0, suspicious: 0, malicious: 0, unknown: 0, flagged: 0 });
});

t("reads backend `urls` field and splits host/path", () => {
  const m = buildLinkModel({ urls: [LONG] });
  assert.strictEqual(m.counts.total, 1);
  assert.strictEqual(m.items[0].host, "www.pinterest.com");
  assert.ok(m.items[0].pathPreview.length <= 64, "path preview is truncated");
  assert.strictEqual(m.items[0].url, LONG, "full URL is preserved untouched");
});

t("no check data -> unknown (never 'safe')", () => {
  assert.strictEqual(buildLinkModel({ urls: ["https://a.example/"] }).items[0].status, "unknown");
});

t("checked and clean -> safe; long-url flag alone is not suspicious", () => {
  const m = buildLinkModel({
    urls: ["https://a.example/"],
    m3: { phishtank: [{ url: "https://a.example/", listed: false }],
          local_heuristics: [{ indicator: "https://a.example/", indicator_type: "url", flags: ["very_long_url"], local_score: 10 }] },
  });
  assert.strictEqual(m.items[0].status, "safe");
});

t("PhishTank listing -> malicious, sorted first, counted as flagged", () => {
  const m = buildLinkModel({
    urls: ["https://ok.example/", "https://evil.example/login"],
    m3: { phishtank: [{ url: "https://ok.example/", listed: false }, { url: "https://evil.example/login", listed: true }],
          local_heuristics: [] },
  });
  assert.strictEqual(m.items[0].url, "https://evil.example/login");
  assert.strictEqual(m.items[0].status, "malicious");
  assert.strictEqual(m.counts.malicious, 1);
  assert.strictEqual(m.counts.safe, 1);
  assert.strictEqual(m.counts.flagged, 1);
});

t("strong heuristic flag -> suspicious", () => {
  assert.strictEqual(classify(null, { flags: ["brand_lookalike_domain"], local_score: 30 }), "suspicious");
  assert.strictEqual(classify(null, { flags: [], local_score: 25 }), "suspicious");
});

t("duplicates collapse; object entries supported; counts add up", () => {
  const m = buildLinkModel({ urls: ["https://a.example/", "https://a.example/", { url: "https://b.example/" }] });
  assert.strictEqual(m.counts.total, 2);
  const c = m.counts;
  assert.strictEqual(c.safe + c.suspicious + c.malicious + c.unknown, c.total);
});

t("malformed URL does not throw", () => {
  const m = buildLinkModel({ urls: ["not a url at all", "http://[::1"] });
  assert.strictEqual(m.counts.total, 2);
});
console.log("all vp-links tests passed");
