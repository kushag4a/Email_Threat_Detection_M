/* =========================================================
   ValorProtects — link model for the email-detail modal.

   Pure functions, no DOM, no network. Loaded before app.js (browser:
   window.VPLinks) and also require()-able from Node so the logic is
   unit-testable (see tests/test_frontend_assets.py).

   It only RE-ORGANISES evidence the backend already produced for the
   message (result.urls + result.m3.phishtank / local_heuristics). It
   never decides that a link is safe on its own authority:

     malicious   PhishTank lists the URL
     suspicious  local heuristics raised a meaningful flag / score
     safe        checked by the local feeds + heuristics, nothing found
     unknown     no check result exists for that URL

   "safe" therefore means "no threat indicators found by the local
   checks", not "verified benign".
   ========================================================= */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.VPLinks = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Flags that are informational only and must not, by themselves, make a
  // link "suspicious" (a long tracking URL is normal for marketing mail).
  var WEAK_FLAGS = { very_long_url: true };
  var SUSPICIOUS_SCORE = 20;
  var PATH_PREVIEW_CHARS = 64;

  var STATUS_ORDER = { malicious: 0, suspicious: 1, unknown: 2, safe: 3 };

  function urlOf(entry) {
    if (typeof entry === "string") return entry;
    if (entry && typeof entry === "object") return entry.url || entry.indicator || "";
    return "";
  }

  function splitUrl(url) {
    var host = "";
    var rest = "";
    try {
      var u = new URL(url);
      host = u.hostname || "";
      rest = (u.pathname === "/" && !u.search && !u.hash ? "" : u.pathname) + u.search + u.hash;
    } catch (e) {
      var m = /^[a-z][a-z0-9+.-]*:\/\/([^\/?#]*)([^]*)$/i.exec(url);
      if (m) { host = m[1]; rest = m[2]; } else { rest = url; }
    }
    return { host: host, rest: rest };
  }

  function truncate(text, max) {
    if (text.length <= max) return text;
    return text.slice(0, max - 1) + "\u2026";
  }

  function classify(phishtank, local) {
    if (phishtank && phishtank.listed) return "malicious";
    if (local) {
      var flags = local.flags || [];
      var strong = flags.filter(function (f) { return !WEAK_FLAGS[f]; });
      if (strong.length || (local.local_score || 0) >= SUSPICIOUS_SCORE) return "suspicious";
    }
    if (phishtank || local) return "safe";
    return "unknown";
  }

  function indexBy(list, keyFn) {
    var map = {};
    (list || []).forEach(function (item) {
      var k = keyFn(item);
      if (k && !(k in map)) map[k] = item;
    });
    return map;
  }

  /**
   * Build the structured links model for one analysis result.
   * Returns { items, counts:{total,safe,suspicious,malicious,unknown,flagged} }.
   */
  function buildLinkModel(result) {
    result = result || {};
    var m3 = result.m3 || {};
    var ptByUrl = indexBy(m3.phishtank, function (x) { return x && x.url; });
    var lhByUrl = indexBy(
      (m3.local_heuristics || []).filter(function (x) { return x && x.indicator_type === "url"; }),
      function (x) { return x.indicator; }
    );

    var raw = (result.urls || result.detected_urls || []).map(urlOf).filter(Boolean);
    var seen = {};
    var items = [];
    raw.forEach(function (url) {
      if (seen[url]) return;
      seen[url] = true;
      var parts = splitUrl(url);
      var pt = ptByUrl[url] || null;
      var lh = lhByUrl[url] || null;
      items.push({
        url: url,
        host: parts.host || "(no host)",
        pathPreview: truncate(parts.rest, PATH_PREVIEW_CHARS),
        status: classify(pt, lh),
        phishtank: pt,
        local: lh,
        flags: lh ? (lh.flags || []).slice() : [],
        score: lh ? (lh.local_score || 0) : null
      });
    });

    items.sort(function (a, b) { return STATUS_ORDER[a.status] - STATUS_ORDER[b.status]; });

    var counts = { total: items.length, safe: 0, suspicious: 0, malicious: 0, unknown: 0 };
    items.forEach(function (i) { counts[i.status] += 1; });
    counts.flagged = counts.suspicious + counts.malicious;
    return { items: items, counts: counts };
  }

  return {
    buildLinkModel: buildLinkModel,
    classify: classify,
    splitUrl: splitUrl,
    WEAK_FLAGS: WEAK_FLAGS,
    SUSPICIOUS_SCORE: SUSPICIOUS_SCORE
  };
});
