"""
ONE unified risk engine.

Replaces the original risk_engine.py's `url_count > 0 -> +5` rule,
which would have penalized every legitimate newsletter/receipt email
that contains a link. Per the project's explicit false-positive
requirement: many headers, many URLs, a PDF attachment, or a Google
relay hop must NOT by themselves push a score toward HIGH/CRITICAL.
Only *evidence* does that: a failed auth check, a mismatched
Reply-To/Return-Path, a URL/IP actually listed by a local
threat-intel feed, meaningful local-heuristic flags, or a genuinely
suspicious attachment.

--------------------------------------------------------------------
CANONICAL STAGE ORDER (attachment-first/conditional, see
analysis_service.py and attachment_analysis.py)
--------------------------------------------------------------------
Attachments are analyzed FIRST, before M1/M2/M3/M4, because their
metadata is available immediately and is the cheapest signal in the
pipeline. A high-severity attachment finding (executable/script,
macro-enabled document, disguised double extension) is used to
conditionally force M2's deeper rule-based text scan even when the ML
phishing probability alone is low - this only ever adds scanning, it
never removes it, so it cannot introduce a false negative. This
engine no longer computes attachment severity itself - that
determination is made once, in attachment_analysis.py, and passed in
here as `attachment_analysis`. Keeping exactly one place that decides
"is this attachment suspicious" avoids the duplicate-risk-logic
problem this project has explicitly been asked to avoid.

--------------------------------------------------------------------
CONFIGURABLE RISK POLICY (RISK_CONFIG, below)
--------------------------------------------------------------------
Every weight/multiplier, cap, floor, and severity threshold used by
calculate_risk() lives in the single RISK_CONFIG structure below.
There are no other magic numbers scattered through the scoring logic
- if a value affects the score, it is a named entry in RISK_CONFIG
and is read from there. The values below are the CURRENT/production
policy (unchanged from the previous hardcoded version) presented as
defaults, so normal behavior is unaffected unless RISK_CONFIG itself
is edited or a caller passes a `config=` override to calculate_risk().

DOCUMENTED WEIGHTS (max 100, floor 0) - see RISK_CONFIG for the exact
machine-readable values:

M2 (AI/ML):
  phishing_probability            -> up to 40 points (probability * 40)
  multithreat "phishing" >= 70%   -> +10
  multithreat "phishing" >= 40%   -> +5
  multithreat "suspicious" >= 50% -> +6
  multithreat "spam" >= 70%       -> +3

M1 (auth/header forensics):
  SPF fail                        -> +8
  DKIM fail                       -> +8
  DMARC fail                      -> +8
  Reply-To mismatch               -> +10
  Return-Path mismatch            -> +8  (or +2 if SPF+DKIM+DMARC all pass)

M3 (threat intelligence, source-transparent):
  URL listed by PhishTank         -> +20 per listed URL (capped +40)
  IP listed by Spamhaus DROP      -> +20 per listed IP  (capped +40)
  Local heuristic local_score     -> up to +10 total (avg local_score / 10,
                                      capped), never enough alone to reach HIGH

Attachments (from attachment_analysis.py, computed FIRST):
  Executable/script extension, macro-enabled document, disguised
  double extension, or an extension/detected-type mismatch
                                     -> +15 per flagged file (capped +30)
  A PDF/DOCX/XLSX/image by itself   -> +0 (not inherently suspicious)
  YARA high/medium-severity match   -> EXPLICIT FLOOR: score forced to
                                        at least 65 (HIGH), on top of
                                        (not instead of) the normal
                                        additive scoring above. This is
                                        a deliberate policy so a
                                        malicious attachment cannot be
                                        diluted away by a low body/AI
                                        score - see calculate_risk().

Risk levels:
  0-29   LOW
  30-59  MEDIUM
  60-79  HIGH
  80-100 CRITICAL
--------------------------------------------------------------------
"""

from __future__ import annotations

import copy

RISK_CONFIG_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Single source of truth for every weight/multiplier, cap, floor, and
# severity threshold used by calculate_risk(). These are the CURRENT
# production values - changing one changes real scoring behavior, so
# treat this structure itself as the policy document.
# ---------------------------------------------------------------------------
RISK_CONFIG: dict = {
    "weights": {
        # M2 - AI / ML
        "ml_phishing_probability_multiplier": 40,
        "ml_phishing_category_high_threshold": 70,
        "ml_phishing_category_high_bonus": 10,
        "ml_phishing_category_moderate_threshold": 40,
        "ml_phishing_category_moderate_bonus": 5,
        "ml_suspicious_category_threshold": 50,
        "ml_suspicious_category_bonus": 6,
        "ml_spam_category_threshold": 70,
        "ml_spam_category_bonus": 3,
        "ml_phishing_probability_reason_threshold": 0.60,
        "rule_based_divisor": 4,
        "rule_based_min_contribution": 3,
        # M1 - auth / header forensics
        "spf_fail": 8,
        "dkim_fail": 8,
        "dmarc_fail": 8,
        "reply_to_mismatch": 10,
        "return_path_mismatch_strong_auth": 2,
        "return_path_mismatch_weak_auth": 8,
        # M3 - threat intelligence
        "phishtank_per_url": 20,
        "spamhaus_per_ip": 20,
        "local_heuristic_generic_divisor": 2,
        # Base local_score already attributed to a named strong
        # indicator - subtracted from an item's local_score before the
        # generic bucket runs, so the same evidence is never scored
        # twice (once as a named flag, once as generic local_score).
        "local_heuristic_explicit_bases": {
            "brand_lookalike_domain": 30,
            "uri_userinfo_obfuscation": 20,
            "redirector_with_nested_destination": 20,
        },
        "local_heuristic_strong_flag_weights": {
            "brand_lookalike_domain": 24,
            "uri_userinfo_obfuscation": 20,
            "redirector_with_nested_destination": 22,
        },
        # Attachments
        "attachment_per_flagged_file": 15,
    },
    "caps": {
        "rule_based_max": 15,
        "phishtank_max": 40,
        "spamhaus_max": 40,
        "local_heuristic_generic_max": 8,
        "local_heuristic_strong_max": 30,
        "attachment_max": 30,
    },
    "floors": {
        # A high/medium-severity YARA match is a strong enough
        # independent signal that a low body/AI score must not be
        # able to dilute it below HIGH. This is a floor, not
        # "YARA matched -> 100": the additive score above is still
        # computed normally and can end up higher than the floor on
        # its own evidence; the floor only raises a score that would
        # otherwise land below it.
        "yara_high_medium_floor": 65,
    },
    "thresholds": {
        "low_max": 29,
        "medium_min": 30,
        "medium_max": 59,
        "high_min": 60,
        "high_max": 79,
        "critical_min": 80,
    },
}


def _cfg(config: dict | None) -> dict:
    """Merge a caller-supplied override on top of the RISK_CONFIG
    defaults (one level deep per top-level section), so partial
    overrides (e.g. only `{"weights": {...}}`) don't silently drop the
    rest of the policy. Returns a fresh dict; RISK_CONFIG itself is
    never mutated."""
    merged = copy.deepcopy(RISK_CONFIG)
    if not config:
        return merged
    for section, values in config.items():
        if isinstance(values, dict) and isinstance(merged.get(section), dict):
            merged[section].update(values)
        else:
            merged[section] = values
    return merged


def calculate_risk(
    *,
    m1: dict,
    m2: dict,
    m3: dict,
    header_analysis: dict,
    attachment_analysis: dict,
    config: dict | None = None,
) -> dict:
    cfg = _cfg(config)
    weights = cfg["weights"]
    caps = cfg["caps"]
    floors = cfg["floors"]
    thresholds = cfg["thresholds"]

    score = 0.0
    reasons: list[str] = []
    contributing_modules: list[str] = []

    # Explainable calculation breakdown - one entry per contribution
    # actually applied to the score (zero-value checks that didn't
    # trigger are not listed as noise).
    calc_items: list[dict] = []
    caps_applied: list[dict] = []
    floors_applied: list[dict] = []

    def _add(signal: str, input_value, multiplier, contribution: float, **extra):
        contribution = round(contribution, 4)
        item = {
            "signal": signal,
            "input": input_value,
            "multiplier": multiplier,
            "contribution": contribution,
        }
        item.update(extra)
        calc_items.append(item)
        return contribution

    # ---------------- M2: AI / ML ----------------
    phishing_probability = m2.get("phishing_probability", 0) / 100.0
    ml_multiplier = weights["ml_phishing_probability_multiplier"]
    ml_contribution = phishing_probability * ml_multiplier
    if phishing_probability > 0:
        score += _add(
            "ML phishing probability",
            round(phishing_probability * 100, 2),
            ml_multiplier,
            ml_contribution,
        )
        contributing_modules.append("M2")

    threat_categories = m2.get("threat_categories", {})
    phishing_cat = threat_categories.get("phishing", 0)
    suspicious_cat = threat_categories.get("suspicious", 0)
    spam_cat = threat_categories.get("spam", 0)

    if phishing_cat >= weights["ml_phishing_category_high_threshold"]:
        bonus = weights["ml_phishing_category_high_bonus"]
        score += _add("AI phishing-category confidence (high)", phishing_cat, bonus, bonus)
        reasons.append("AI model: high phishing-category confidence")
    elif phishing_cat >= weights["ml_phishing_category_moderate_threshold"]:
        bonus = weights["ml_phishing_category_moderate_bonus"]
        score += _add("AI phishing-category confidence (moderate)", phishing_cat, bonus, bonus)
        reasons.append("AI model: moderate phishing-category confidence")

    if suspicious_cat >= weights["ml_suspicious_category_threshold"]:
        bonus = weights["ml_suspicious_category_bonus"]
        score += _add("AI suspicious-category confidence", suspicious_cat, bonus, bonus)
        reasons.append("AI model: elevated 'suspicious' category confidence")

    if spam_cat >= weights["ml_spam_category_threshold"]:
        bonus = weights["ml_spam_category_bonus"]
        score += _add("AI spam-category confidence", spam_cat, bonus, bonus)

    if phishing_probability >= weights["ml_phishing_probability_reason_threshold"]:
        reasons.append(f"AI phishing probability {phishing_probability * 100:.0f}%")

    # rule_based_threats now always runs in ml_classifier.classify_email
    # (previously gated behind phishing_probability >= 40%, which meant
    # a message the ML model was unsure about never got the cheap
    # keyword scan at all) and is scored HERE independently of the AI
    # probability above, so a confident keyword hit (BEC/credential-
    # theft/financial-fraud phrasing) is not silenced just because the
    # ML model itself was uncertain.
    rule_based_threats = m2.get("rule_based_threats") or {}
    if rule_based_threats:
        top_category = max(rule_based_threats, key=rule_based_threats.get)
        top_score = rule_based_threats.get(top_category, 0)
        # Cheap keyword matching is noisier than the trained ML model,
        # so it is weighted down and can move a message toward MEDIUM
        # but never single-handedly reach HIGH on its own.
        divisor = weights["rule_based_divisor"]
        cap = caps["rule_based_max"]
        raw_contribution = top_score / divisor
        rule_based_contribution = min(raw_contribution, cap)
        if rule_based_contribution >= weights["rule_based_min_contribution"]:
            score += _add(
                f"Rule-based keyword scan ('{top_category}')",
                top_score,
                f"1/{divisor}",
                rule_based_contribution,
            )
            if raw_contribution > cap:
                caps_applied.append({
                    "cap": "rule_based_max",
                    "limit": cap,
                    "raw_value": round(raw_contribution, 4),
                    "clamped_value": rule_based_contribution,
                })
            contributing_modules.append("M2")
            reasons.append(
                f"Rule-based keyword scan flagged '{top_category}' language"
            )

    # ---------------- M1: auth / forensics ----------------
    if m1:
        contributing_modules.append("M1")
        if m1.get("spf") == "fail":
            w = weights["spf_fail"]
            score += _add("SPF failed", True, w, w)
            reasons.append("SPF failed")
        if m1.get("dkim") == "fail":
            w = weights["dkim_fail"]
            score += _add("DKIM failed", True, w, w)
            reasons.append("DKIM failed")
        if m1.get("dmarc") == "fail":
            w = weights["dmarc_fail"]
            score += _add("DMARC failed", True, w, w)
            reasons.append("DMARC failed")

    if header_analysis.get("reply_to_mismatch"):
        w = weights["reply_to_mismatch"]
        score += _add("Reply-To mismatch", True, w, w)
        reasons.append("Reply-To does not match sender")
        contributing_modules.append("M1")

    if header_analysis.get("return_path_mismatch"):
        # BUG FIX (Twitch false positive / Return-Path semantics - see
        # DIAGNOSTIC_EVIDENCE.md): this used to add a flat +8
        # regardless of authentication outcome. Return-Path differing
        # from the visible sender is completely normal for legitimate
        # bulk-mail/ESP infrastructure (Amazon SES, SendGrid,
        # Mailchimp, ...) precisely BECAUSE that infrastructure is
        # third-party - it is not, by itself, evidence of spoofing.
        # Verified against a real Twitch notification (From:
        # no-reply@twitch.tv, Return-Path on Amazon SES) with SPF,
        # DKIM, and DMARC all passing: the flat +8 contributed roughly
        # a sixth of that email's total score with no relationship to
        # whether the message was actually authenticated.
        #
        # This is generic - it keys off the authentication verdicts
        # already computed by M1 for every message, not off any
        # specific sender - so it does not special-case Twitch (or
        # any other domain) and still scores a mismatch on an
        # unauthenticated message the same as before.
        strong_auth = (
            m1.get("spf") == "pass"
            and m1.get("dkim") == "pass"
            and m1.get("dmarc") == "pass"
        )
        if strong_auth:
            w = weights["return_path_mismatch_strong_auth"]
            score += _add("Return-Path mismatch (strong auth)", True, w, w)
            reasons.append(
                "Return-Path differs from sender (common for authenticated "
                "bulk-mail/ESP infrastructure; weak signal since SPF, DKIM, "
                "and DMARC all passed)"
            )
        else:
            w = weights["return_path_mismatch_weak_auth"]
            score += _add("Return-Path mismatch (auth not fully passing)", True, w, w)
            reasons.append("Return-Path does not match sender")
        contributing_modules.append("M1")

    # ---------------- M3: threat intelligence ----------------
    critical_evidence = False
    if m3:
        listed_urls = [r for r in m3.get("phishtank", []) if r.get("listed")]
        listed_ips = [r for r in m3.get("spamhaus", []) if r.get("listed")]

        if listed_urls:
            contributing_modules.append("M3")
            per_url = weights["phishtank_per_url"]
            cap = caps["phishtank_max"]
            raw = len(listed_urls) * per_url
            contribution = min(raw, cap)
            score += _add(
                "PhishTank local feed matches",
                len(listed_urls),
                per_url,
                contribution,
            )
            if raw > cap:
                caps_applied.append({
                    "cap": "phishtank_max", "limit": cap, "raw_value": raw, "clamped_value": contribution,
                })
            reasons.append(
                f"{len(listed_urls)} URL(s) matched the local PhishTank feed"
            )
            critical_evidence = True

        if listed_ips:
            contributing_modules.append("M3")
            per_ip = weights["spamhaus_per_ip"]
            cap = caps["spamhaus_max"]
            raw = len(listed_ips) * per_ip
            contribution = min(raw, cap)
            score += _add(
                "Spamhaus DROP local feed matches",
                len(listed_ips),
                per_ip,
                contribution,
            )
            if raw > cap:
                caps_applied.append({
                    "cap": "spamhaus_max", "limit": cap, "raw_value": raw, "clamped_value": contribution,
                })
            reasons.append(
                f"{len(listed_ips)} IP(s) matched the local Spamhaus DROP feed"
            )
            critical_evidence = True

        local_heuristics = m3.get("local_heuristics", [])
        if local_heuristics:
            # Do not double-count the three high-confidence indicators:
            # their local_score is already part of the heuristic result, so
            # subtract the named signal's base contribution before applying
            # the generic local bucket. This keeps a malicious URL from
            # becoming disproportionately large simply because the same
            # evidence is scored once as local_score and again as an
            # explicit flag.
            explicit_bases = weights["local_heuristic_explicit_bases"]
            strong_flag_weights_cfg = weights["local_heuristic_strong_flag_weights"]

            residual_scores = []
            strong_flag_weights = []
            matched_strong_flags: list[str] = []
            for item in local_heuristics:
                item_score = float(item.get("local_score", 0) or 0)
                flags = set(item.get("flags", []))
                explicit_base = max(
                    (weight for flag, weight in explicit_bases.items() if flag in flags),
                    default=0,
                )
                residual_scores.append(max(item_score - explicit_base, 0))

                for flag, weight in strong_flag_weights_cfg.items():
                    if flag in flags:
                        strong_flag_weights.append(weight)
                        matched_strong_flags.append(flag)

            if residual_scores:
                max_residual = max(residual_scores)
                divisor = weights["local_heuristic_generic_divisor"]
                cap = caps["local_heuristic_generic_max"]
                raw_contribution = max_residual / divisor
                generic_local_contribution = min(raw_contribution, cap)
                if generic_local_contribution > 0:
                    score += _add(
                        "Local heuristic indicators (generic)",
                        max_residual,
                        f"1/{divisor}",
                        generic_local_contribution,
                    )
                    if raw_contribution > cap:
                        caps_applied.append({
                            "cap": "local_heuristic_generic_max", "limit": cap,
                            "raw_value": round(raw_contribution, 4), "clamped_value": generic_local_contribution,
                        })
                    contributing_modules.append("M3")
                    reasons.append("Local heuristics flagged indicator patterns")

            # Strong local indicators are explicit, narrow evidence types.
            # Take the strongest useful combination but cap the total so
            # repeated URLs cannot turn a legitimate message into CRITICAL
            # merely through score multiplication.
            if strong_flag_weights:
                cap = caps["local_heuristic_strong_max"]
                raw = sum(strong_flag_weights)
                strong_local_contribution = min(raw, cap)
                score += _add(
                    "Strong local heuristic indicators",
                    sorted(set(matched_strong_flags)),
                    "sum(weights)",
                    strong_local_contribution,
                )
                if raw > cap:
                    caps_applied.append({
                        "cap": "local_heuristic_strong_max", "limit": cap,
                        "raw_value": raw, "clamped_value": strong_local_contribution,
                    })
                contributing_modules.append("M3")
                if "brand_lookalike_domain" in matched_strong_flags:
                    reasons.append(
                        "URL/sender domain closely mimics a known brand (lookalike or homoglyph)"
                    )
                if "uri_userinfo_obfuscation" in matched_strong_flags:
                    reasons.append(
                        "URL uses userinfo (@) obfuscation to hide its real destination host"
                    )
                if "redirector_with_nested_destination" in matched_strong_flags:
                    reasons.append(
                        "URL redirects through a nested destination not shown in the visible link"
                    )
                # These are sufficiently specific that they count as
                # independent evidence for a CRITICAL verdict when combined
                # with other strong signals. They do not by themselves make
                # an email CRITICAL.
                critical_evidence = True

    # Authentication/header failures are also independent high-confidence
    # evidence for CRITICAL. Keep the existing score weights above; this flag
    # only determines whether an otherwise very high aggregate score is
    # allowed to cross the CRITICAL severity boundary.
    if m1 and any(
        m1.get(name) == "fail" for name in ("spf", "dkim", "dmarc")
    ):
        critical_evidence = True
    if header_analysis.get("reply_to_mismatch"):
        critical_evidence = True

    # ---------------- Attachments ----------------
    flagged_items = [
        i for i in (attachment_analysis or {}).get("items", []) if i.get("flags")
    ]
    yara_high_severity_hit = False
    if flagged_items:
        per_file = weights["attachment_per_flagged_file"]
        cap = caps["attachment_max"]
        raw = len(flagged_items) * per_file
        contribution = min(raw, cap)
        score += _add(
            "Flagged attachment(s)",
            len(flagged_items),
            per_file,
            contribution,
        )
        if raw > cap:
            caps_applied.append({
                "cap": "attachment_max", "limit": cap, "raw_value": raw, "clamped_value": contribution,
            })
        for item in flagged_items:
            reasons.append(
                f"Attachment '{item['filename']}' flagged: {', '.join(item['flags'])}"
            )
            yara_info = item.get("yara") or {}
            if yara_info.get("matches"):
                severities = {m.get("severity") for m in yara_info["matches"]}
                if "high" in severities or "medium" in severities:
                    yara_high_severity_hit = True
        contributing_modules.append("attachments")

    raw_score = score
    score = max(0, min(round(score), 100))

    # EXPLICIT POLICY (documented, not an accident of arithmetic): a
    # high/medium-severity YARA match is a strong enough independent
    # signal that a low body/AI score must not be able to dilute it
    # below HIGH. This is a deliberate floor, not "YARA matched -> 100":
    # the unified score above is still computed normally and can end
    # up higher than the floor on its own evidence; the floor only
    # raises a score that would otherwise land below it.
    if yara_high_severity_hit:
        floor_value = floors["yara_high_medium_floor"]
        score_before_floor = score
        score = max(score, floor_value)
        if score != score_before_floor:
            floors_applied.append({
                "floor": "yara_high_medium_floor",
                "minimum": floor_value,
                "score_before": score_before_floor,
                "score_after": score,
            })
        if "YARA rule match forced a minimum HIGH risk floor" not in reasons:
            reasons.append("YARA rule match forced a minimum HIGH risk floor, regardless of body/AI score")

    if score >= thresholds["critical_min"] and critical_evidence:
        level = "CRITICAL"
    elif score >= thresholds["high_min"]:
        level = "HIGH"
    elif score >= thresholds["medium_min"]:
        level = "MEDIUM"
    else:
        level = "LOW"

    if score >= thresholds["critical_min"] and not critical_evidence:
        reasons.append(
            "Aggregate score reached the CRITICAL range, but no independent high-confidence evidence was present; capped at HIGH."
        )

    if not reasons:
        reasons.append("No significant risk indicators found")

    calculation = {
        "raw_score": round(raw_score, 4),
        "final_score": score,
        "items": calc_items,
        "caps_applied": caps_applied,
        "floors_applied": floors_applied,
        "thresholds": dict(thresholds),
    }

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "contributing_modules": sorted(set(contributing_modules)),
        "calculation": calculation,
        "config_version": RISK_CONFIG_VERSION,
    }
