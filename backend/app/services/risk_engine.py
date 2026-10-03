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
SpamAssassin (optional, supporting signal only - see RISK_CONFIG["spamassassin"]):
  SpamAssassin score above its own reported threshold (falling back to
  RISK_CONFIG["spamassassin"]["default_score_threshold"] when the
  adapter did not report one) -> (score - threshold) * score_multiplier,
  capped at max_contribution (recommended/default: 5 points total).
  Zero contribution whenever the stage is disabled (either via this
  engine's own RISK_CONFIG["spamassassin"]["enabled"] flag or because
  the adapter itself is disabled/unavailable/errored/timed out), or
  the reported score is None. SpamAssassin NEVER creates a floor or a
  hard override, and never independently reaches HIGH/CRITICAL - see
  RISK_CONFIG["spamassassin"] and the "SpamAssassin" section of
  calculate_risk() below. is_spam=True (only) adds the "Spam"
  threat_type - never phishing/malware/BEC.
--------------------------------------------------------------------
HARDENING (2026): deterministic evidence cannot be neutralized
--------------------------------------------------------------------
Per the final risk-hardening review, ML classifies email CONTENT, but
deterministic security evidence can impose severity FLOORS or hard
OVERRIDES when the evidence is intrinsically high-confidence. The
scoring pipeline, in order, is:

  1. Additive score from independent signals (as documented above,
     plus the deterministic BEC section - see bec_detector.py).
  2. Section caps (per-signal, already applied inline above).
  3. Deterministic severity FLOORS (RISK_CONFIG["floors"]) - raise a
     score that would otherwise land too low. Floors never lower a
     score that is already higher on its own evidence.
  4. Threshold mapping (score -> LOW/MEDIUM/HIGH/CRITICAL).
  5. Hard OVERRIDES (RISK_CONFIG["overrides"]) - CRITICAL-grade
     evidence classes ONLY. Applied last, so they can only raise the
     outcome, never lower it, and can never be suppressed by a low/
     benign ML score. Every override is named, documented, and
     reported in `overrides_applied` - there is no hidden "force
     critical" switch.
  6. ML can contribute to the additive score but cannot reduce a
     floor or override applied by deterministic evidence.

Evidence classes (see RISK_CONFIG["overrides"]/["floors"] for the
exact, current thresholds):
  CRITICAL-grade (hard override): a YARA severity=high match; a
    magic-byte-confirmed executable disguised behind a non-executable
    filename/extension; a confirmed PhishTank URL match; an extreme,
    multi-category BEC combination occurring together with an
    identity/authentication mismatch.
  HIGH-grade (floor): a YARA severity=medium match; a magic-byte-
    confirmed executable attachment (even with no YARA match); a
    confirmed Spamhaus DROP IP match; a serious BEC combination
    (without an accompanying identity mismatch); a high-confidence
    lookalike domain combined with credential/payment-intent
    language.

Deterministic BEC (business email compromise) evidence comes from
bec_detector.py: specific, multi-word phrase PATTERNS grouped into
named categories (payment/bank change, invoice/payment instructions,
payroll change, gift-card requests, executive impersonation, secrecy
+urgency, wire/ACH change, supplier banking change) - never a single
generic word. A lone category contributes only its own modest weight
(RISK_CONFIG["weights"]["bec_category_weights"]); real severity comes
from named combo bonuses for specific dangerous PAIRINGS
(RISK_CONFIG["weights"]["bec_combo_bonus_weights"]), all capped
(RISK_CONFIG["caps"]["bec_max"]).

`threat_types` (Malware Attachment, Credential Phishing, Brand
Impersonation, Malicious Redirect, BEC / Financial Fraud,
Authentication Spoofing, Threat Intelligence Match, Suspicious
Infrastructure) are derived ONLY from the deterministic evidence
above - never from ML probability alone - so they are stable inputs
for dashboard aggregation.
--------------------------------------------------------------------
"""

from __future__ import annotations

import copy

RISK_CONFIG_VERSION = "1.2.0"

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
        # BEC (Business Email Compromise) - deterministic, combination
        # based. Each category is a named, multi-word-phrase pattern
        # (see bec_detector.py) - never a single generic word. A lone
        # category contributes only its own modest weight; real
        # severity comes from the combo bonuses below, which only
        # fire for specific, genuinely dangerous PAIRINGS of evidence.
        "bec_category_weights": {
            "payment_bank_change": 12,
            "invoice_payment_instruction": 6,
            "payroll_change": 10,
            "gift_card_request": 10,
            "executive_impersonation": 10,
            "secrecy_urgency": 8,
            "wire_ach_change": 12,
            "supplier_banking_change": 12,
        },
        "bec_combo_bonus_weights": {
            "impersonation_plus_payment_change": 15,
            "secrecy_urgency_plus_payment": 10,
            "gift_card_plus_impersonation": 10,
        },
    },
    "caps": {
        "rule_based_max": 15,
        "phishtank_max": 40,
        "spamhaus_max": 40,
        "local_heuristic_generic_max": 8,
        "local_heuristic_strong_max": 30,
        "attachment_max": 30,
        "bec_max": 35,
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
        # High-grade: an attachment declared/named as an executable
        # (.exe/.scr/...) whose content is CONFIRMED (by magic bytes,
        # not by trusting the extension) to actually be an executable.
        # This is independent of YARA - a genuine executable payload
        # is dangerous even with no rule match.
        "verified_executable_floor": 65,
        # High-grade: at least one origin IP confirmed listed on the
        # local Spamhaus DROP feed. The additive per-IP score above
        # (capped) already contributes; this floor guarantees the
        # message cannot land below HIGH purely because ML/body
        # scoring was low.
        "spamhaus_confirmed_floor": 65,
        # High-grade: a serious, multi-category BEC combination
        # (see RISK_CONFIG["overrides"]["extreme_bec_min_categories"]
        # for what counts as "serious"). Without an accompanying
        # identity/authentication mismatch this stays HIGH, not
        # CRITICAL - see the "extreme_bec_with_identity_mismatch"
        # override below for the CRITICAL-grade version.
        "bec_extreme_combo_floor": 65,
        # High-grade: a high-confidence lookalike/homoglyph domain
        # combined with clear credential- or payment-intent language.
        # Either signal alone is already scored on its own merits;
        # this floor is for the specific dangerous COMBINATION.
        "lookalike_plus_payment_intent_floor": 65,
    },
    # ------------------------------------------------------------------
    # Hard overrides - CRITICAL-grade evidence classes only. Each is a
    # named, documented condition (never a hidden "force critical"
    # switch): when the condition is met, the final severity is set
    # directly to `level` and the score is raised to at least `floor`
    # so the numeric score and the displayed severity stay consistent.
    # Overrides are applied LAST, after additive scoring, caps,
    # floors, and threshold mapping - see calculate_risk() - and are
    # always reported in the output under `overrides_applied`, naming
    # exactly which evidence triggered them. ML/body-text scoring can
    # never suppress or reverse an override.
    # ------------------------------------------------------------------
    "overrides": {
        "yara_high_severity_malicious": {
            "floor": 88,
            "level": "CRITICAL",
            "description": (
                "A YARA rule match with severity=high is a genuinely "
                "high-confidence malicious-content finding (e.g. a "
                "PowerShell dropper, process-injection API combination, "
                "or macro auto-exec pattern) - not merely a name/extension "
                "heuristic. This is treated as CRITICAL-grade evidence "
                "regardless of body text or ML score."
            ),
        },
        "disguised_malicious_executable": {
            "floor": 90,
            "level": "CRITICAL",
            "description": (
                "The attachment's real content (confirmed by magic bytes) "
                "is an executable disguised behind a non-executable "
                "filename/extension (e.g. 'invoice.pdf.exe' or a "
                "mismatched declared type) - a deliberate evasion pattern, "
                "not an incidental mismatch."
            ),
        },
        "confirmed_malicious_url_threat_intel": {
            "floor": 88,
            "level": "CRITICAL",
            "description": (
                "At least one URL in the message is confirmed listed on "
                "the local PhishTank feed. A confirmed threat-intelligence "
                "match on a URL actually present in this message is "
                "CRITICAL-grade evidence that a benign-looking body or low "
                "ML phishing probability must not be able to neutralize."
            ),
        },
        "extreme_bec_with_identity_mismatch": {
            "floor": 85,
            "level": "CRITICAL",
            "description": (
                "A serious, multi-category BEC combination (executive "
                "impersonation plus a payment/wire/payroll/supplier-"
                "banking change request, optionally with secrecy+urgency) "
                "occurring TOGETHER WITH an independent identity or "
                "authentication mismatch (SPF/DKIM/DMARC failure, or a "
                "Reply-To mismatch) - i.e. the impersonation claim and the "
                "header evidence corroborate each other."
            ),
        },
        # Minimum number of distinct BEC categories (see
        # bec_detector.py) required before a combination counts as
        # "serious" for bec_extreme_combo_floor / this override. Must
        # include executive_impersonation and at least one
        # payment-type category (payment_bank_change, wire_ach_change,
        # payroll_change, supplier_banking_change, gift_card_request).
        "extreme_bec_min_categories": 3,
    },
    "thresholds": {
        "low_max": 29,
        "medium_min": 30,
        "medium_max": 59,
        "high_min": 60,
        "high_max": 79,
        "critical_min": 80,
    },
    # ------------------------------------------------------------------
    # SpamAssassin - a SMALL, OPTIONAL, CONFIGURABLE supporting signal
    # (see backend/app/spam and the module docstring above). This is
    # spam-oriented evidence only - it is never treated as a phishing,
    # malware, BEC, or threat-intel verdict, never creates a floor or
    # a hard override, and can never by itself push a message into
    # HIGH/CRITICAL (see the "SpamAssassin" section of calculate_risk()).
    # Deterministic security evidence (YARA, threat-intel, BEC) always
    # keeps its existing priority: SpamAssassin's contribution is
    # additive only, capped low, and applied before floors/overrides so
    # it can never dilute or suppress them either.
    # ------------------------------------------------------------------
    "spamassassin": {
        # Engine-level toggle for whether SpamAssassin evidence is
        # allowed to affect the risk SCORE at all. This is independent
        # of, and in addition to, the adapter's own SPAMASSASSIN_ENABLED
        # environment flag (backend/app/spam/config.py), which controls
        # whether the adapter runs at all. Turning this off still lets
        # the raw SpamAssassin result be surfaced elsewhere (e.g. the
        # `spamassassin` field on AnalysisResult) without it influencing
        # the score.
        "enabled": True,
        # Fallback spam-score threshold used only when a given message's
        # SpamAssassin result did not report its own `threshold`
        # (SpamAssassin's `required=` value). When the adapter DID
        # report a threshold, that per-message value is used instead -
        # see calculate_risk().
        "default_score_threshold": 5.0,
        # Points of risk contribution per point of SpamAssassin score
        # above the (per-message or default) threshold.
        "score_multiplier": 1.0,
        # Hard cap on SpamAssassin's total contribution to the risk
        # score, regardless of how far above threshold the score is.
        # RECOMMENDED DEFAULT: 5 - small enough that SpamAssassin alone
        # can never move a message between severity levels on its own.
        "max_contribution": 5,
    },
}

# Categories from bec_detector.py that represent an actual
# payment/money-movement request (as opposed to impersonation or
# secrecy/urgency framing alone). Used both for the "impersonation +
# payment change" combo bonus and for the extreme-combination floor.
_BEC_PAYMENT_TYPE_CATEGORIES = {
    "payment_bank_change",
    "wire_ach_change",
    "payroll_change",
    "supplier_banking_change",
    "gift_card_request",
    "invoice_payment_instruction",
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
    bec_analysis: dict | None = None,
    spamassassin: dict | None = None,
    config: dict | None = None,
) -> dict:
    cfg = _cfg(config)
    weights = cfg["weights"]
    caps = cfg["caps"]
    floors = cfg["floors"]
    overrides_cfg = cfg.get("overrides", {})
    thresholds = cfg["thresholds"]
    spamassassin_cfg = cfg.get("spamassassin", {})

    score = 0.0
    reasons: list[str] = []
    contributing_modules: list[str] = []
    threat_types: set[str] = set()

    # Explainable calculation breakdown - one entry per contribution
    # actually applied to the score (zero-value checks that didn't
    # trigger are not listed as noise).
    calc_items: list[dict] = []
    caps_applied: list[dict] = []
    floors_applied: list[dict] = []
    overrides_applied: list[dict] = []

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
        # threat_types come from deterministic (keyword-pattern)
        # evidence, never from raw ML probability - see module
        # docstring.
        if rule_based_threats.get("credential_theft", 0) > 0:
            threat_types.add("Credential Phishing")
        if rule_based_threats.get("phishing", 0) > 0:
            threat_types.add("Credential Phishing")

    # ---------------- Deterministic BEC (combination-based) ----------------
    # See bec_detector.py: each category is a specific multi-word
    # phrase pattern, never a single generic word, and is present or
    # absent (no double counting within a category). Real severity
    # comes from named combo bonuses for genuinely dangerous pairings,
    # not from summing many weak categories.
    bec = bec_analysis or {}
    bec_categories: dict = bec.get("categories") or {}
    bec_extreme_combo = False
    if bec_categories:
        contributing_modules.append("BEC")
        cat_weights = weights["bec_category_weights"]
        combo_weights = weights["bec_combo_bonus_weights"]
        bec_cap = caps["bec_max"]

        raw_bec = sum(cat_weights.get(cat, 0) for cat in bec_categories)
        combo_hits: list[str] = []

        has_impersonation = "executive_impersonation" in bec_categories
        has_payment_type = bool(_BEC_PAYMENT_TYPE_CATEGORIES & bec_categories.keys())
        has_secrecy_urgency = "secrecy_urgency" in bec_categories
        has_gift_card = "gift_card_request" in bec_categories

        if has_impersonation and has_payment_type:
            raw_bec += combo_weights["impersonation_plus_payment_change"]
            combo_hits.append("impersonation_plus_payment_change")
        if has_secrecy_urgency and has_payment_type:
            raw_bec += combo_weights["secrecy_urgency_plus_payment"]
            combo_hits.append("secrecy_urgency_plus_payment")
        if has_gift_card and has_impersonation:
            raw_bec += combo_weights["gift_card_plus_impersonation"]
            combo_hits.append("gift_card_plus_impersonation")

        bec_contribution = min(raw_bec, bec_cap)
        score += _add(
            "Deterministic BEC pattern combination",
            sorted(bec_categories),
            "category weights + combo bonuses",
            bec_contribution,
            combo_bonuses_applied=combo_hits,
        )
        if raw_bec > bec_cap:
            caps_applied.append({
                "cap": "bec_max", "limit": bec_cap, "raw_value": raw_bec, "clamped_value": bec_contribution,
            })
        reasons.append(
            "Deterministic BEC evidence: " + ", ".join(sorted(bec_categories))
        )
        threat_types.add("BEC / Financial Fraud")

        extreme_min = overrides_cfg.get("extreme_bec_min_categories", 3)
        bec_extreme_combo = (
            len(bec_categories) >= extreme_min
            and has_impersonation
            and has_payment_type
        )

    # ---------------- M1: auth / forensics ----------------
    identity_or_auth_mismatch = False
    if m1:
        contributing_modules.append("M1")
        if m1.get("spf") == "fail":
            w = weights["spf_fail"]
            score += _add("SPF failed", True, w, w)
            reasons.append("SPF failed")
            identity_or_auth_mismatch = True
            threat_types.add("Authentication Spoofing")
        if m1.get("dkim") == "fail":
            w = weights["dkim_fail"]
            score += _add("DKIM failed", True, w, w)
            reasons.append("DKIM failed")
            identity_or_auth_mismatch = True
            threat_types.add("Authentication Spoofing")
        if m1.get("dmarc") == "fail":
            w = weights["dmarc_fail"]
            score += _add("DMARC failed", True, w, w)
            reasons.append("DMARC failed")
            identity_or_auth_mismatch = True
            threat_types.add("Authentication Spoofing")

    if header_analysis.get("reply_to_mismatch"):
        w = weights["reply_to_mismatch"]
        score += _add("Reply-To mismatch", True, w, w)
        reasons.append("Reply-To does not match sender")
        contributing_modules.append("M1")
        identity_or_auth_mismatch = True
        threat_types.add("Authentication Spoofing")

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
            identity_or_auth_mismatch = True
            threat_types.add("Authentication Spoofing")
        contributing_modules.append("M1")

    # ---------------- M3: threat intelligence ----------------
    critical_evidence = False
    confirmed_malicious_url = False
    spamhaus_confirmed = False
    matched_strong_flags: list[str] = []
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
            confirmed_malicious_url = True
            threat_types.add("Threat Intelligence Match")

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
            spamhaus_confirmed = True
            threat_types.add("Threat Intelligence Match")
            threat_types.add("Suspicious Infrastructure")

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
                    threat_types.add("Brand Impersonation")
                if "uri_userinfo_obfuscation" in matched_strong_flags:
                    reasons.append(
                        "URL uses userinfo (@) obfuscation to hide its real destination host"
                    )
                    threat_types.add("Malicious Redirect")
                if "redirector_with_nested_destination" in matched_strong_flags:
                    reasons.append(
                        "URL redirects through a nested destination not shown in the visible link"
                    )
                    threat_types.add("Malicious Redirect")
                # These are sufficiently specific that they count as
                # independent evidence for a CRITICAL verdict when combined
                # with other strong signals. They do not by themselves make
                # an email CRITICAL.
                critical_evidence = True

    # High-grade combination: a high-confidence lookalike/homoglyph
    # domain together with clear credential- or payment-intent
    # language (deterministic BEC evidence or the rule-based
    # credential_theft/financial_fraud keyword categories - never ML
    # probability alone). See RISK_CONFIG["floors"]["lookalike_plus_payment_intent_floor"].
    lookalike_plus_payment_intent = False
    if "brand_lookalike_domain" in matched_strong_flags:
        has_payment_or_credential_intent = bool(
            _BEC_PAYMENT_TYPE_CATEGORIES & bec_categories.keys()
        ) or bool(
            (m2.get("rule_based_threats") or {}).get("credential_theft", 0) > 0
            or (m2.get("rule_based_threats") or {}).get("financial_fraud", 0) > 0
        )
        if has_payment_or_credential_intent:
            lookalike_plus_payment_intent = True

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
    yara_high_severity_hit = False  # high OR medium YARA severity (existing HIGH-grade floor)
    yara_truly_high_hit = False     # severity == "high" specifically (CRITICAL-grade override)
    verified_executable_hit = False
    disguised_malicious_executable_hit = False
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
            flags = item.get("flags") or []
            reasons.append(
                f"Attachment '{item['filename']}' flagged: {', '.join(flags)}"
            )
            yara_info = item.get("yara") or {}
            if yara_info.get("matches"):
                severities = {m.get("severity") for m in yara_info["matches"]}
                if "high" in severities or "medium" in severities:
                    yara_high_severity_hit = True
                    threat_types.add("Malware Attachment")
                if "high" in severities:
                    yara_truly_high_hit = True

            is_verified_executable = (
                item.get("detected_category") == "executable"
                or item.get("detected_type") in ("application/x-msdownload", "application/x-elf")
            )
            if is_verified_executable and "executable_or_script_extension" in flags:
                verified_executable_hit = True
                threat_types.add("Malware Attachment")
            if is_verified_executable and (
                "disguised_double_extension" in flags
                or "extension_content_type_mismatch" in flags
            ):
                disguised_malicious_executable_hit = True
                threat_types.add("Malware Attachment")
        contributing_modules.append("attachments")

    # ---------------- SpamAssassin (optional supporting signal) ----------------
    # Spam-oriented evidence only - never a phishing/malware/BEC/threat-
    # intel verdict. Contributes ZERO when disabled (this engine's own
    # spamassassin.enabled flag), when no result was supplied, when the
    # adapter reports unavailable/errored, or when no numeric score is
    # present (covers disabled/unavailable/failed/timeout/None-score per
    # the adapter's own result contract - see result_schema.py). Never
    # creates a floor or hard override and is capped low (see
    # RISK_CONFIG["spamassassin"]["max_contribution"]) so it can never,
    # by itself, move a message between severity levels.
    score_before_spamassassin = score
    spamassassin_contribution = 0.0
    sa_result = spamassassin or {}
    sa_usable = bool(
        spamassassin_cfg.get("enabled", True)
        and sa_result
        and sa_result.get("available")
        and not sa_result.get("error")
    )
    if sa_usable:
        contributing_modules.append("SpamAssassin")
        sa_score = sa_result.get("score")
        if sa_score is not None:
            sa_score = float(sa_score)
            sa_threshold = sa_result.get("threshold")
            sa_threshold = (
                float(sa_threshold)
                if sa_threshold is not None
                else float(spamassassin_cfg.get("default_score_threshold", 5.0))
            )
            multiplier = spamassassin_cfg.get("score_multiplier", 1.0)
            cap = spamassassin_cfg.get("max_contribution", 5)
            raw_excess = max(0.0, sa_score - sa_threshold)
            raw_contribution = raw_excess * multiplier
            spamassassin_contribution = min(raw_contribution, cap)
            # Recorded unconditionally (even when the contribution is
            # zero, e.g. a below-threshold score) so the calculation
            # breakdown always shows this signal ran and what it found -
            # deliberately not treated as "zero-value noise" like the
            # other sections above, since this is spam-oriented evidence
            # the explanation/evidence contract must surface either way.
            score += _add(
                "SpamAssassin spam score",
                sa_score,
                multiplier,
                spamassassin_contribution,
                threshold=sa_threshold,
                matched_rules=sa_result.get("matched_rules", []),
                is_spam=sa_result.get("is_spam"),
                engine="spamassassin",
            )
            if raw_contribution > cap:
                caps_applied.append({
                    "cap": "spamassassin_max", "limit": cap,
                    "raw_value": round(raw_contribution, 4), "clamped_value": spamassassin_contribution,
                })
            if spamassassin_contribution > 0:
                reasons.append(
                    f"SpamAssassin flagged spam-like indicators (score {sa_score:.1f}, "
                    f"threshold {sa_threshold:.1f})"
                )
        # Only SpamAssassin's own explicit is_spam=True verdict adds the
        # "Spam" threat type - never inferred as phishing/malware/BEC,
        # and never derived from the numeric score alone.
        if sa_result.get("is_spam") is True:
            threat_types.add("Spam")

    raw_score = score
    score_before_floors = max(0, min(round(score), 100))
    score = score_before_floors

    # EXPLICIT POLICY (documented, not an accident of arithmetic): a
    # high/medium-severity YARA match is a strong enough independent
    # signal that a low body/AI score must not be able to dilute it
    # below HIGH. This is a deliberate floor, not "YARA matched -> 100":
    # the unified score above is still computed normally and can end
    # up higher than the floor on its own evidence; the floor only
    # raises a score that would otherwise land below it.
    def _apply_floor(name: str, condition: bool, reason: str):
        nonlocal score
        if not condition:
            return
        floor_value = floors[name]
        score_before_floor = score
        score = max(score, floor_value)
        if score != score_before_floor:
            floors_applied.append({
                "floor": name,
                "minimum": floor_value,
                "score_before": score_before_floor,
                "score_after": score,
            })
        if reason not in reasons:
            reasons.append(reason)

    # EXPLICIT POLICY (documented, not an accident of arithmetic): a
    # high/medium-severity YARA match is a strong enough independent
    # signal that a low body/AI score must not be able to dilute it
    # below HIGH. This is a deliberate floor, not "YARA matched -> 100":
    # the unified score above is still computed normally and can end
    # up higher than the floor on its own evidence; the floor only
    # raises a score that would otherwise land below it.
    _apply_floor(
        "yara_high_medium_floor", yara_high_severity_hit,
        "YARA rule match forced a minimum HIGH risk floor, regardless of body/AI score",
    )
    _apply_floor(
        "verified_executable_floor", verified_executable_hit,
        "Attachment content confirmed (by magic bytes, not filename) to be an executable - "
        "forced a minimum HIGH risk floor, regardless of body/AI score",
    )
    _apply_floor(
        "spamhaus_confirmed_floor", spamhaus_confirmed,
        "Origin IP confirmed on the local Spamhaus DROP feed - forced a minimum HIGH risk floor",
    )
    _apply_floor(
        "bec_extreme_combo_floor", bec_extreme_combo,
        "Serious multi-category BEC combination (impersonation + payment-type request) "
        "forced a minimum HIGH risk floor, regardless of body/AI score",
    )
    _apply_floor(
        "lookalike_plus_payment_intent_floor", lookalike_plus_payment_intent,
        "High-confidence lookalike domain combined with credential/payment-intent language "
        "forced a minimum HIGH risk floor",
    )

    # ---------------- Threshold mapping (score -> severity level) ----------------
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

    # ------------------------------------------------------------------
    # Hard overrides - CRITICAL-grade evidence classes ONLY (see
    # RISK_CONFIG["overrides"]). Applied LAST, after threshold mapping,
    # so they can only ever RAISE the outcome (to CRITICAL) and can
    # never be suppressed by a low ML/body score - that low score is
    # exactly the scenario these overrides exist to guard against.
    # Every override fired is reported in `overrides_applied` with the
    # specific evidence and the config entry that triggered it - there
    # is no undocumented "force critical" path.
    # ------------------------------------------------------------------
    ml_understated = bool(m2 and m2.get("phishing_probability", 0) < 40)

    def _apply_override(name: str, condition: bool, evidence: str):
        nonlocal score, level
        if not condition:
            return
        entry = overrides_cfg.get(name)
        if not entry:
            return
        floor_value = entry["floor"]
        forced_level = entry["level"]
        score_before = score
        score = max(score, floor_value)
        level_before = level
        level = forced_level
        overrides_applied.append({
            "override": name,
            "evidence": evidence,
            "forced_level": forced_level,
            "score_before": score_before,
            "score_after": score,
            "level_before": level_before,
        })
        note = f"Hard override ({name}): {entry['description']}"
        if ml_understated:
            note += (
                " Deterministic evidence controlled the final severity; the AI/ML "
                "phishing probability for this message was low and was NOT permitted "
                "to downgrade or neutralize this evidence."
            )
        reasons.append(note)

    _apply_override(
        "yara_high_severity_malicious", yara_truly_high_hit,
        "YARA rule match with severity=high",
    )
    _apply_override(
        "disguised_malicious_executable", disguised_malicious_executable_hit,
        "Attachment content confirmed executable but disguised via filename/extension/declared type",
    )
    _apply_override(
        "confirmed_malicious_url_threat_intel", confirmed_malicious_url,
        "One or more URLs confirmed listed on the local PhishTank feed",
    )
    _apply_override(
        "extreme_bec_with_identity_mismatch", bec_extreme_combo and identity_or_auth_mismatch,
        "Serious multi-category BEC combination together with an identity/authentication mismatch",
    )

    score = max(0, min(round(score), 100))

    if not reasons:
        reasons.append("No significant risk indicators found")

    calculation = {
        "raw_score": round(raw_score, 4),
        "score_before_spamassassin": round(score_before_spamassassin, 4),
        "spamassassin_contribution": round(spamassassin_contribution, 4),
        "score_before_floors": score_before_floors,
        "final_score": score,
        "items": calc_items,
        "caps_applied": caps_applied,
        "floors_applied": floors_applied,
        "overrides_applied": overrides_applied,
        "thresholds": dict(thresholds),
    }

    return {
        "score": score,
        "level": level,
        "threat_types": sorted(threat_types),
        "reasons": reasons,
        "contributing_modules": sorted(set(contributing_modules)),
        "calculation": calculation,
        "config_version": RISK_CONFIG_VERSION,
    }
