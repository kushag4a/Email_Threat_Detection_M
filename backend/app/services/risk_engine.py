"""
ONE unified risk engine.

Replaces the original risk_engine.py's `url_count > 0 → +5` rule,
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
DOCUMENTED WEIGHTS (max 100, floor 0)
--------------------------------------------------------------------
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

def calculate_risk(*, m1: dict, m2: dict, m3: dict, header_analysis: dict, attachment_analysis: dict) -> dict:
    score = 0.0
    reasons: list[str] = []
    contributing_modules: list[str] = []

    # ---------------- M2: AI / ML ----------------
    phishing_probability = m2.get("phishing_probability", 0) / 100.0
    score += phishing_probability * 40
    if phishing_probability > 0:
        contributing_modules.append("M2")

    threat_categories = m2.get("threat_categories", {})
    phishing_cat = threat_categories.get("phishing", 0)
    suspicious_cat = threat_categories.get("suspicious", 0)
    spam_cat = threat_categories.get("spam", 0)

    if phishing_cat >= 70:
        score += 10
        reasons.append("AI model: high phishing-category confidence")
    elif phishing_cat >= 40:
        score += 5
        reasons.append("AI model: moderate phishing-category confidence")

    if suspicious_cat >= 50:
        score += 6
        reasons.append("AI model: elevated 'suspicious' category confidence")

    if spam_cat >= 70:
        score += 3

    if phishing_probability >= 0.60:
        reasons.append(f"AI phishing probability {phishing_probability * 100:.0f}%")

    # ---------------- M1: auth / forensics ----------------
    if m1:
        contributing_modules.append("M1")
        if m1.get("spf") == "fail":
            score += 8
            reasons.append("SPF failed")
        if m1.get("dkim") == "fail":
            score += 8
            reasons.append("DKIM failed")
        if m1.get("dmarc") == "fail":
            score += 8
            reasons.append("DMARC failed")

    if header_analysis.get("reply_to_mismatch"):
        score += 10
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
            score += 2
            reasons.append(
                "Return-Path differs from sender (common for authenticated "
                "bulk-mail/ESP infrastructure; weak signal since SPF, DKIM, "
                "and DMARC all passed)"
            )
        else:
            score += 8
            reasons.append("Return-Path does not match sender")
        contributing_modules.append("M1")

    # ---------------- M3: threat intelligence ----------------
    if m3:
        listed_urls = [r for r in m3.get("phishtank", []) if r.get("listed")]
        listed_ips = [r for r in m3.get("spamhaus", []) if r.get("listed")]

        if listed_urls:
            contributing_modules.append("M3")
            score += min(len(listed_urls) * 20, 40)
            reasons.append(
                f"{len(listed_urls)} URL(s) matched the local PhishTank feed"
            )

        if listed_ips:
            contributing_modules.append("M3")
            score += min(len(listed_ips) * 20, 40)
            reasons.append(
                f"{len(listed_ips)} IP(s) matched the local Spamhaus DROP feed"
            )

        local_scores = [
            h.get("local_score", 0) for h in m3.get("local_heuristics", [])
        ]
        if local_scores:
            avg_local = sum(local_scores) / len(local_scores)
            local_contribution = min(avg_local / 10, 8)
            if local_contribution >= 5:
                score += local_contribution
                contributing_modules.append("M3")
                reasons.append("Local heuristics flagged indicator patterns")

    # ---------------- Attachments ----------------
    flagged_items = [
        i for i in (attachment_analysis or {}).get("items", []) if i.get("flags")
    ]
    yara_high_severity_hit = False
    if flagged_items:
        score += min(len(flagged_items) * 15, 30)
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

    score = max(0, min(round(score), 100))

    # EXPLICIT POLICY (documented, not an accident of arithmetic): a
    # high/medium-severity YARA match is a strong enough independent
    # signal that a low body/AI score must not be able to dilute it
    # below HIGH. This is a deliberate floor, not "YARA matched -> 100":
    # the unified score above is still computed normally and can end
    # up higher than the floor on its own evidence; the floor only
    # raises a score that would otherwise land below HIGH.
    if yara_high_severity_hit:
        score = max(score, 65)
        if "YARA rule match forced a minimum HIGH risk floor" not in reasons:
            reasons.append("YARA rule match forced a minimum HIGH risk floor, regardless of body/AI score")

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("No significant risk indicators found")

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "contributing_modules": sorted(set(contributing_modules)),
    }
