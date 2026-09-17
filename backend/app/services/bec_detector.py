"""
Deterministic, explainable Business-Email-Compromise (BEC) detector.

This is NOT the legacy single-word keyword scan in threat_classifier.py
(that module fires +15 the moment the word "payment", "invoice", or
"supplier" appears anywhere in the message - see its `BEC` loop). Per
the hardening requirement, BEC risk must come from COMBINATIONS of
specific, multi-word phrases, never from one generic word. A message
that happens to contain the word "payment" once must not, by itself,
contribute anything meaningful here.

Design:
  - Each category below is detected via a list of specific multi-word
    phrases (never a single common word on its own).
  - A category is either present or not (boolean) - matching five
    phrases in the same category still counts once, so the same
    evidence is never scored twice.
  - `secrecy_urgency` additionally requires phrases from TWO different
    sub-groups (a secrecy phrase AND an urgency phrase) before it is
    considered present at all - neither alone is enough.
  - The combination score (category weights + a small number of
    named, explicit combination bonuses for genuinely dangerous
    pairings) lives in risk_engine.RISK_CONFIG["bec"], not here - this
    module only detects and reports evidence; risk_engine.py is the
    single place that turns evidence into score.

Categories map directly to the "useful patterns" from the hardening
brief:
  payment_bank_change        - request to change bank/payment details
  invoice_payment_instruction- invoice/payment remittance instructions
  payroll_change              - payroll/direct-deposit change request
  gift_card_request           - request to purchase gift cards
  executive_impersonation     - sender claims to be an executive
  secrecy_urgency             - confidentiality request + urgency, together
  wire_ach_change              - wire/ACH transfer instruction changes
  supplier_banking_change     - supplier/vendor banking detail changes
"""

from __future__ import annotations

_PAYMENT_BANK_CHANGE_PHRASES = [
    "update the bank account",
    "update our bank details",
    "update our banking details",
    "change the bank account",
    "change the bank details",
    "new bank account details",
    "new banking details",
    "bank details have changed",
    "banking details have changed",
    "update your banking information",
    "change of bank details",
    "updated payment details",
    "update the payment details",
    "please update our payment information",
]

_INVOICE_PAYMENT_INSTRUCTION_PHRASES = [
    "please process the attached invoice",
    "remit payment to",
    "kindly process payment",
    "invoice payment instructions",
    "please arrange payment for the attached invoice",
    "process this invoice for payment",
    "payment is overdue and must be confirmed",
    "follow the instructions for remittance",
    "outstanding invoice must be paid",
]

_PAYROLL_CHANGE_PHRASES = [
    "update my direct deposit",
    "change my payroll direct deposit",
    "update payroll bank information",
    "direct deposit change request",
    "update my paycheck deposit",
    "change my direct deposit information",
]

_GIFT_CARD_REQUEST_PHRASES = [
    "purchase gift cards",
    "buy gift cards",
    "itunes gift cards",
    "google play gift cards",
    "amazon gift cards",
    "buy some gift cards",
    "purchase several gift cards",
    "gift card codes",
    "send me the gift card",
]

_EXECUTIVE_IMPERSONATION_PHRASES = [
    "i am the ceo",
    "this is the ceo",
    "i am the cfo",
    "this is the cfo",
    "i am the director",
    "this is the director",
    "i am your manager",
    "this is your manager",
    "on behalf of the ceo",
    "message from the ceo",
    "i am currently in a meeting",
    "i am in a meeting",
    "i am traveling and unavailable",
    "i am out of the office and need your help",
    # Display-name-spoof pattern: attackers commonly use a title-only
    # "From" display name (e.g. "CEO Office <attacker@evil.test>")
    # instead of a named individual, precisely to avoid a checkable
    # identity claim. build_analysis_text() includes the raw "From:"
    # header line, so these phrases match the display name itself.
    "ceo office",
    "office of the ceo",
    "cfo office",
    "office of the cfo",
    "coo office",
    "office of the coo",
    "executive office",
]

_SECRECY_PHRASES = [
    "keep this confidential",
    "do not discuss this with anyone",
    "don't tell anyone",
    "keep this between us",
    "this must remain confidential",
    "do not tell anyone",
]

_URGENCY_PHRASES = [
    "as soon as possible",
    "right away",
    "immediately",
    "urgent request",
    "before end of day",
    "time sensitive",
    "respond urgently",
]

_WIRE_ACH_CHANGE_PHRASES = [
    "wire transfer instructions",
    "update the wire instructions",
    "new wiring instructions",
    "ach transfer details",
    "change the ach details",
    "update ach information",
    "wire the funds to",
    "send a wire transfer",
    # Urgent-transfer / "CEO fraud" request phrasing - not a change to
    # existing instructions, but an urgent one-off wire/transfer
    # request, which is the classic executive-impersonation wire-fraud
    # pattern rather than the "update our banking details" pattern
    # above. Kept specific (not just "payment" or "transfer") to avoid
    # firing on ordinary invoice/payment correspondence.
    "confidential vendor payment",
    "transfer has been initiated",
    "process this transfer immediately",
    "initiate the wire transfer",
    "vendor payment processed immediately",
]

_SUPPLIER_BANKING_CHANGE_PHRASES = [
    "supplier has changed their bank",
    "vendor bank account has changed",
    "update the vendor's banking",
    "supplier requested a change to their payment details",
    "update the supplier bank account",
    "supplier bank account details",
    "vendor has updated their banking",
]

_CATEGORY_PHRASE_LISTS: dict[str, list[str]] = {
    "payment_bank_change": _PAYMENT_BANK_CHANGE_PHRASES,
    "invoice_payment_instruction": _INVOICE_PAYMENT_INSTRUCTION_PHRASES,
    "payroll_change": _PAYROLL_CHANGE_PHRASES,
    "gift_card_request": _GIFT_CARD_REQUEST_PHRASES,
    "executive_impersonation": _EXECUTIVE_IMPERSONATION_PHRASES,
    "wire_ach_change": _WIRE_ACH_CHANGE_PHRASES,
    "supplier_banking_change": _SUPPLIER_BANKING_CHANGE_PHRASES,
}


def _matched_phrases(text: str, phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in text]


def detect_bec(email_text: str | None) -> dict:
    """
    Returns:
      {
        "categories": {category_name: True, ...},   # present categories only
        "matched_phrases": {category_name: [phrase, ...], ...},
        "category_count": int,
      }

    An empty/None input, or one with no combination-worthy phrase
    matches, returns {"categories": {}, "matched_phrases": {}, "category_count": 0}.
    """
    text = (email_text or "").lower()
    categories: dict[str, bool] = {}
    matched_phrases: dict[str, list[str]] = {}

    for category, phrases in _CATEGORY_PHRASE_LISTS.items():
        hits = _matched_phrases(text, phrases)
        if hits:
            categories[category] = True
            matched_phrases[category] = hits

    secrecy_hits = _matched_phrases(text, _SECRECY_PHRASES)
    urgency_hits = _matched_phrases(text, _URGENCY_PHRASES)
    if secrecy_hits and urgency_hits:
        categories["secrecy_urgency"] = True
        matched_phrases["secrecy_urgency"] = secrecy_hits + urgency_hits

    return {
        "categories": categories,
        "matched_phrases": matched_phrases,
        "category_count": len(categories),
    }
