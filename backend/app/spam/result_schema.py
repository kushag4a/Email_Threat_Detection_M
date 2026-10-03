"""Result contract for the isolated SpamAssassin adapter.

This is spam-oriented evidence only: a score and rule hits produced by
SpamAssassin's heuristic rule base. It is a distinct signal from, and must
never be confused with, phishing probability produced elsewhere in the
system (e.g. the V2 phishing model).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SpamAssassinResult(BaseModel):
    """Structured, stable result of a single SpamAssassin analysis call.

    Exactly one of two states holds:
      * A successful analysis: `available=True`, `error=None`, and
        `score`/`threshold`/`is_spam` populated from SpamAssassin's output.
      * A failure (missing executable, timeout, non-zero exit, empty
        input, or unparsable output): `error` is set with a human-readable
        message, and `score`/`threshold`/`is_spam` are `None`.

    Attributes:
        available: Whether the SpamAssassin executable was found and,
            when invoked, ran to completion. `False` when the executable
            itself could not be located.
        score: The spam score SpamAssassin assigned to the message, taken
            directly from its `X-Spam-Status` header. Not a probability.
        threshold: The configured score threshold ("required") above
            which SpamAssassin classifies a message as spam.
        is_spam: SpamAssassin's own Yes/No classification, or `None` if
            analysis did not complete.
        matched_rules: Names of the SpamAssassin rules that fired (the
            `tests=` list), in the order SpamAssassin reported them. Empty
            if none fired or analysis did not complete.
        raw_status: The raw `X-Spam-Status` header value as emitted by
            SpamAssassin, kept for debugging/traceability.
        error: Human-readable failure description, or `None` on success.
        engine: Static identifier for this evidence source, always
            `"spamassassin"`. Present so downstream consumers can
            distinguish this signal from other engines without guessing.
    """

    available: bool = False
    score: float | None = None
    threshold: float | None = None
    is_spam: bool | None = None
    matched_rules: list[str] = Field(default_factory=list)
    raw_status: str | None = None
    error: str | None = None
    engine: str = "spamassassin"
