"""Isolated SpamAssassin adapter.

This package wraps a locally installed SpamAssassin executable to produce
spam-oriented evidence (a score, threshold, verdict, and matched rule
names) for a single raw email. It is self-contained and is NOT currently
wired into the production analysis pipeline (`analysis_service.py`), the
risk engine, NLLB, or the V2 phishing model -- integration is a separate,
deliberate step.

Public API:
    check_available: Check whether the configured SpamAssassin executable
        is present, without running it.
    analyze_email: Run SpamAssassin against a raw email and return a
        structured `SpamAssassinResult`.
    SpamAssassinResult: The stable result contract returned by
        `analyze_email`.
    SpamAssassinConfig / get_spamassassin_config: Environment-driven
        configuration for the adapter.
"""

from .config import SpamAssassinConfig, get_spamassassin_config
from .result_schema import SpamAssassinResult
from .spamassassin import analyze_email, check_available

__all__ = [
    "SpamAssassinConfig",
    "get_spamassassin_config",
    "SpamAssassinResult",
    "analyze_email",
    "check_available",
]
