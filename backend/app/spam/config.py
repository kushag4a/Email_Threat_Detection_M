"""Environment-driven configuration for the isolated SpamAssassin adapter.

Every setting comes from an environment variable with a safe, explicit
default, so the adapter works out of the box in local/dev environments and
can be tuned per-deployment without code changes -- consistent with how the
rest of this project is expected to be configured.

This module owns configuration only. It performs no subprocess calls and
has no dependency on the rest of the `spam` package.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# --- Environment variable names -------------------------------------------------
# Centralized here so callers (and any future tests) reference one source of truth
# instead of hardcoding the string names.
ENV_ENABLED = "SPAMASSASSIN_ENABLED"
ENV_EXECUTABLE = "SPAMASSASSIN_EXECUTABLE"
ENV_ARGS = "SPAMASSASSIN_ARGS"
ENV_TIMEOUT_SECONDS = "SPAMASSASSIN_TIMEOUT_SECONDS"

# --- Defaults ---------------------------------------------------------------
# SpamAssassin is an OPTIONAL analysis stage: disabled unless explicitly
# turned on, so a fresh checkout with no SpamAssassin executable/Docker
# container available still starts and analyzes email normally.
DEFAULT_ENABLED = False

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}

DEFAULT_EXECUTABLE = "spamassassin"

# --test-mode (-t): always pipe the message through and append the full
#     report, whether or not the message is judged spam. Without this,
#     SpamAssassin's default filter behavior only decorates messages it
#     considers spam, which would make ham results harder to parse.
# --local (-L): local tests only -- disables DNS/RBL/network-backed rules,
#     matching this adapter's "no network calls" requirement.
# --nocreate-prefs (-x): don't write a per-user preferences file as a
#     side effect of running.
DEFAULT_ARGS: tuple[str, ...] = ("--test-mode", "--local", "--nocreate-prefs")

DEFAULT_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class SpamAssassinConfig:
    """Immutable runtime configuration for the SpamAssassin adapter.

    Attributes:
        enabled: Master feature flag for the optional SpamAssassin analysis
            stage. When `False` (the default), callers must not invoke
            SpamAssassin (or, transitively, Docker) at all. This flag is
            not read by `analyze_email`/`check_available` themselves --
            it is the integration point's (e.g. the analysis pipeline's)
            responsibility to check it before calling them.
        executable: Command or path used to invoke SpamAssassin.
        args: Extra CLI arguments passed to the executable, in order.
        timeout_seconds: Maximum time to let the subprocess run before it
            is killed and treated as a timeout failure.
    """

    enabled: bool = DEFAULT_ENABLED
    executable: str = DEFAULT_EXECUTABLE
    args: tuple[str, ...] = DEFAULT_ARGS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS


def get_spamassassin_config() -> SpamAssassinConfig:
    """Build a `SpamAssassinConfig` from environment variables.

    Recognized environment variables:
        SPAMASSASSIN_ENABLED:
            Master feature flag for the optional SpamAssassin analysis
            stage. Accepts (case-insensitively) ``"1"/"true"/"yes"/"on"``
            or ``"0"/"false"/"no"/"off"``.
            Default: ``False`` (disabled).
        SPAMASSASSIN_EXECUTABLE:
            Executable name or absolute path to invoke.
            Default: ``"spamassassin"``.
        SPAMASSASSIN_ARGS:
            Whitespace-separated CLI arguments, overriding the default
            argument set entirely when set.
            Default: ``"--test-mode --local --nocreate-prefs"``.
        SPAMASSASSIN_TIMEOUT_SECONDS:
            Subprocess timeout in seconds, parsed as a float.
            Default: ``15.0``.

    Missing or blank variables fall back to defaults. A malformed
    ``SPAMASSASSIN_ENABLED`` or ``SPAMASSASSIN_TIMEOUT_SECONDS`` also falls
    back to the default (disabled / 15.0s) rather than raising, since a
    misconfigured value here should degrade this isolated component
    gracefully rather than break startup.

    Returns:
        A populated, immutable `SpamAssassinConfig`.
    """
    raw_enabled = os.environ.get(ENV_ENABLED, "").strip().lower()
    if raw_enabled in _TRUE_VALUES:
        enabled = True
    elif raw_enabled in _FALSE_VALUES:
        enabled = False
    else:
        # Blank or unrecognized value: degrade to the safe default
        # (disabled) rather than guessing or raising.
        enabled = DEFAULT_ENABLED

    executable = os.environ.get(ENV_EXECUTABLE, "").strip() or DEFAULT_EXECUTABLE

    raw_args = os.environ.get(ENV_ARGS, "").strip()
    args = tuple(raw_args.split()) if raw_args else DEFAULT_ARGS

    raw_timeout = os.environ.get(ENV_TIMEOUT_SECONDS, "").strip()
    timeout_seconds = DEFAULT_TIMEOUT_SECONDS
    if raw_timeout:
        try:
            timeout_seconds = float(raw_timeout)
        except ValueError:
            timeout_seconds = DEFAULT_TIMEOUT_SECONDS

    return SpamAssassinConfig(
        enabled=enabled,
        executable=executable,
        args=args,
        timeout_seconds=timeout_seconds,
    )
