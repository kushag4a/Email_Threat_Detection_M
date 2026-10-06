"""
Deterministic guards for the plain HTML/CSS/JS frontend (no browser, no
mock state): they pin the structural fixes so they cannot silently regress.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")
CSS = (STATIC / "styles.css").read_text(encoding="utf-8")


def _strip_js_comments(src: str) -> str:
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", src)


JS_CODE = _strip_js_comments(JS)  # assertions about behaviour ignore explanatory comments


def _rule(selector: str) -> str:
    """Body of the first CSS rule whose selector list contains `selector` exactly."""
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", CSS):
        if selector in [s.strip() for s in m.group(1).split(",")]:
            return m.group(2)
    raise AssertionError(f"CSS rule not found: {selector}")


class TestAssets:
    def test_every_asset_url_in_html_exists_in_static_or_static_assets(self):
        for url in re.findall(r'(?:src|href)="/assets/([^"]+)"', HTML):
            assert (STATIC / url).is_file() or (STATIC / "assets" / url).is_file(), url

    def test_favicon_declared(self):
        assert 'rel="icon"' in HTML

    def test_default_avatar_exists(self):
        assert (STATIC / "assets" / "default-avatar.svg").is_file()


class TestAuthLanding:
    def test_welcome_has_skip_and_provider_buttons_use_existing_oauth_routes(self):
        assert 'id="welcomeSkipBtn"' in HTML and "Skip for now" in HTML
        assert "/auth/${providerId}/login" in JS
        assert "password" not in HTML.lower()  # no invented username/password auth

    def test_logout_and_signin_are_mutually_exclusive_in_markup_and_logic(self):
        assert re.search(r'id="logoutBtn"[^>]*\bhidden\b', HTML)
        assert re.search(r'id="signInBtn"[^>]*\bhidden\b', HTML)
        assert "logout.hidden = !connected" in JS and "signIn.hidden = connected" in JS

    def test_anonymous_mode_gates_exactly_inbox_dashboard_reports(self):
        assert 'new Set(["inbox", "dashboard", "reports"])' in JS
        for view in ("inbox", "dashboard", "reports"):
            assert re.search(rf'data-view="{view}" data-requires-mailbox="true"', HTML)
        for view in ("custom", "settings", "home", "user"):
            assert not re.search(rf'data-view="{view}"[^>]*data-requires-mailbox', HTML)

    def test_startup_waits_for_status_before_first_render(self):
        boot = JS[JS.index("async function bootstrap()"):]
        assert boot.index("await refreshConnectionStatus()") < boot.index('setActiveView("home")')
        assert re.search(r"\n  bootstrap\(\);\n\n\}\)\(\);\s*$", JS)
        assert "\n  refreshConnectionStatus();" not in JS  # the old un-awaited fire-and-forget call

    def test_theme_applied_before_first_paint(self):
        head = HTML[:HTML.index("</head>")]
        assert "vp_theme" in head and "data-theme" in head

    def test_no_sensitive_data_stored_by_auth_choice(self):
        assert "sessionStorage" in JS and "vp_auth_choice" in JS


class TestReviewFixes:
    def test_boot_veil_covers_nav_and_profile_not_just_main(self):
        assert re.search(r"html\.vp-booting \.nav-links", CSS) and re.search(r"html\.vp-booting \.user-profile", CSS)

    def test_pill_first_measurement_is_not_animated(self):
        assert 'style.transition = "none"' in JS

    def test_back_from_consent_screen_rebuilds_state(self):
        assert '"pageshow"' in JS and "e.persisted" in JS

    def test_logout_of_one_provider_reloads_remaining_mailbox(self):
        block = JS[JS.index("async function doLogout"):JS.index("const logoutBtn")]
        assert "await loadEmailPage(null, 0)" in block

    def test_detection_click_never_renders_a_partial_stand_in(self):
        block = JS[JS.index("async function openDetectionEmail"):JS.index("DASHBOARD: ANALYSIS REPORT CHART")]
        assert "/api/analysis/" in block and "Could not load the stored analysis" in block
        assert "risk: { level: det.risk_level" not in block

    def test_chart_has_a_readable_minimum_height(self):
        assert re.search(r"min-height:\s*190px", _rule(".chart-canvas-wrap"))


class TestEmailModalCss:
    def test_kv_value_no_longer_breaks_every_character(self):
        assert "break-all" not in _rule(".kv-row .v")
        assert "overflow-wrap: anywhere" in _rule(".kv-row .v")
        assert "min-width: 0" in _rule(".kv-row .v")

    def test_modal_body_never_scrolls_horizontally(self):
        assert "overflow-x: hidden" in _rule(".drawer-body")

    def test_scan_progress_is_theme_native(self):
        body = _rule(".scan-progress")
        assert "rgba(255,255,255,0.9)" not in body and "var(--surface)" in body

    def test_disposition_is_theme_native(self):
        body = _rule(".disposition-box")
        assert "#f4f4f4" not in body and "#888" not in body and "var(--surface)" in body
        assert "#f4f4f4" not in CSS

    def test_link_full_url_is_wrapped_and_constrained(self):
        body = _rule(".link-full")
        assert "overflow-wrap: anywhere" in body and "max-height" in body

    def test_hidden_attribute_wins_over_display_flex(self):
        assert re.search(r"\[hidden\]\s*\{\s*display:\s*none\s*!important", CSS)


class TestEmailModalJs:
    def test_urls_read_from_real_backend_field(self):
        assert "detected_urls" not in JS_CODE  # field never existed in the backend result
        assert "VPLinks" in JS and "linksSectionHtml" in JS and "Show links" in JS

    def test_raw_phishtank_url_rows_removed_from_threat_intel(self):
        assert "PhishTank: ${escapeHtml(r.url" not in JS


class TestDashboardJs:
    def test_chart_no_longer_uses_geo_trend(self):
        assert "threat-geo/trend" not in JS_CODE
        assert "/api/dashboard/risk-trend" in JS

    def test_chart_legend_is_the_four_classifications(self):
        for label in ('"Safe"', '"Medium Risk"', '"High Risk"', '"Critical"'):
            assert label in JS
        assert 'label: "Suspicious"' not in JS

    def test_period_buttons_refetch_real_data(self):
        block = JS[JS.index("// Time toggle buttons for chart"):JS.index("// Export report")]
        assert "state.chartPeriod = period" in block and "renderDashboardChart()" in block
        assert "Could re-fetch" not in block
        for period in ("daily", "weekly", "monthly"):
            assert f'data-time="{period}"' in HTML

    def test_exactly_one_period_active_initially_and_it_matches_state(self):
        active = re.findall(r'class="time-btn active" data-time="(\w+)"', HTML)
        assert active == ["daily"]
        assert 'chartPeriod: "daily"' in JS

    def test_all_mails_pill_selected_in_markup_and_painted_before_measurement(self):
        assert re.search(r'class="pill-btn active" data-index="0">All mails', HTML)
        assert ".pill-nav-container:not(.ready) .pill-btn.active" in CSS
        assert 'addEventListener("resize", updatePillIndicator)' in JS
        assert "offsetWidth" in JS and 'classList.add("ready")' in JS

    def test_threat_vectors_come_from_categories_endpoint_and_are_clickable(self):
        assert "/api/dashboard/threat-vectors" in JS
        assert "/api/threat-intel/summary" not in JS[JS.index("async function renderDashboard"):JS.index("DASHBOARD: THREAT VECTORS")]
        assert 'role="button" tabindex="0" data-kind=' in JS
        assert "openThreatDetail" in JS and "openDetectionEmail" in JS

    def test_local_heuristics_uses_the_same_clickable_row_as_other_vectors(self):
        # one renderer for both kinds -> identical behaviour by construction
        assert JS.count("function threatRowHtml(") == 1
        assert 'threatRowHtml("source"' in JS and 'threatRowHtml("vector"' in JS

    def test_sources_are_in_their_own_section(self):
        assert "Threat intelligence sources" in JS

    def test_no_mock_data_reintroduced(self):
        for marker in ("mockEmails", "MOCK_", "simulateOAuth", "fakeScan", "Math.random()"):
            assert marker not in JS


class TestNodeLinkTests:
    @pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
    def test_vp_links_js_unit_tests(self):
        proc = subprocess.run(
            ["node", str(ROOT / "tests" / "js" / "vp-links.test.js")],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    @pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
    def test_app_boot_smoke_tests(self):
        """Boots the real app.js against a DOM stub: welcome/anonymous/connected phases,
        single-flow OAuth return, real chart endpoints, clickable threat rows."""
        proc = subprocess.run(
            ["node", str(ROOT / "tests" / "js" / "boot.test.js")],
            capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
