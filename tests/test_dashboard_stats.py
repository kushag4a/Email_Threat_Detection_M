"""
Regression tests for the dashboard aggregations (services/dashboard_stats.py).

Pure functions over result dicts - no FastAPI, no network, no models.
Guards: the chart is built from REAL classified mail (not geolocation),
covers Safe/Medium/High/Critical, never fabricates periods or dates, and
threat categories are kept apart from threat-intelligence sources.
"""
from __future__ import annotations

import datetime as dt

import pytest

from backend.app.services.dashboard_stats import (
    build_intel_sources,
    build_risk_trend,
    build_threat_vectors,
    result_date,
)

TODAY = dt.date(2026, 10, 5)  # a Monday


def _res(mid, level, *, date="Sun, 04 Oct 2026 17:13:31 +0000", threat_types=(), score=50,
         analyzed_at="2026-10-05T09:00:00Z", m3=None, status="analyzed", sender="a@x.com"):
    return {
        "message_id": mid, "provider": "google", "account_id": "me@gmail.com",
        "status": status, "analyzed_at": analyzed_at,
        "email": {"sender": sender, "subject": f"s-{mid}", "date": date},
        "risk": {"level": level, "score": score},
        "threat_types": list(threat_types),
        "m3": m3 or {"phishtank": [], "spamhaus": [], "local_heuristics": []},
    }


class TestRiskTrend:
    def test_counts_all_four_classifications_not_just_suspicious(self):
        results = [_res("1", "LOW"), _res("2", "LOW"), _res("3", "MEDIUM"),
                   _res("4", "HIGH"), _res("5", "CRITICAL")]
        out = build_risk_trend(results, period="day", today=TODAY)
        t = out["totals"]
        assert (t["safe"], t["medium"], t["high"], t["critical"], t["total"]) == (2, 1, 1, 1, 5)
        day = next(b for b in out["buckets"] if b["period"] == "2026-10-04")
        assert day["safe"] == 2 and day["total"] == 5

    def test_zero_filled_window_and_no_fabricated_counts(self):
        out = build_risk_trend([_res("1", "LOW")], period="day", today=TODAY)
        assert len(out["buckets"]) == 14
        assert out["buckets"][-1]["period"] == TODAY.isoformat()
        assert sum(b["total"] for b in out["buckets"]) == 1
        assert [b["period"] for b in out["buckets"]] == sorted(b["period"] for b in out["buckets"])

    def test_empty_results_are_all_zero(self):
        for period in ("day", "week", "month"):
            out = build_risk_trend([], period=period, today=TODAY)
            assert out["totals"]["total"] == 0 and out["analyzed_total"] == 0

    def test_failed_and_unknown_results_are_ignored(self):
        results = [_res("1", "UNKNOWN"), _res("2", None), _res("3", "LOW", status="analysis_failed")]
        assert build_risk_trend(results, period="day", today=TODAY)["analyzed_total"] == 0

    def test_weekly_and_monthly_bucketing_differ(self):
        results = [_res("1", "LOW", date="Mon, 28 Sep 2026 10:00:00 +0000"),
                   _res("2", "HIGH", date="Sun, 04 Oct 2026 10:00:00 +0000"),
                   _res("3", "MEDIUM", date="Tue, 01 Sep 2026 10:00:00 +0000")]
        week = build_risk_trend(results, period="week", today=TODAY)
        assert week["period_type"] == "week" and len(week["buckets"]) == 12
        wk = next(b for b in week["buckets"] if b["period"] == "2026-09-28")
        assert wk["safe"] == 1 and wk["high"] == 1  # both fall in the week starting Mon 28 Sep
        month = build_risk_trend(results, period="month", today=TODAY)
        assert len(month["buckets"]) == 12
        sep = next(b for b in month["buckets"] if b["period"] == "2026-09")
        assert sep["medium"] == 1 and sep["safe"] == 1 and sep["total"] == 2
        assert next(b for b in month["buckets"] if b["period"] == "2026-10")["total"] == 1
        day = build_risk_trend(results, period="day", today=TODAY)
        assert day["totals"]["total"] == 2 and day["outside_window"] == 1  # 1 Sep is outside the 14-day window

    def test_undated_mail_is_counted_but_never_re_dated_to_today(self):
        r = _res("1", "LOW", date="garbage", analyzed_at="")
        out = build_risk_trend([r], period="day", today=TODAY)
        assert out["undated"] == 1 and out["totals"]["total"] == 0

    def test_falls_back_to_analyzed_at_when_email_date_unparseable(self):
        r = _res("1", "LOW", date="", analyzed_at="2026-10-03T12:00:00Z")
        out = build_risk_trend([r], period="day", today=TODAY)
        assert next(b for b in out["buckets"] if b["period"] == "2026-10-03")["safe"] == 1

    def test_timezone_is_normalised_to_utc(self):
        # 23:30 on 3 Oct at -0700 is 06:30 UTC on 4 Oct
        assert result_date(_res("1", "LOW", date="Sat, 03 Oct 2026 23:30:00 -0700")) == dt.date(2026, 10, 4)

    def test_invalid_period_rejected(self):
        with pytest.raises(ValueError):
            build_risk_trend([], period="year", today=TODAY)

    def test_month_window_crosses_year_boundary(self):
        out = build_risk_trend([], period="month", today=dt.date(2026, 2, 10))
        assert out["buckets"][0]["period"] == "2025-03" and out["buckets"][-1]["period"] == "2026-02"


class TestThreatVectors:
    def test_ranks_categories_by_distinct_emails_and_keeps_sources_separate(self):
        results = [
            _res("1", "MEDIUM", threat_types=["Authentication Spoofing"]),
            _res("2", "MEDIUM", threat_types=["Authentication Spoofing", "Credential Phishing"]),
            _res("3", "HIGH", threat_types=["Credential Phishing"]),
            _res("4", "MEDIUM", threat_types=["Authentication Spoofing"]),
        ]
        out = build_threat_vectors(results)
        names = [v["name"] for v in out["vectors"]]
        assert names == ["Authentication Spoofing", "Credential Phishing"]
        assert out["vectors"][0]["count"] == 3
        # Sources never appear as categories
        for forbidden in ("PhishTank", "Spamhaus", "Local heuristics"):
            assert not any(forbidden in n for n in names)
        assert [s["key"] for s in out["sources"]] == ["phishtank", "spamhaus", "local_heuristics"]

    def test_detections_carry_ids_needed_to_open_the_email(self):
        out = build_threat_vectors([_res("m-9", "HIGH", threat_types=["Malware Attachment"], score=88)])
        det = out["vectors"][0]["detections"][0]
        assert det["message_id"] == "m-9" and det["provider"] == "google"
        assert det["account_id"] == "me@gmail.com" and det["risk_score"] == 88

    def test_detections_sorted_highest_risk_first(self):
        results = [_res("lo", "MEDIUM", threat_types=["X"], score=40), _res("hi", "CRITICAL", threat_types=["X"], score=95)]
        dets = build_threat_vectors(results)["vectors"][0]["detections"]
        assert [d["message_id"] for d in dets] == ["hi", "lo"]

    def test_severity_breakdown(self):
        results = [_res("1", "MEDIUM", threat_types=["X"]), _res("2", "HIGH", threat_types=["X"])]
        sev = build_threat_vectors(results)["vectors"][0]["severity"]
        assert sev == {"safe": 0, "medium": 1, "high": 1, "critical": 0}

    def test_no_threats_gives_empty_vectors(self):
        out = build_threat_vectors([_res("1", "LOW")])
        assert out["vectors"] == [] and out["total_analyzed"] == 1


class TestIntelSources:
    M3 = {
        "phishtank": [{"url": "http://evil.example/login", "listed": True},
                      {"url": "http://ok.example/", "listed": False}],
        "spamhaus": [{"ip": "1.2.3.4", "listed": True, "network": "1.2.3.0/24"}],
        "local_heuristics": [{"indicator": "http://evil.example/login", "indicator_type": "url",
                              "flags": ["suspicious_action_keywords"], "local_score": 10},
                             {"indicator": "http://ok.example/", "indicator_type": "url", "flags": [], "local_score": 0}],
    }

    def test_counts_match_threat_intel_summary_rules(self):
        src = {s["key"]: s for s in build_intel_sources([_res("1", "HIGH", m3=self.M3), _res("2", "LOW")])}
        assert src["phishtank"]["matches"] == 1
        assert src["spamhaus"]["matches"] == 1
        assert src["local_heuristics"]["matches"] == 1
        assert src["local_heuristics"]["message_count"] == 1

    def test_local_heuristics_has_clickable_detections(self):
        src = {s["key"]: s for s in build_intel_sources([_res("1", "HIGH", m3=self.M3)])}
        det = src["local_heuristics"]["detections"][0]
        assert det["message_id"] == "1" and "suspicious_action_keywords" in det["evidence"]
