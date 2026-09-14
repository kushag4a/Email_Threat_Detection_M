"""
Tests for background geolocation enrichment.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock
import pytest

from backend.app.services.store import ResultStore


class TestGeoEnrichmentIntegration:
    def test_enqueue_low_risk_gets_not_applicable(self):
        """LOW risk emails should get geo_status=not_applicable."""
        store = ResultStore()
        store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={
                "status": "analyzed",
                "risk": {"score": 10, "level": "LOW"},
                "m4": [],
                "geo_status": "pending",
            },
        )

        from backend.app.services import geo_enrichment
        # Temporarily point geo_enrichment at our test store
        original_store = geo_enrichment.STORE
        geo_enrichment.STORE = store
        try:
            geo_enrichment.enqueue_geo_enrichment(
                ip="1.2.3.4",
                session_id="s1",
                provider="google",
                account_id="a@b.com",
                message_id="m1",
                risk_level="LOW",
            )
        finally:
            geo_enrichment.STORE = original_store

        result = store.get_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1",
        )
        assert result["geo_status"] == "not_applicable"

    def test_enrichment_does_not_change_verdict(self):
        """Enrichment must never change risk score/level/reasons."""
        store = ResultStore()
        original_risk = {"score": 80, "level": "CRITICAL", "reasons": ["SPF failed"]}
        store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={
                "status": "analyzed",
                "risk": dict(original_risk),
                "m4": [],
                "geo_status": "pending",
            },
        )

        store.update_result_enrichment(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", enrichment={
                "geo": [{"ip": "1.2.3.4", "country": "RU"}],
                "geo_status": "completed",
            },
        )

        result = store.get_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1",
        )
        assert result["risk"] == original_risk
        assert result["geo_status"] == "completed"
        assert len(result["m4"]) == 1

    def test_enrichment_failure_preserves_verdict(self):
        store = ResultStore()
        original_risk = {"score": 25, "level": "LOW", "reasons": []}
        store.save_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", result={
                "status": "analyzed",
                "risk": dict(original_risk),
                "m4": [],
                "geo_status": "pending",
            },
        )

        store.update_result_enrichment(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1", enrichment={
                "geo": [],
                "geo_status": "failed",
            },
        )

        result = store.get_result(
            session_id="s1", provider="google", account_id="a@b.com",
            message_id="m1",
        )
        assert result["risk"] == original_risk
        assert result["geo_status"] == "failed"


class TestGeoStatusInAnalysis:
    def test_analysis_result_has_geo_status_pending(self, sample_email):
        from backend.app.services.analysis_service import analyze_email_safe
        result = analyze_email_safe(sample_email)
        assert result["geo_status"] == "pending"
