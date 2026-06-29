"""Unit tests for src/models/enums.py."""

import json

import pytest

from src.models.enums import (
    AccessMethod,
    BenignMessageType,
    ConflictStatus,
    CredibilityLevel,
    EvidenceLevel,
    Label,
    RecordType,
    RedistributionStatus,
    RequiresAction,
    SourceType,
    SummaryMethod,
    VerificationMethod,
)


class TestSourceType:
    """Tests for SourceType enum."""

    def test_has_all_values(self) -> None:
        expected = {
            "official_government",
            "threat_feed",
            "news_media",
            "community_report",
            "benign_reference",
            "international_organization",
        }
        assert {e.value for e in SourceType} == expected

    def test_is_str_subclass(self) -> None:
        assert isinstance(SourceType.THREAT_FEED, str)

    def test_json_serializable(self) -> None:
        result = json.dumps({"source_type": SourceType.THREAT_FEED})
        assert '"threat_feed"' in result


class TestCredibilityLevel:
    """Tests for CredibilityLevel enum."""

    def test_has_all_values(self) -> None:
        expected = {"official", "high", "medium", "low", "unknown"}
        assert {e.value for e in CredibilityLevel} == expected

    def test_is_str_subclass(self) -> None:
        assert isinstance(CredibilityLevel.HIGH, str)


class TestAccessMethod:
    """Tests for AccessMethod enum."""

    def test_has_all_values(self) -> None:
        expected = {
            "public_api",
            "public_csv",
            "public_rss",
            "public_webpage",
            "manual_curated",
            "api_key_required",
        }
        assert {e.value for e in AccessMethod} == expected


class TestRedistributionStatus:
    """Tests for RedistributionStatus enum."""

    def test_has_all_values(self) -> None:
        expected = {"allowed", "prohibited", "unknown"}
        assert {e.value for e in RedistributionStatus} == expected


class TestEvidenceLevel:
    """Tests for EvidenceLevel enum."""

    def test_has_all_values(self) -> None:
        expected = {"A", "B", "C", "D", "E"}
        assert {e.value for e in EvidenceLevel} == expected

    def test_ordering_by_value(self) -> None:
        levels = sorted(EvidenceLevel, key=lambda e: e.value)
        assert [e.value for e in levels] == ["A", "B", "C", "D", "E"]


class TestRecordType:
    """Tests for RecordType enum."""

    def test_has_all_values(self) -> None:
        expected = {"url", "case", "domain", "message"}
        assert {e.value for e in RecordType} == expected


class TestLabel:
    """Tests for Label enum."""

    def test_has_all_values(self) -> None:
        expected = {
            "phishing_url",
            "malware_url",
            "scam_case",
            "scam_pattern",
            "suspicious",
            "community_reported_unverified",
            "benign_url",
            "benign_message",
            "unknown",
        }
        assert {e.value for e in Label} == expected

    def test_count(self) -> None:
        assert len(Label) == 9


class TestConflictStatus:
    """Tests for ConflictStatus enum."""

    def test_has_all_values(self) -> None:
        expected = {"needs_review", "resolved"}
        assert {e.value for e in ConflictStatus} == expected


class TestBenignMessageType:
    """Tests for BenignMessageType enum."""

    def test_has_all_values(self) -> None:
        expected = {
            "otp_warning",
            "delivery_notification",
            "bank_education",
            "promotion",
            "system_notification",
            "other",
        }
        assert {e.value for e in BenignMessageType} == expected


class TestSummaryMethod:
    """Tests for SummaryMethod enum."""

    def test_has_all_values(self) -> None:
        expected = {"manual", "extractive", "abstractive", "rule_based"}
        assert {e.value for e in SummaryMethod} == expected


class TestRequiresAction:
    """Tests for RequiresAction enum."""

    def test_has_all_values(self) -> None:
        expected = {"approve", "reject", "edit", "escalate"}
        assert {e.value for e in RequiresAction} == expected


class TestVerificationMethod:
    """Tests for VerificationMethod enum."""

    def test_has_all_values(self) -> None:
        expected = {"manual_curated", "tranco_ranking", "official_registry"}
        assert {e.value for e in VerificationMethod} == expected


class TestAllEnumsJsonSerializable:
    """Verify all enums serialize to JSON as plain strings."""

    @pytest.mark.parametrize(
        "enum_class",
        [
            SourceType,
            CredibilityLevel,
            AccessMethod,
            RedistributionStatus,
            EvidenceLevel,
            RecordType,
            Label,
            ConflictStatus,
            BenignMessageType,
            SummaryMethod,
            RequiresAction,
            VerificationMethod,
        ],
    )
    def test_json_round_trip(self, enum_class: type) -> None:
        for member in enum_class:
            serialized = json.dumps(member)
            assert json.loads(serialized) == member.value
