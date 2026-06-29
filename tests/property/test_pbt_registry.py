"""Property-based tests for source registry validation.

Property 1: Source Registry Validation Completeness
Property 2: Source ID Uniqueness Enforcement
"""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from src.models.source import SourceEntry, SourceRegistry
from src.models.enums import SourceType, CredibilityLevel, AccessMethod, RedistributionStatus


# ---- Strategies ----

VALID_SOURCE_TYPES = [e.value for e in SourceType]
VALID_CREDIBILITY = [e.value for e in CredibilityLevel]
VALID_ACCESS = [e.value for e in AccessMethod]
VALID_REDISTRIBUTION = [e.value for e in RedistributionStatus]


def valid_source_entry_dict(source_id: str = "test_source") -> st.SearchStrategy:
    """Strategy generating valid source entry dictionaries."""
    return st.fixed_dictionaries({
        "source_id": st.just(source_id) if source_id != "random" else st.text(min_size=1, max_size=50),
        "source_name": st.text(min_size=1, max_size=100),
        "source_url": st.sampled_from(["https://example.com", "http://test.org", "https://api.example.io"]),
        "source_type": st.sampled_from(VALID_SOURCE_TYPES),
        "credibility_level": st.sampled_from(VALID_CREDIBILITY),
        "license_note": st.text(min_size=1, max_size=200),
        "access_method": st.sampled_from(VALID_ACCESS),
        "redistribution_status": st.sampled_from(VALID_REDISTRIBUTION),
    })


# ---- Property 1: Validation Completeness ----
# Feature: scamshield-vn-pipeline, Property 1: Source Registry Validation Completeness

class TestProperty1ValidationCompleteness:
    """For any source entry, validation passes iff all required fields present with valid enums."""

    @given(data=valid_source_entry_dict("test_prop1"))
    @settings(max_examples=100)
    def test_valid_entry_passes_validation(self, data):
        """Valid source entry dictionaries should always pass validation."""
        entry = SourceEntry(**data)
        assert entry.source_id == "test_prop1"
        assert entry.source_type in SourceType
        assert entry.credibility_level in CredibilityLevel
        assert entry.access_method in AccessMethod
        assert entry.redistribution_status in RedistributionStatus

    @given(
        field_to_remove=st.sampled_from([
            "source_id", "source_name", "source_url", "source_type",
            "credibility_level", "license_note", "access_method", "redistribution_status"
        ])
    )
    @settings(max_examples=100)
    def test_missing_required_field_fails_validation(self, field_to_remove):
        """Removing any required field should cause validation to fail."""
        valid_data = {
            "source_id": "test",
            "source_name": "Test Source",
            "source_url": "https://example.com",
            "source_type": "threat_feed",
            "credibility_level": "high",
            "license_note": "Test license",
            "access_method": "public_api",
            "redistribution_status": "allowed",
        }
        # Remove the field
        del valid_data[field_to_remove]
        
        with pytest.raises(Exception):  # ValidationError from Pydantic
            SourceEntry(**valid_data)

    @given(
        invalid_value=st.text(min_size=1, max_size=30).filter(
            lambda x: x not in VALID_SOURCE_TYPES
        )
    )
    @settings(max_examples=50)
    def test_invalid_source_type_fails(self, invalid_value):
        """Invalid source_type values should fail validation."""
        data = {
            "source_id": "test",
            "source_name": "Test",
            "source_url": "https://example.com",
            "source_type": invalid_value,
            "credibility_level": "high",
            "license_note": "test",
            "access_method": "public_api",
            "redistribution_status": "allowed",
        }
        with pytest.raises(Exception):
            SourceEntry(**data)

    @given(
        invalid_value=st.text(min_size=1, max_size=30).filter(
            lambda x: x not in VALID_CREDIBILITY
        )
    )
    @settings(max_examples=50)
    def test_invalid_credibility_level_fails(self, invalid_value):
        """Invalid credibility_level values should fail validation."""
        data = {
            "source_id": "test",
            "source_name": "Test",
            "source_url": "https://example.com",
            "source_type": "threat_feed",
            "credibility_level": invalid_value,
            "license_note": "test",
            "access_method": "public_api",
            "redistribution_status": "allowed",
        }
        with pytest.raises(Exception):
            SourceEntry(**data)


# ---- Property 2: Source ID Uniqueness Enforcement ----
# Feature: scamshield-vn-pipeline, Property 2: Source ID Uniqueness Enforcement

class TestProperty2UniqueSourceIds:
    """For any list with duplicate source_ids, validation must reject."""

    @given(
        source_id=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=("L", "N")))
    )
    @settings(max_examples=100)
    def test_duplicate_source_ids_rejected(self, source_id):
        """Registry with duplicate source_ids must raise ValueError."""
        assume(len(source_id) > 0)
        
        entry_data = {
            "source_id": source_id,
            "source_name": "Test",
            "source_url": "https://example.com",
            "source_type": "threat_feed",
            "credibility_level": "high",
            "license_note": "test",
            "access_method": "public_api",
            "redistribution_status": "allowed",
        }
        
        entry1 = SourceEntry(**entry_data)
        entry2 = SourceEntry(**entry_data)
        
        with pytest.raises(ValueError, match="Duplicate source_id"):
            SourceRegistry(sources=[entry1, entry2])

    @given(
        ids=st.lists(
            st.text(min_size=1, max_size=30, alphabet=st.characters(whitelist_categories=("L", "N"))),
            min_size=2,
            max_size=10,
            unique=True,
        )
    )
    @settings(max_examples=100)
    def test_unique_source_ids_accepted(self, ids):
        """Registry with all unique source_ids must pass validation."""
        entries = []
        for sid in ids:
            entries.append(SourceEntry(
                source_id=sid,
                source_name=f"Source {sid}",
                source_url="https://example.com",
                source_type="threat_feed",
                credibility_level="high",
                license_note="test",
                access_method="public_api",
                redistribution_status="allowed",
            ))
        
        registry = SourceRegistry(sources=entries)
        assert len(registry.sources) == len(ids)
