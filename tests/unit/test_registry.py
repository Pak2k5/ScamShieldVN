"""Unit tests for source registry loading and validation."""

import pytest
import tempfile
from pathlib import Path

from src.config.registry import load_registry
from src.models.source import SourceEntry, SourceRegistry


class TestRegistryLoading:
    """Tests for registry file loading behavior."""

    def test_load_valid_config(self):
        """Default config/sources.yaml loads successfully."""
        registry = load_registry("config/sources.yaml")
        assert len(registry.sources) > 0
        assert all(isinstance(s, SourceEntry) for s in registry.sources)

    def test_file_not_found_raises_error(self, tmp_path):
        """Missing file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_registry(str(tmp_path / "nonexistent.yaml"))

    def test_malformed_yaml_raises_error(self, tmp_path):
        """Invalid YAML syntax raises error."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("sources: [{{invalid yaml")
        with pytest.raises(Exception):
            load_registry(str(bad_file))

    def test_empty_file_raises_error(self, tmp_path):
        """Empty YAML file raises ValueError."""
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("")
        with pytest.raises(ValueError):
            load_registry(str(empty_file))

    def test_missing_required_field_raises_error(self, tmp_path):
        """Source entry missing required field raises validation error."""
        bad_config = tmp_path / "bad_source.yaml"
        bad_config.write_text("""
sources:
  - source_id: "test"
    source_name: "Test"
    source_url: "https://example.com"
    # missing: source_type, credibility_level, license_note, access_method, redistribution_status
""")
        with pytest.raises(ValueError):
            load_registry(str(bad_config))

    def test_invalid_enum_value_raises_error(self, tmp_path):
        """Invalid enum value raises validation error."""
        bad_config = tmp_path / "bad_enum.yaml"
        bad_config.write_text("""
sources:
  - source_id: "test"
    source_name: "Test"
    source_url: "https://example.com"
    source_type: "invalid_type"
    credibility_level: "high"
    license_note: "test"
    access_method: "public_api"
    redistribution_status: "allowed"
""")
        with pytest.raises(ValueError):
            load_registry(str(bad_config))

    def test_duplicate_source_id_raises_error(self, tmp_path):
        """Duplicate source_id raises validation error."""
        dup_config = tmp_path / "dup.yaml"
        dup_config.write_text("""
sources:
  - source_id: "same_id"
    source_name: "Source 1"
    source_url: "https://example1.com"
    source_type: "threat_feed"
    credibility_level: "high"
    license_note: "test"
    access_method: "public_api"
    redistribution_status: "allowed"
  - source_id: "same_id"
    source_name: "Source 2"
    source_url: "https://example2.com"
    source_type: "threat_feed"
    credibility_level: "high"
    license_note: "test"
    access_method: "public_api"
    redistribution_status: "allowed"
""")
        with pytest.raises(ValueError, match="Duplicate source_id"):
            load_registry(str(dup_config))

    def test_invalid_url_format_raises_error(self, tmp_path):
        """Invalid URL format raises validation error."""
        bad_url = tmp_path / "bad_url.yaml"
        bad_url.write_text("""
sources:
  - source_id: "test"
    source_name: "Test"
    source_url: "not-a-url"
    source_type: "threat_feed"
    credibility_level: "high"
    license_note: "test"
    access_method: "public_api"
    redistribution_status: "allowed"
""")
        with pytest.raises(ValueError):
            load_registry(str(bad_url))

    def test_enabled_sources_count(self):
        """Verify enabled sources are correctly counted."""
        registry = load_registry("config/sources.yaml")
        enabled = [s for s in registry.sources if s.enabled]
        assert len(enabled) == len(registry.sources)  # All enabled in default config
