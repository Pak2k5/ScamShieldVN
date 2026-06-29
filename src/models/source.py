"""
Source Registry Pydantic models for the ScamShield VN pipeline.

Defines the SourceEntry model representing a single data source configuration,
and the SourceRegistry model that holds a validated collection of sources
with uniqueness constraints on source_id.
"""

from pydantic import BaseModel, field_validator, model_validator

from src.models.enums import (
    AccessMethod,
    CredibilityLevel,
    RedistributionStatus,
    SourceType,
)


class SourceEntry(BaseModel):
    """A single data source entry in the source registry.

    Represents all metadata and configuration needed to identify, access,
    and govern a data source used by the pipeline.

    Attributes:
        source_id: Unique identifier for the source.
        source_name: Human-readable name of the source.
        source_url: URL pointing to the source's data endpoint or homepage.
        source_type: Classification of the source origin type.
        credibility_level: Credibility rating assigned to this source.
        license_note: Brief description of the source's licensing terms.
        access_method: Method used to retrieve data from this source.
        redistribution_status: Whether redistributing data from this source is allowed.
        rate_limit_rps: Maximum requests per second allowed. Defaults to 1.0.
        requires_api_key: Whether an API key is needed for access. Defaults to False.
        enabled: Whether this source is currently active. Defaults to True.
    """

    source_id: str
    source_name: str
    source_url: str
    source_type: SourceType
    credibility_level: CredibilityLevel
    license_note: str
    access_method: AccessMethod
    redistribution_status: RedistributionStatus
    rate_limit_rps: float = 1.0
    requires_api_key: bool = False
    enabled: bool = True

    @field_validator("source_url")
    @classmethod
    def validate_url_format(cls, v: str) -> str:
        """Validate that source_url is a properly formatted URL."""
        if not v.startswith(("http://", "https://")):
            raise ValueError(
                f"source_url must be a valid URL starting with http:// or https://, got: {v}"
            )
        return v


class SourceRegistry(BaseModel):
    """Registry containing all configured data sources for the pipeline.

    Validates that all source entries have unique source_id values to prevent
    configuration conflicts.

    Attributes:
        sources: List of all registered source entries.
    """

    sources: list[SourceEntry]

    @model_validator(mode="after")
    def check_unique_source_ids(self) -> "SourceRegistry":
        """Ensure all source_id values are unique across entries."""
        seen: set[str] = set()
        for entry in self.sources:
            if entry.source_id in seen:
                raise ValueError(
                    f"Duplicate source_id found: '{entry.source_id}'. "
                    f"Each source must have a unique source_id."
                )
            seen.add(entry.source_id)
        return self
