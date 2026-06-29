"""Source registry loader for ScamShield VN pipeline.

Loads and validates the source registry YAML configuration file
against the SourceRegistry Pydantic model.
"""

from pathlib import Path

import yaml
from loguru import logger

from src.models.source import SourceRegistry


def load_registry(config_path: str = "config/sources.yaml") -> SourceRegistry:
    """Load and validate the source registry from a YAML file.

    Args:
        config_path: Path to the sources YAML configuration file.
            Defaults to "config/sources.yaml".

    Returns:
        A validated SourceRegistry instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file contains malformed YAML.
        ValueError: If the YAML content fails Pydantic validation.
    """
    path = Path(config_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Source registry config not found: {path.resolve()}"
        )

    logger.info("Loading source registry from: {}", path)

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise yaml.YAMLError(
            f"Malformed YAML in source registry config '{path}': {e}"
        ) from e

    if raw is None:
        raise ValueError(f"Source registry config is empty: {path}")

    try:
        registry = SourceRegistry(**raw)
    except Exception as e:
        raise ValueError(
            f"Source registry validation failed for '{path}': {e}"
        ) from e

    logger.info(
        "Loaded {} sources ({} enabled)",
        len(registry.sources),
        sum(1 for s in registry.sources if s.enabled),
    )

    return registry
