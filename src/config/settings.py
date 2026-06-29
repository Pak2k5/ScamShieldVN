"""Pipeline configuration loader for ScamShield VN.

Loads pipeline settings from a YAML file with sensible defaults.
If the config file does not exist, defaults are used.
"""

from pathlib import Path

import yaml
from loguru import logger
from pydantic import BaseModel


class PipelineConfig(BaseModel):
    """Pipeline configuration with defaults.

    Attributes:
        output_dir: Base output directory for data tiers.
        rate_limit_rps: Default requests per second rate limit.
        max_retries: Maximum number of HTTP retry attempts.
        backoff_base: Exponential backoff base in seconds.
        backoff_max: Maximum backoff delay in seconds.
        timeout: HTTP request timeout in seconds.
        log_level: Logging level string.
        dataset_version: Semantic version for the dataset.
    """

    output_dir: str = "./data"
    rate_limit_rps: float = 1.0
    max_retries: int = 3
    backoff_base: int = 2
    backoff_max: int = 30
    timeout: int = 30
    log_level: str = "INFO"
    dataset_version: str = "0.1.0"


def load_settings(config_path: str = "config/pipeline.yaml") -> PipelineConfig:
    """Load pipeline settings from a YAML file.

    If the file does not exist, default values are used.
    File values are merged with defaults (file values take precedence).

    Args:
        config_path: Path to the pipeline YAML configuration file.
            Defaults to "config/pipeline.yaml".

    Returns:
        A validated PipelineConfig instance.

    Raises:
        yaml.YAMLError: If the file contains malformed YAML.
        ValueError: If the YAML content fails Pydantic validation.
    """
    path = Path(config_path)

    if not path.exists():
        logger.info(
            "Pipeline config not found at '{}', using defaults.", path
        )
        return PipelineConfig()

    logger.info("Loading pipeline settings from: {}", path)

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise yaml.YAMLError(
            f"Malformed YAML in pipeline config '{path}': {e}"
        ) from e

    if raw is None:
        logger.info("Pipeline config file is empty, using defaults.")
        return PipelineConfig()

    try:
        config = PipelineConfig(**raw)
    except Exception as e:
        raise ValueError(
            f"Pipeline config validation failed for '{path}': {e}"
        ) from e

    logger.info("Pipeline settings loaded (version={})", config.dataset_version)

    return config
