"""Environment variable loader for ScamShield VN pipeline.

Loads API keys and sensitive configuration from .env file
and environment variables using python-dotenv.
"""

import os
from typing import Optional

from dotenv import load_dotenv
from loguru import logger
from pydantic import BaseModel


class EnvConfig(BaseModel):
    """Environment-based configuration for API keys.

    All fields are optional since API keys are only required
    for sources that use them.

    Attributes:
        google_safe_browsing_key: Google Safe Browsing API key.
        virustotal_key: VirusTotal API key.
        phishtank_key: PhishTank API key.
    """

    google_safe_browsing_key: Optional[str] = None
    virustotal_key: Optional[str] = None
    phishtank_key: Optional[str] = None


def _get_env_or_none(var_name: str) -> Optional[str]:
    """Read an environment variable, treating empty/whitespace as None.

    Logs a warning if the variable is set but contains only whitespace.

    Args:
        var_name: The environment variable name to read.

    Returns:
        The stripped value, or None if unset or blank.
    """
    value = os.environ.get(var_name)

    if value is None:
        return None

    stripped = value.strip()

    if not stripped:
        logger.warning(
            "Environment variable '{}' is set but empty/whitespace-only, treating as None.",
            var_name,
        )
        return None

    return stripped


def load_env() -> EnvConfig:
    """Load environment configuration from .env file and environment variables.

    Environment variables take precedence over .env file values.
    Empty or whitespace-only values are treated as None.

    Returns:
        An EnvConfig instance with available API keys.
    """
    load_dotenv()

    config = EnvConfig(
        google_safe_browsing_key=_get_env_or_none(
            "SCAMSHIELD_GOOGLE_SAFE_BROWSING_KEY"
        ),
        virustotal_key=_get_env_or_none("SCAMSHIELD_VIRUSTOTAL_KEY"),
        phishtank_key=_get_env_or_none("SCAMSHIELD_PHISHTANK_KEY"),
    )

    # Log which keys are available (without revealing values)
    available_keys = []
    if config.google_safe_browsing_key:
        available_keys.append("google_safe_browsing")
    if config.virustotal_key:
        available_keys.append("virustotal")
    if config.phishtank_key:
        available_keys.append("phishtank")

    if available_keys:
        logger.info("API keys loaded: {}", ", ".join(available_keys))
    else:
        logger.info("No API keys configured.")

    return config
