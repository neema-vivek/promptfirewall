"""Runtime configuration loaded from environment / .env."""
from __future__ import annotations

import os

try:
    from dotenv import load_dotenv

    load_dotenv()
except ModuleNotFoundError:
    # python-dotenv is optional; env vars still work without it.
    pass


class Settings:
    """Application settings sourced from environment variables."""

    def __init__(self) -> None:
        self.openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
        self.openai_base_url: str = os.getenv(
            # Neutral default; set OPENAI_BASE_URL in your .env for a real
            # OpenAI or Azure OpenAI endpoint.
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        )
        self.openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o")

        # Provider selection: honor LLM_PROVIDER if set; otherwise auto-pick
        # openai when an API key is present, else fall back to the mock.
        provider = os.getenv("LLM_PROVIDER", "").lower()
        if not provider:
            provider = "openai" if self.openai_api_key else "mock"
        self.llm_provider: str = provider

        self.block_threshold: int = int(os.getenv("FIREWALL_BLOCK_THRESHOLD", "70"))
        self.sanitize_threshold: int = int(
            os.getenv("FIREWALL_SANITIZE_THRESHOLD", "30")
        )

        # --- LLM classifier layer (optional semantic second opinion) ------
        # Mode controls WHEN the LLM is consulted:
        #   off  : never (rules only) — fully offline
        #   gray : only for inconclusive gray-zone inputs (cheapest coverage)
        #   all  : classify every input not already blocked (best coverage)
        # Default: 'gray' if an OpenAI provider is configured, else 'off'.
        _mode = os.getenv("FIREWALL_LLM_MODE", "").lower()
        # Back-compat: FIREWALL_LLM_CLASSIFIER=off/on still respected.
        _legacy = os.getenv("FIREWALL_LLM_CLASSIFIER", "").lower()
        if _legacy in ("0", "false", "off", "no"):
            _mode = "off"
        elif _legacy in ("1", "true", "on", "yes") and not _mode:
            _mode = "gray"
        if _mode not in ("off", "gray", "all"):
            _mode = "gray" if self.llm_provider == "openai" else "off"
        self.llm_mode: str = _mode
        self.llm_classifier_enabled: bool = _mode != "off"

        # Gray zone: rule risk in [low, high) is inconclusive -> ask the LLM.
        self.gray_zone_low: int = int(os.getenv("FIREWALL_GRAYZONE_LOW", "1"))
        self.gray_zone_high: int = int(os.getenv("FIREWALL_GRAYZONE_HIGH", "70"))


settings = Settings()
