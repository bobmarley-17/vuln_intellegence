"""Central configuration for the vulnerability intelligence pipeline.

All secrets (API keys) are read exclusively from environment variables /
a local `.env` file (never hardcoded, never committed). Non-secret tunables
can be overridden via `config.yaml` in the project root.
"""
from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
_SECRET_KEY_PATH = BASE_DIR / "cache" / ".secret_key"


def _load_or_create_secret_key() -> str:
    """Session-signing key for the dashboard's login cookies. Prefers an
    explicit SECRET_KEY env var; otherwise generates one on first run and
    persists it locally so sessions survive restarts. Never committed."""
    env_key = os.getenv("SECRET_KEY")
    if env_key:
        return env_key
    if _SECRET_KEY_PATH.exists():
        return _SECRET_KEY_PATH.read_text(encoding="utf-8").strip()
    _SECRET_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    new_key = secrets.token_hex(32)
    _SECRET_KEY_PATH.write_text(new_key, encoding="utf-8")
    return new_key


def _load_yaml_overrides() -> dict:
    path = BASE_DIR / "config.yaml"
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


_yaml_cfg = _load_yaml_overrides()


def _get(key: str, default):
    """YAML override > environment variable > default."""
    try:
        if key in _yaml_cfg:
            return _yaml_cfg[key]
        env_val = os.getenv(key.upper())
        if env_val is not None:
            return env_val
    except (KeyError, ValueError) as e:
        print(f"Error reading configuration for '{key}': {e}", file=sys.stderr)
        sys.exit(1)

    return default


@dataclass(frozen=True)
class Config:
    # --- API keys (secrets, env-only) ---
    nvd_api_key: str | None = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    github_token: str | None = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))

    # --- Dashboard session signing (secret, env-only or auto-generated) ---
    secret_key: str = field(default_factory=_load_or_create_secret_key)

    # --- Network behavior ---
    try:
        request_timeout: int = field(default_factory=lambda: int(_get("request_timeout", 15)))
        max_retries: int = field(default_factory=lambda: int(_get("max_retries", 3)))
        backoff_factor: float = field(default_factory=lambda: float(_get("backoff_factor", 1.5)))
        concurrency: int = field(default_factory=lambda: int(_get("concurrency", 5)))
    except (ValueError, TypeError) as e:
        print(f"Invalid numeric value in configuration: {e}", file=sys.stderr)
        sys.exit(1)

    user_agent: str = field(
        default_factory=lambda: _get(
            "user_agent",
            "VulnIntelBot/1.0 (+security research; contact: security-team@localhost)",
        )
    )

    # --- Folders ---
    output_folder: str = field(default_factory=lambda: _get("output_folder", str(BASE_DIR / "reports")))
    log_folder: str = field(default_factory=lambda: _get("log_folder", str(BASE_DIR / "logs")))
    cache_folder: str = field(default_factory=lambda: _get("cache_folder", str(BASE_DIR / "cache")))

    # --- Cache behavior ---
    try:
        cache_ttl_hours: int = field(default_factory=lambda: int(_get("cache_ttl_hours", 24)))
    except (ValueError, TypeError) as e:
        print(f"Invalid numeric value for 'cache_ttl_hours': {e}", file=sys.stderr)
        sys.exit(1)

    # --- Input ---
    urls_file: str = field(default_factory=lambda: _get("urls_file", str(BASE_DIR / "security_urls.txt")))

    # --- NVD rate limiting (per NVD published guidance) ---
    @property
    def nvd_rate_limit_delay(self) -> float:
        return 0.6 if self.nvd_api_key else 6.0

    @property
    def cache_db_path(self) -> str:
        return str(Path(self.cache_folder) / "vuln_intel.db")

    @property
    def log_file_path(self) -> str:
        return str(Path(self.log_folder) / "application.log")

    def ensure_folders(self) -> None:
        for folder in (self.output_folder, self.log_folder, self.cache_folder):
            Path(folder).mkdir(parents=True, exist_ok=True)


config = Config()
config.ensure_folders()
