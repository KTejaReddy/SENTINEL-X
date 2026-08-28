"""Application configuration with startup validation.

All configuration flows from environment variables (with `.env` support).
Critical secrets are validated at startup — the app fails safely when they
are missing rather than running with insecure defaults in production.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_FILE = Path(__file__).resolve().parents[3] / ".env"

DEFAULT_JWT_SECRET = "dev-only-insecure-secret-change-me"
DEFAULT_ENCRYPTION_KEY = "dev-only-insecure-encryption-key-change-me-000000000000000"


def _load_env_file() -> dict[str, str]:
    """Minimal .env loader (no hard dependency on python-dotenv behaviour)."""
    data: dict[str, str] = {}
    path = ENV_FILE
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key:
                data[key] = value
    return data


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ENV_FILE), extra="ignore")

    # --- Core ---
    ENVIRONMENT: str = "development"  # development | test | production
    LOG_LEVEL: str = "INFO"
    APP_NAME: str = "SENTINEL X"
    API_VERSION: str = "0.1.0"
    BUILD: str = "local"
    GIT_REVISION: str = "dev"

    # --- Database ---
    DATABASE_URL: str = "sqlite:///./sentinelx.db"

    # --- Infra ---
    REDIS_URL: Optional[str] = None
    OPENSEARCH_URL: Optional[str] = None
    OBJECT_STORAGE_PATH: str = "./storage/evidence"

    # --- Security ---
    JWT_SECRET: str = DEFAULT_JWT_SECRET
    JWT_ACCESS_TTL_MINUTES: int = 30
    JWT_REFRESH_TTL_DAYS: int = 7
    ENCRYPTION_KEY: str = DEFAULT_ENCRYPTION_KEY
    WEBHOOK_SECRET: str = "dev-webhook-secret"

    # --- AI ---
    AI_PROVIDER: str = "local"  # local | openai_compatible
    AI_MODEL: str = "local-heuristic-v1"
    AI_API_BASE: Optional[str] = None
    AI_API_KEY: Optional[str] = None
    AI_STRONG_MODEL: str = "gpt-4o"
    AI_SMALL_MODEL: str = "gpt-4o-mini"
    AI_TOKEN_BUDGET_PER_DAY: int = 500_000
    AI_CACHE_ENABLED: bool = True

    # --- Security tools ---
    TOOL_PATHS: dict[str, str] = {}
    NMAP_PATH: str = "nmap"
    NUCLEI_PATH: str = "nuclei"
    ZAP_PATH: str = "zap.sh"
    SEMGREP_PATH: str = "semgrep"
    GITLEAKS_PATH: str = "gitleaks"
    TRIVY_PATH: str = "trivy"

    # --- Lab range ---
    LAB_CIDR: str = "10.10.10.0/24"
    LAB_NETWORK: str = "lab-network"

    # --- Live telemetry ingest (JSONL watcher) ---
    TELEMETRY_ENABLED: bool = True
    TELEMETRY_SOURCES: str = ""  # comma-separated JSONL paths; defaults to cyber-range/logs/*.jsonl
    TELEMETRY_ORG_SLUG: str = "acme"  # org that owns the lab assets

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:5173,http://127.0.0.1:5173"

    @field_validator("JWT_SECRET", "ENCRYPTION_KEY")
    @classmethod
    def _reject_insecure_in_prod(cls, v: str, info):
        if info.data.get("ENVIRONMENT") == "production":
            insecure = {DEFAULT_JWT_SECRET, DEFAULT_ENCRYPTION_KEY}
            if v in insecure:
                raise ValueError(f"{info.field_name} must be overridden in production")
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    def validate(self) -> None:
        """Fail fast if the configuration is unusable for the current environment."""
        missing: list[str] = []
        if not self.DATABASE_URL:
            missing.append("DATABASE_URL")
        if self.ENVIRONMENT in {"production", "staging"}:
            for name in ("JWT_SECRET", "ENCRYPTION_KEY", "WEBHOOK_SECRET"):
                value = getattr(self, name)
                if not value or "change-me" in value or "dev-" in value:
                    missing.append(name)
        if missing:
            raise RuntimeError(
                "FATAL: missing/insecure configuration: "
                + ", ".join(missing)
                + ". See .env.example."
            )


@lru_cache
def get_settings() -> Settings:
    # Load env file into os.environ first so pydantic-settings picks it up on some
    # setups where `env_file` resolution differs; keep both paths harmless.
    for k, v in _load_env_file().items():
        os.environ.setdefault(k, v)
    settings = Settings()
    settings.validate()
    return settings


settings = get_settings()
