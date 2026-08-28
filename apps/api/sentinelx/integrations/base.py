"""Tool Adapter Framework.

Every external security tool is integrated through a ToolAdapter. The
application never executes arbitrary CLI commands — only the commands
constructed by an approved adapter for an in-scope target.

An adapter is responsible for:
  validate_configuration()  -> configuration present?
  validate_scope(...)       -> target is inside the engagement scope
  build_request(...)        -> structured request (never raw user strings)
  execute(...)              -> run the tool (CLI or API)
  parse_output(...)         -> raw output -> structured entities
  normalize_result(...)     -> structured entities -> platform entities
  health_check()            -> installed/version
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ..config import settings

logger = logging.getLogger(__name__)


@dataclass
class NormalizedAsset:
    name: str
    asset_type: str = "HOST"
    ip_address: Optional[str] = None
    dns_name: Optional[str] = None
    technology: Optional[str] = None
    os: Optional[str] = None
    exposure: str = "INTERNAL"
    source: str = "tool"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedService:
    asset_ip: str
    name: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    version: Optional[str] = None
    technology: Optional[str] = None
    state: str = "open"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedFinding:
    title: str
    severity: str = "MEDIUM"
    description: str = ""
    cve: Optional[str] = None
    cwe: Optional[str] = None
    category: Optional[str] = None
    endpoint: Optional[str] = None
    cvss: Optional[float] = None
    cvss_vector: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 0.5
    evidence: dict[str, Any] = field(default_factory=dict)
    asset_ip: Optional[str] = None
    asset_name: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedEvent:
    event_type: str
    severity: str = "low"
    timestamp: Optional[datetime] = None
    asset_ip: Optional[str] = None
    user: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedEvidence:
    kind: str = "TOOL_OUTPUT"
    data: dict[str, Any] = field(default_factory=dict)
    tool: Optional[str] = None


class AdapterError(Exception):
    """Raised when an adapter cannot execute safely or successfully."""


class ToolNotInstalled(AdapterError):
    """Tool binary/endpoint unavailable — graceful degraded mode."""


def run_cli(cmd: list[str], timeout: int = 300, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Run a tool subprocess WITHOUT a shell. Never pass user strings into argv
    construction — adapters must build commands from validated structured params."""
    logger.info("executing tool: %s", " ".join(cmd))
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        check=False,
        shell=False,
    )


class ToolAdapter:
    name: str = "base"
    category: str = "scanner"
    description: str = ""

    # --- Configuration ---
    def validate_configuration(self) -> tuple[bool, str]:
        return True, "ok"

    def health_check(self) -> dict[str, Any]:
        installed = self._binary_available()
        version = None
        if installed:
            try:
                proc = run_cli([self._binary_path(), "--version"], timeout=15)
                version = proc.stdout.strip().splitlines()[0][:64] if proc.stdout else None
            except Exception:
                version = None
        return {
            "name": self.name,
            "installed": installed,
            "version": version,
            "health": "OK" if installed else "NOT_INSTALLED",
        }

    def _binary_available(self) -> bool:
        return shutil.which(self._binary_path()) is not None

    def _binary_path(self) -> str:
        return getattr(settings, f"{self.name.upper().replace('-', '_')}_PATH", self.name)

    # --- Scope ---
    def validate_scope(self, db, engagement, target_ref: str, asset=None) -> None:
        from ..services.scope_engine import evaluate_scope

        decision = evaluate_scope(db, engagement, target_ref, asset=asset)
        if not decision.allowed:
            raise AdapterError(f"Target out of scope: {decision.reason}")

    # --- Execution protocol ---
    def build_request(self, target: str, params: dict[str, Any]) -> dict[str, Any]:
        return {"target": target, "params": params}

    def execute(self, request: dict[str, Any]) -> Any:
        raise NotImplementedError

    def parse_output(self, raw: Any) -> list[Any]:
        raise NotImplementedError

    def normalize_result(self, parsed: list[Any]) -> dict[str, Any]:
        raise NotImplementedError

    def run(self, db, engagement, target_ref: str, params: dict[str, Any] | None = None, asset=None) -> dict[str, Any]:
        """Full adapter pipeline with scope enforcement. This is the only entry
        point called by the job worker."""
        params = params or {}
        self.validate_scope(db, engagement, target_ref, asset=asset)
        request = self.build_request(target_ref, params)
        raw = self.execute(request)
        parsed = self.parse_output(raw)
        return self.normalize_result(parsed)


class ToolRegistry:
    def __init__(self) -> None:
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> ToolAdapter:
        if name not in self._adapters:
            raise AdapterError(f"Unknown tool adapter: {name}")
        return self._adapters[name]

    def all(self) -> list[ToolAdapter]:
        return list(self._adapters.values())

    def health_snapshot(self) -> list[dict[str, Any]]:
        return [a.health_check() for a in self._adapters.values()]


_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
        from .adapters import register_all

        register_all(_registry)
    return _registry


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
