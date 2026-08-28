# SENTINEL X — Tool integrations

## The ToolAdapter contract

Every external security tool plugs in through a single interface
(`integrations/base.py`). The UI and job system never see raw CLI output —
adapters normalize results into typed entities.

```python
class ToolAdapter(ABC):
    name: str
    category: str          # discovery | vulnerability_scan | exploitation | destructive | ingest
    availability: str      # available | not_installed | degraded

    def validate_configuration(self) -> list[str]     # missing settings
    def validate_scope(self, target: str, scope) -> ScopeDecision
    def health_check(self) -> ToolHealth                # binary present?
    def build_request(self, target, params) -> ToolRequest   # constrained CLI
    def execute(self, request, timeout) -> ToolOutput
    def parse_output(self, raw) -> list[dict]           # structured rows
    def normalize_result(self, rows, org, asset) -> list[Entity]
```

Key rule: **no arbitrary command strings** are accepted from clients or the
AI. `build_request` is the only place a command line is assembled, from
validated parameters.

## Adapter catalog

| Adapter | Purpose | Availability handling |
|---|---|---|
| `nmap` | host/port discovery, service fingerprinting → `Service` entities | `nmap` missing → `NOT INSTALLED`, job fails with clear error |
| `nuclei` | template-based vulnerability scanning → `Finding` rows | binary check at health-check |
| `scanners` | semgrep / gitleaks / trivy / grype source & container scanning → findings mapped to repos→builds→apps→assets | per-tool binary check |
| `ingest` | SIEM event ingestion (suricata eve, wazuh alerts, zeek logs, generic JSON) → normalized `Event` rows | missing file path → degraded, not fatal |
| `lab-range` | controlled exercise generator against the isolated lab (10.10.10.0/24) — produces real jobs/events/findings labeled `CONTROLLED LAB` | always available in dev |

A single API surface exposes the registry: `GET /api/tools` returns each
tool with `availability`, and `POST /api/tools/health-check` runs live
`health_check()` probes.

## Integrating a new tool

1. Add `integrations/adapters/<tool>.py` subclassing `ToolAdapter`.
2. Return structured entities: assets/services for recon tools, findings for
   scanners, events for sensors.
3. Register in `integrations/__init__.py` so `GET /api/tools` picks it up.
4. Add a `TOOL_PATHS`-style config key and document it in `.env.example`.
5. Test the degraded path (binary absent) — the platform must report
   `NOT INSTALLED`, never crash.

## Real-world integration points

- **Offensive:** engagements authorize tools; the scope engine constrains
  targets; jobs execute via adapters; findings flow to correlation + evidence.
- **Defensive:** ingest adapters feed the normalized event pipeline
  (`events` table), which the detection engine evaluates.
- **Response:** response actions (session revocation, isolation, credential
  rotation…) run through adapters in `services/response_adapters.py`, gated
  by the human-approval model.
