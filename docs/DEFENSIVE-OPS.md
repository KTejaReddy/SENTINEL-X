# SENTINEL X — Defensive operations

## Pipeline

```
SENSOR → INGEST → NORMALIZE → ENRICH → CORRELATE → DETECT → INCIDENT
```

Events use a common schema (`event_type`, `severity`, `source`, `asset_id`,
`user_id`, `event_data`). Ingest adapters normalize Suricata/Zeek/Wazuh-style
telemetry; the lab range ships a lightweight sensor that emits the same shape.

## Detection

Detection is layered — signatures + rules + thresholds + correlation — never
an LLM alone:

- `detection_rules` rows with source (`sigma`/`suricata`/`custom`),
  severity, MITRE mapping, status (`DRAFT`/`DEPLOYED`/…), version, and
  test cases.
- The detection engine evaluates ingested events against deployed rules,
  fires matches, and opens or updates incidents.
- Rule lifecycle includes versioning (each update bumps the version and
  keeps history).

## Incident lifecycle

States: `OPEN → INVESTIGATING → CONTAINED → ERADICATION → RECOVERY → RESOLVED → CLOSED`

Every incident has a forensic timeline (each entry links to evidence), an
optional AI investigation (`POST /api/incidents/{id}/analyze`) that separates
**fact / inference / hypothesis / recommendation**, and correlation to
findings (`POST /api/incidents/{id}/link-finding`) so an analyst can pivot
vulnerability → attack activity → identity → asset → network connection →
destination.

## Threat hunting

`POST /api/hunts` accepts natural-language goals and translates them into a
validated, structured query plan (never an unrestricted AI-generated
database query). Supported hunts include suspicious authentication patterns,
new outbound destinations, unusual process activity, unexpected privilege
changes, and rare network communication.

## Response playbooks

Playbooks contain actions; each action has a risk level and an approval gate
(see SECURITY.md §5). Example playbooks seeded: Suspicious Account, Endpoint
Isolation, Session Revocation, Credential Rotation, Network Block, Increased
Monitoring, Evidence Collection.

```
LOW      → auto (create ticket, enable enhanced monitoring)
HIGH     → require approval (disable test account)
CRITICAL → require explicit approval (production isolation)
```

Actions execute through adapters (`services/response_adapters.py`); the AI
can only *recommend* actions, never bypass approval.

## Purple team & detection engineering loop

```
RED EVENT → NO DETECTION → PURPLE GAP → RULE PROPOSAL → TEST → DEPLOY
→ REPLAY → DETECTION VERIFIED → stored as a regression test
```

The purple module tracks a coverage matrix over attack stages
(Recon, Initial Access, Execution, Privilege, Lateral Movement, Collection,
Exfiltration, Impact). Each gap shows evidence, missing telemetry,
recommended detection, and retest status.

## Security regressions

Every verified fix / detection can become a reusable test case
(`SEC-REG-####`). The retest service runs it; a failure on a later build
raises `SECURITY REGRESSION DETECTED` and links back to the original
finding + remediation + evidence.
