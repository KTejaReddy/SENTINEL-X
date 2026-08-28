# SENTINEL X — AI agents

## Specialist agents, not one giant model

| Agent | Domain | Tool access |
|---|---|---|
| Orchestrator | drives engagements/workflows | job creation (scope-gated) |
| Recon / Asset | discovery, fingerprinting | scan jobs |
| Web Security | DAST, crawl, routes | web scan jobs |
| API Security | BOLA/BFLA, schema | api scan jobs |
| Cloud Security | IAM, exposure | cloud scan jobs |
| Vulnerability | triage, correlation | finding services |
| Attack Path | path computation | graph services |
| Evidence | capture, hash, attach | evidence vault |
| Report | generate reports | reporting service |
| SOC / Detection | event triage, rule proposals | detection services |
| Investigation | incident analysis | incident services |
| Response | playbook recommendations | response actions (approval-gated) |
| Purple | control validation | purple exercises |

Agents are represented in `agents` + `agent_runs` tables with identity,
permissions, and audit history. The current implementation ships the
deterministic evidence-driven engine (`AI_PROVIDER=local`); a remote model can
be enabled with `AI_PROVIDER=openai_compatible` + `AI_API_BASE`/`AI_API_KEY`
— its output passes through the same Pydantic validation gates.

## Typed output contracts

Every AI response that affects the application is validated against a strict
Pydantic schema before any side effect. Examples:

**Triage** (`POST /api/ai/triage` → `AITriageResponse`):

```json
{
  "classification": "validated_candidate",
  "severity": "HIGH",
  "confidence": 0.93,
  "asset_criticality": "CRITICAL",
  "business_risk": "HIGH",
  "likely_attack_path": true,
  "evidence_required": [],
  "recommended_validation": "",
  "remediation": ""
}
```

**Action request** (`POST /api/ai/action` → `AIActionResponse`):

```json
{
  "action": "create_validation_job",
  "target_id": "asset_123",
  "objective": "authorization_boundary_check",
  "confidence": 0.91,
  "requires_approval": true
}
```

**Incident analysis** — the AI explicitly separates fact, inference,
hypothesis, and recommendation; nothing is presented as confirmed unless
supported by stored events/evidence.

**Copilot** — answers from structured retrieval (assets, findings, attack
paths, incidents, detection rules, evidence). Responses cite internal
references (`F-1042`, `INC-882`, `EV-337`). When evidence is missing the
response says **INSUFFICIENT EVIDENCE** instead of inventing data.

## Hallucination control rules

1. Malformed AI output → rejected (422), never executed.
2. Unsupported action types → rejected before any job is created.
3. Out-of-scope targets → rejected by the scope engine, same as a human.
4. Missing evidence → `INSUFFICIENT EVIDENCE`, no fabricated conclusions.
5. The AI cannot run arbitrary shell commands; it only issues structured
   requests that pass scope → policy → adapter.

## Copilot example queries (all answered from real data)

- “What are our most dangerous vulnerabilities?”
- “Which external asset changed today?”
- “Which vulnerabilities participate in a path to the database?”
- “Would our SOC detect this attack path?” (purple coverage)
- “Which remediation gives the biggest risk reduction?”
- “What changed after yesterday's deployment?”

## Controlled security exercise

`POST /api/ai/exercise` (or the Command Center button) runs a deterministic,
scope-approved demo workflow through the real pipeline — engagement → recon
job → finding → validation → attack path → detection → incident → response →
remediation → retest → verified. Artifacts are labeled `CONTROLLED LAB` and
persisted as real rows you can open in the UI.
