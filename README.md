# VPN Intelligence AI

Multi-tenant B2B platform foundation for ISP network-flow intelligence.

## Current implementation

- FastAPI service with OpenAPI documentation at `/docs`.
- PostgreSQL support (SQLite only for local development).
- Tenant provisioning protected by a separate bootstrap admin secret.
- Tenant-specific API keys; only SHA-256 hashes are stored. Raw keys are returned once.
- Tenant identity is derived from the API key, never accepted from flow-ingestion requests.
- Tenant-scoped ingestion and aggregate analytics.
- Minimal browser dashboard at `/` (API key held in tab memory only).
- Transparent heuristic scoring with per-signal explanations.
- Docker and Render Blueprint configuration.

## Important product status

The scoring engine is a transparent heuristic baseline, **not a trained AI model**. No detection accuracy is claimed. Production-grade VPN intelligence requires licensed and regularly refreshed IP/proxy/Tor intelligence, lawfully sourced labeled ISP flow data, model validation, drift monitoring, and independent security review. These external data sources and credentials are not included.

## Privacy and responsible use

Only process telemetry the ISP is authorized to process (for example, NetFlow/IPFIX/sFlow-derived metadata). Do not ingest packet payloads, messages, credentials, subscriber identities, or direct customer identifiers. Keep subscriber-to-session mapping inside the ISP's systems. Scores are probabilistic indicators, not proof of VPN use, and must not be the sole basis for blocking, account action, or sanctions. Complete jurisdiction-specific privacy, telecom, and security review before production use.

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
export BOOTSTRAP_ADMIN_KEY='use-a-long-random-local-secret'
uvicorn app.main:app --reload
```

Health: `GET /health`; dashboard: `/`; API docs: `/docs`.

## Provision a tenant

Send `POST /v1/tenants` with `X-Admin-Key: $BOOTSTRAP_ADMIN_KEY`:

```json
{"tenant_id":"isp-demo","name":"Demo ISP","key_label":"primary"}
```

The response contains a tenant API key exactly once. Store it securely.

## Tenant API

Send `X-API-Key: <tenant-key>`:
- `GET /v1/me`
- `POST /v1/flows` with a `features` object
- `GET /v1/summary`

The tenant ID is resolved from the authenticated key. Clients cannot choose another tenant's ID in requests.

## Render

The Blueprint provisions a web service and a PostgreSQL database in Ohio. The current file selects Render's free plans for initial evaluation; free-tier availability, persistence, and limits are subject to Render's current terms. Review the plan and expected limitations in the Render Dashboard before applying. No Render resource has been created by this repository change.

## Remaining production gates

1. Run automated tests and dependency/security scans in CI.
2. Add database migrations, key rotation/revocation endpoints, RBAC, audit logs, rate limiting, and SSO/MFA.
3. Integrate licensed threat-intelligence providers and data freshness controls.
4. Build NetFlow/IPFIX/sFlow collectors with authenticated ingestion, buffering, backpressure, and retention policies.
5. Train and validate a model on representative, lawfully obtained labeled data; publish measured precision/recall and calibration.
6. Conduct penetration testing, privacy/legal review, disaster-recovery testing, and production monitoring.

This repository is a stronger deployable foundation, not a claim of audited or production-certified security.
