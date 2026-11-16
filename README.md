# VPN Intelligence AI

Privacy-preserving, multi-tenant B2B SaaS starter for ISP network-flow intelligence.

## MVP features
- FastAPI health, tenant identity, flow-ingestion and summary endpoints.
- Transparent rule-based VPN/proxy/Tor risk indicators.
- Stores normalized feature flags and aggregate results only.
- Docker and Render deployment configuration.

## Privacy and responsible use
Use only network telemetry the ISP is authorized to process (for example, NetFlow/IPFIX/sFlow-derived metadata). Do not collect packet payloads, message contents, passwords, or subscriber identity. Keep subscriber-to-network-session mapping inside the ISP's own systems. Scores are probabilistic indicators, not proof of VPN use, and must not be the sole basis for blocking, account action, or sanctions. Complete privacy, telecom, security, and local legal review before production use.

## Quick start
```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set a strong API_KEY in .env
uvicorn app.main:app --reload
```

Health: `GET /health`

Authenticated endpoints use the `X-API-Key` header:
- `GET /v1/me`
- `POST /v1/flows`
- `GET /v1/summary?tenant_id=demo-isp`

## Detection baseline
This is a transparent heuristic baseline, not a trained AI model. Weights: tunnel protocol 55; known VPN/proxy/Tor destination 25; hosting network 12; TLS fingerprint 12; port pattern 18; long/high-volume flow 8. Scores are capped at 100. Thresholds: 65+ likely_tunnel; 35–64 possible_tunnel; below 35 no_strong_signal. Calibrate against labeled, lawfully obtained data before operational use.

## Production roadmap
PostgreSQL and migrations; tenant-specific API keys and rotation; RBAC, audit logs and rate limits; licensed intelligence feeds; collector integrations; scalable analytics storage; monitoring, SSO/MFA, retention controls, security testing, model validation and legal review. The development fallback key is not suitable for production; always configure a strong secret.
