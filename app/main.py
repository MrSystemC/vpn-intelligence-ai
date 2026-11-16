import os, sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APP_NAME = os.getenv('APP_NAME', 'VPN Intelligence AI')
API_KEY = os.getenv('API_KEY', 'dev-only-change-me')
DB_PATH = os.getenv('DATABASE_PATH', './data/app.db')
os.makedirs(os.path.dirname(DB_PATH) or '.', exist_ok=True)
app = FastAPI(title=APP_NAME, version='0.1.0', description='Privacy-preserving network-flow intelligence MVP')

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

with db() as con:
    con.execute('''CREATE TABLE IF NOT EXISTS flow_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL,
        observed_at TEXT NOT NULL, score INTEGER NOT NULL, verdict TEXT NOT NULL,
        features TEXT NOT NULL)''')

def authorize(x_api_key: Optional[str]):
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail='Invalid API key')

class FlowFeatures(BaseModel):
    tunnel_protocol: bool = False
    known_vpn_proxy_tor_destination: bool = False
    hosting_network: bool = False
    tls_fingerprint_match: bool = False
    port_pattern_match: bool = False
    long_high_volume_flow: bool = False

class FlowIn(BaseModel):
    tenant_id: str = Field(min_length=2, max_length=80)
    features: FlowFeatures
    observed_at: Optional[datetime] = None

class FlowOut(BaseModel):
    score: int
    verdict: str
    explanation: list[str]
    disclaimer: str = 'Heuristic risk indicator only; not proof of VPN use.'

def score_flow(f: FlowFeatures):
    rules = [
        ('tunnel_protocol', 55, 'Tunnel protocol indicator'),
        ('known_vpn_proxy_tor_destination', 25, 'Destination matches configured VPN/proxy/Tor intelligence'),
        ('hosting_network', 12, 'Destination is in a hosting network'),
        ('tls_fingerprint_match', 12, 'TLS fingerprint indicator'),
        ('port_pattern_match', 18, 'Port pattern indicator'),
        ('long_high_volume_flow', 8, 'Long-duration, high-volume flow'),
    ]
    score, reasons = 0, []
    for field, points, label in rules:
        if getattr(f, field):
            score += points
            reasons.append(f'{label} (+{points})')
    score = min(score, 100)
    verdict = 'likely_tunnel' if score >= 65 else 'possible_tunnel' if score >= 35 else 'no_strong_signal'
    return FlowOut(score=score, verdict=verdict, explanation=reasons)

@app.get('/health')
def health():
    return {'status': 'ok', 'service': APP_NAME, 'version': '0.1.0'}

@app.get('/v1/me')
def me(x_api_key: Optional[str] = Header(default=None)):
    authorize(x_api_key)
    return {'tenant_id': 'tenant-from-api-key', 'role': 'isp_api', 'scopes': ['flows:write', 'analytics:read']}

@app.post('/v1/flows', response_model=FlowOut)
def ingest_flow(payload: FlowIn, x_api_key: Optional[str] = Header(default=None)):
    authorize(x_api_key)
    result = score_flow(payload.features)
    observed = (payload.observed_at or datetime.now(timezone.utc)).isoformat()
    # Store normalized features only. Never submit subscriber IDs, raw IPs, or payload data.
    with db() as con:
        con.execute('INSERT INTO flow_events (tenant_id, observed_at, score, verdict, features) VALUES (?, ?, ?, ?, ?)',
                    (payload.tenant_id, observed, result.score, result.verdict, payload.features.model_dump_json()))
    return result

@app.get('/v1/summary')
def summary(tenant_id: str, x_api_key: Optional[str] = Header(default=None)):
    authorize(x_api_key)
    with db() as con:
        rows = con.execute('SELECT verdict, COUNT(*) AS count, AVG(score) AS avg_score FROM flow_events WHERE tenant_id=? GROUP BY verdict', (tenant_id,)).fetchall()
        total = con.execute('SELECT COUNT(*) FROM flow_events WHERE tenant_id=?', (tenant_id,)).fetchone()[0]
    return {'tenant_id': tenant_id, 'total_flows': total, 'by_verdict': [dict(r) for r in rows], 'note': 'Aggregated heuristic indicators; not proof of VPN use.'}
