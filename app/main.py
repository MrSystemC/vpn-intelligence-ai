import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

APP_NAME = "VPN Intelligence AI"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/app.db")
BOOTSTRAP_ADMIN_KEY = os.getenv("BOOTSTRAP_ADMIN_KEY", "")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
    os.makedirs("data", exist_ok=True)
engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120), default="default")
    role: Mapped[str] = mapped_column(String(20), default="isp")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FlowEvent(Base):
    __tablename__ = "flow_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    score: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    features: Mapped[dict] = mapped_column(JSON)


app = FastAPI(
    title=APP_NAME,
    version="1.0.0",
    description="Multi-tenant network-flow intelligence API. Scores are probabilistic indicators, not proof."
)


def get_db():
    with SessionLocal() as session:
        yield session


Db = Annotated[Session, Depends(get_db)]


@app.on_event("startup")
def initialize_database():
    Base.metadata.create_all(bind=engine)


class Principal(BaseModel):
    tenant_id: str
    role: str
    api_key_id: str


def hash_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def authenticate(
    db: Db,
    x_api_key: Annotated[str | None, Header()] = None,
) -> Principal:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    digest = hash_key(x_api_key)
    record = db.scalar(select(ApiKey).where(ApiKey.key_hash == digest, ApiKey.revoked_at.is_(None)))
    if not record:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return Principal(tenant_id=record.tenant_id, role=record.role, api_key_id=record.id)


Auth = Annotated[Principal, Depends(authenticate)]


class TenantCreate(BaseModel):
    tenant_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,79}$")
    name: str = Field(min_length=2, max_length=160)
    key_label: str = Field(default="primary", min_length=1, max_length=120)


class FlowFeatures(BaseModel):
    tunnel_protocol: bool = False
    known_vpn_proxy_tor_destination: bool = False
    hosting_network: bool = False
    tls_fingerprint_match: bool = False
    port_pattern_match: bool = False
    long_high_volume_flow: bool = False


class FlowIn(BaseModel):
    features: FlowFeatures
    observed_at: datetime | None = None


class FlowOut(BaseModel):
    score: int
    verdict: str
    explanation: list[str]
    disclaimer: str = "Heuristic risk indicator only; not proof of VPN use."


def score_flow(features: FlowFeatures) -> FlowOut:
    rules = [
        ("tunnel_protocol", 55, "Tunnel protocol indicator"),
        ("known_vpn_proxy_tor_destination", 25, "Destination matches configured VPN/proxy/Tor intelligence"),
        ("hosting_network", 12, "Destination is in a hosting network"),
        ("tls_fingerprint_match", 12, "TLS fingerprint indicator"),
        ("port_pattern_match", 18, "Port pattern indicator"),
        ("long_high_volume_flow", 8, "Long-duration, high-volume flow"),
    ]
    score = 0
    reasons = []
    for field, points, label in rules:
        if getattr(features, field):
            score += points
            reasons.append(f"{label} (+{points})")
    score = min(score, 100)
    verdict = "likely_tunnel" if score >= 65 else "possible_tunnel" if score >= 35 else "no_strong_signal"
    return FlowOut(score=score, verdict=verdict, explanation=reasons)


def require_admin_key(value: str | None):
    if not BOOTSTRAP_ADMIN_KEY:
        raise HTTPException(status_code=503, detail="Tenant provisioning is disabled: configure BOOTSTRAP_ADMIN_KEY")
    if not value or not hmac.compare_digest(value, BOOTSTRAP_ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Admin key required")


@app.get("/health")
def health():
    return {"status": "ok", "service": APP_NAME, "version": "1.0.0"}


@app.get("/v1/me")
def me(auth: Auth):
    return {"tenant_id": auth.tenant_id, "role": auth.role, "api_key_id": auth.api_key_id}


@app.post("/v1/tenants", status_code=201)
def create_tenant(payload: TenantCreate, db: Db, x_admin_key: Annotated[str | None, Header()] = None):
    require_admin_key(x_admin_key)
    if db.get(Tenant, payload.tenant_id):
        raise HTTPException(status_code=409, detail="Tenant already exists")
    raw_key = "vpi_" + secrets.token_urlsafe(36)
    tenant = Tenant(id=payload.tenant_id, name=payload.name)
    key = ApiKey(
        id=secrets.token_hex(16),
        tenant_id=payload.tenant_id,
        key_hash=hash_key(raw_key),
        label=payload.key_label,
        role="isp",
    )
    db.add_all([tenant, key])
    db.commit()
    return {
        "tenant_id": tenant.id,
        "tenant_name": tenant.name,
        "api_key": raw_key,
        "warning": "Copy this key now. It is shown once and cannot be recovered."
    }


@app.post("/v1/flows", response_model=FlowOut, status_code=201)
def ingest_flow(payload: FlowIn, db: Db, auth: Auth):
    result = score_flow(payload.features)
    db.add(FlowEvent(
        tenant_id=auth.tenant_id,
        observed_at=payload.observed_at or datetime.now(timezone.utc),
        score=result.score,
        verdict=result.verdict,
        features=payload.features.model_dump(),
    ))
    db.commit()
    return result


@app.get("/v1/summary")
def summary(db: Db, auth: Auth):
    rows = db.execute(
        select(FlowEvent.verdict, func.count(FlowEvent.id), func.avg(FlowEvent.score))
        .where(FlowEvent.tenant_id == auth.tenant_id)
        .group_by(FlowEvent.verdict)
    ).all()
    total = db.scalar(select(func.count(FlowEvent.id)).where(FlowEvent.tenant_id == auth.tenant_id)) or 0
    return {
        "tenant_id": auth.tenant_id,
        "total_flows": total,
        "by_verdict": [
            {"verdict": verdict, "count": count, "average_score": round(float(avg_score or 0), 2)}
            for verdict, count, avg_score in rows
        ],
        "note": "Aggregated heuristic indicators; not proof of VPN use."
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard():
    return HTMLResponse("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Intelligence AI</title><style>
:root{color-scheme:dark;font:16px system-ui;background:#0b1020;color:#e8eefc}body{margin:0}
main{max-width:960px;margin:48px auto;padding:24px}.panel{background:#151e33;border:1px solid #293653;border-radius:16px;padding:24px;margin:16px 0}
h1{font-size:clamp(28px,5vw,42px);margin-bottom:8px}.muted{color:#9fb0cf}
input,button{font:inherit;border-radius:9px;padding:12px;border:1px solid #405273;background:#0d1528;color:#fff}
button{background:#4268d5;border:0;cursor:pointer;margin-left:8px}.stats{display:flex;gap:16px;flex-wrap:wrap}.stat{font-size:28px;font-weight:700}
pre{white-space:pre-wrap;overflow-wrap:anywhere;color:#b9d4ff}
</style></head><body><main><h1>VPN Intelligence AI</h1><p class="muted">ISP network-flow intelligence · Tenant-isolated analytics</p>
<section class="panel"><h2>Connect workspace</h2><p class="muted">Enter your tenant API key. It remains in this browser tab only.</p>
<input id="key" type="password" autocomplete="off" placeholder="vpi_..." style="width:min(100%,520px)"><button onclick="connect()">Connect</button><p id="status" class="muted"></p></section>
<section class="panel"><h2>Overview</h2><div class="stats"><div><div class="stat" id="total">—</div><div class="muted">Flows analyzed</div></div><div><div class="stat" id="tenant">—</div><div class="muted">Tenant</div></div></div><pre id="details">Connect an API key to load analytics.</pre></section>
<p class="muted">Risk scores are heuristic indicators, not proof of VPN use. Use only authorized NetFlow/IPFIX/sFlow metadata. Do not submit packet payloads or subscriber identities.</p></main>
<script>
let key='';async function api(path){const r=await fetch(path,{headers:{'X-API-Key':key}});if(!r.ok)throw Error((await r.json()).detail||r.statusText);return r.json()}
async function connect(){key=document.getElementById('key').value.trim();const s=document.getElementById('status');try{const [me,sum]=await Promise.all([api('/v1/me'),api('/v1/summary')]);document.getElementById('tenant').textContent=me.tenant_id;document.getElementById('total').textContent=sum.total_flows;document.getElementById('details').textContent=JSON.stringify(sum.by_verdict,null,2);s.textContent='Connected';}catch(e){key='';s.textContent='Connection failed: '+e.message}}
</script></body></html>""")
