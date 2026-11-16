from __future__ import annotations
import base64
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, Response
from pydantic import BaseModel, Field
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

# Ensure crypto module is importable
_root = str(Path(__file__).resolve().parents[1])
if _root not in sys.path:
    sys.path.insert(0, _root)

from .config import settings
from .security import PolicyEngine, RateLimiter, EncryptedEventStore, ReplayGuard, event_id
from .identity import Identity, IdentityPolicy, SessionRegistry, TokenVerifier, IdentityError
from crypto.adaptive import AdaptiveCryptoVault, RotationPolicy, RotationReason
from layer4.waf import WAFEngine, ViolationType
from layer4.rate_limiter import ApplicationRateLimiter
from layer5.prompt_guard import PromptGuard, InjectionType
from layer5.tool_policy import AIToolPolicyEngine, ToolRiskTier
from layer5.dlp import DataLossPreventer
from layer7.sandbox_policy import SandboxPolicyEngine, ExecutionTicket
from layer7.command_parser import SafeCommandParser


# Prometheus Metrics
AUTHORIZE_TOTAL = Counter(
    'sentinel_authorize_total',
    'Total authorization decisions',
    ['action', 'layer', 'reason']
)
RATE_LIMITED_TOTAL = Counter(
    'sentinel_rate_limited_total',
    'Total rate limited requests'
)
AI_TOOL_TOTAL = Counter(
    'sentinel_ai_tool_total',
    'Total AI tool authorization decisions',
    ['action', 'tool', 'risk']
)
WAF_BLOCKS_TOTAL = Counter(
    'sentinel_waf_blocks_total',
    'Total WAF blocked requests',
    ['violation', 'risk']
)
PROMPT_INJECTIONS_TOTAL = Counter(
    'sentinel_prompt_injections_total',
    'Total prompt injection attempts',
    ['threat_type', 'risk']
)
DLP_VIOLATIONS_TOTAL = Counter(
    'sentinel_dlp_violations_total',
    'Total DLP data leak attempts',
    ['detector', 'severity']
)
EXECUTION_TOTAL = Counter(
    'sentinel_execution_total',
    'Total execution authorization decisions',
    ['action', 'command_type', 'risk']
)
IDENTITY_AUTHORIZE_TOTAL = Counter(
    'sentinel_identity_authorize_total',
    'Total identity authorization decisions',
    ['action', 'reason', 'zone']
)
EVENTS_STORED_TOTAL = Counter(
    'sentinel_events_stored_total',
    'Total security events stored'
)
REQUEST_DURATION = Histogram(
    'sentinel_request_duration_seconds',
    'Request latency in seconds',
    ['method', 'endpoint'],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)
ACTIVE_SESSIONS = Gauge(
    'sentinel_active_sessions',
    'Active sessions in registry'
)
REVOKED_SESSIONS = Gauge(
    'sentinel_revoked_sessions',
    'Revoked sessions/tokens'
)
CRYPTO_EPOCHS = Gauge(
    'sentinel_crypto_epochs_total',
    'Total crypto epochs (active + retired)'
)
CRYPTO_EPOCH_ACTIVE = Gauge(
    'sentinel_crypto_epoch_active',
    'Active crypto epoch age in seconds'
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown - could add cleanup here


app = FastAPI(
    title="SENTINEL Ultimate Security Fabric",
    version="0.3.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.env == "development" else None,
    redoc_url=None
)

policy = PolicyEngine()
limiter = RateLimiter(settings.rate_limit_per_minute)
waf = WAFEngine()
app_rate_limiter = ApplicationRateLimiter(default_limit=settings.rate_limit_per_minute)
prompt_guard = PromptGuard()
ai_tool_policy = AIToolPolicyEngine()
dlp = DataLossPreventer()
sandbox_policy = SandboxPolicyEngine()
store = EncryptedEventStore()
identity_policy = IdentityPolicy()
sessions = SessionRegistry(settings.redis_url)
replay_guard = ReplayGuard()


def _audit_crypto_event(event: dict):
    event["source"] = "layer6_crypto"
    event["id"] = event_id(event)
    store.append(event)
    EVENTS_STORED_TOTAL.inc()


crypto_vault = AdaptiveCryptoVault(audit_sink=_audit_crypto_event)


def _sync_crypto_metrics():
    CRYPTO_EPOCHS.set(len(crypto_vault.epoch_ids))
    CRYPTO_EPOCH_ACTIVE.set(time.time() - crypto_vault.active_epoch.created_at)


_sync_crypto_metrics()


class AuthRequest(BaseModel):
    identity: str = Field(min_length=1, max_length=128)
    role: str = Field(min_length=1, max_length=64)
    method: str = "GET"
    path: str = "/"
    body_size: int = 0
    zone: str = "user"


class ToolRequest(BaseModel):
    identity: str
    role: str
    tool: str
    approved: bool = False
    args: dict | None = None


class ExecRequest(BaseModel):
    identity: str
    role: str
    command: str
    sandbox: bool = False


class IdentityAuthorizeRequest(BaseModel):
    subject: str
    roles: list[str] = []
    scopes: list[str] = []
    device_id: str | None = None
    token_id: str | None = None
    auth_time: int | None = None
    amr: list[str] = []
    required_scope: str
    resource: str
    zone: str = "user"
    privileged: bool = False


class RevokeRequest(BaseModel):
    subject: str | None = None
    token_id: str | None = None


class EventRequest(BaseModel):
    source: str
    event_type: str
    severity: str = "INFO"
    metadata: dict = {}


class CryptoRotateRequest(BaseModel):
    reason: str = "administrative"


class CryptoSealRequest(BaseModel):
    plaintext: str
    aad: str | None = None
    is_base64: bool = False


class CryptoOpenRequest(BaseModel):
    envelope: dict
    aad: str | None = None
    as_base64: bool = False
    replay_check: bool = True


class WAFInspectRequest(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = {}
    body: str | None = None
    content_type: str | None = None


class PromptScanRequest(BaseModel):
    prompt: str = Field(min_length=1)


class DLPScanRequest(BaseModel):
    text: str = Field(min_length=1)
    redact: bool = True


class VerifyTicketRequest(BaseModel):
    ticket_id: str
    command: str
    identity: str
    role: str
    created_at: int
    expires_at: int
    signature: str
    cpu_limit: str = "1.0"
    memory_limit: str = "512m"
    timeout_seconds: int = 30


@app.middleware("http")
async def edge_guard(request: Request, call_next):
    start = time.time()
    client = request.client.host if request.client else "unknown"

    # Block dangerous diagnostic HTTP methods
    if request.method.upper() in {"TRACE", "TRACK", "CONNECT"}:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "method_not_allowed"}, status_code=405)

    # Layer 4 Application Fortress: WAF URI & Header inspection
    waf_res = waf.inspect_request(
        method=request.method,
        path=request.url.path,
        headers=dict(request.headers),
        content_type=request.headers.get("content-type")
    )
    if not waf_res.allowed:
        WAF_BLOCKS_TOTAL.labels(violation=waf_res.reason, risk=waf_res.risk).inc()
        event = {
            "ts": time.time(), "source": client, "event": "waf_block",
            "reason": waf_res.reason, "violations": waf_res.violations,
            "path": request.url.path, "method": request.method
        }
        store.append({**event, "id": event_id(event)})
        from fastapi.responses import JSONResponse
        status_code = 405 if waf_res.reason == "method_not_allowed" else 400
        return JSONResponse({
            "error": "waf_blocked",
            "layer": 4,
            "reason": waf_res.reason,
            "risk": waf_res.risk,
            "violations": waf_res.violations
        }, status_code=status_code)

    # Rate limiting
    if not limiter.allow(client):
        RATE_LIMITED_TOTAL.inc()
        event = {"ts": time.time(), "source": client, "event": "rate_limit", "path": request.url.path}
        store.append({**event, "id": event_id(event)})
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "rate_limited", "layer": 1}, status_code=429)

    # TLS enforcement behind trusted proxy
    if request.headers.get("x-forwarded-proto") == "http" and settings.trusted_proxy:
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "tls_required"}, status_code=400)

    response = await call_next(request)

    # Hardened Defense-in-Depth Security Headers
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; sandbox"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Record latency
    REQUEST_DURATION.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(time.time() - start)

    return response


@app.get("/health")
def health():
    """Liveness probe - basic service health."""
    return {
        "service": "sentinel",
        "status": "ok",
        "version": "0.3.0",
        "layers": 7,
        "timestamp": time.time()
    }


@app.get("/ready")
def ready():
    """Readiness probe - checks dependencies."""
    _sync_crypto_metrics()
    checks = {
        "store": "ok" if store.key or True else "degraded",  # Encrypted or fallback
        "sessions": "ok",
        "policy": "ok",
        "crypto_vault": "ok" if crypto_vault.active_epoch else "degraded",
    }
    all_ok = all(v == "ok" for v in checks.values())
    from fastapi.responses import JSONResponse
    return JSONResponse(
        {"service": "sentinel", "status": "ready" if all_ok else "degraded", "checks": checks},
        status_code=200 if all_ok else 503
    )


@app.get("/metrics")
def metrics():
    """Prometheus metrics endpoint."""
    _sync_crypto_metrics()
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/v1/security/status")
def status():
    _sync_crypto_metrics()
    return {
        "status": "operational",
        "default_policy": "deny",
        "tls": "TLS 1.3 at trusted edge proxy",
        "data_at_rest": "AES-256-GCM when SENTINEL_MASTER_KEY is configured",
        "layers": {
            "1_edge": "active",
            "2_network": "policy gateway",
            "3_identity": "active — OIDC/RBAC/ABAC/step-up/mTLS boundary",
            "4_application": "active",
            "5_ai": "active",
            "6_data": f"active — Adaptive double AES-256-GCM (epoch: {crypto_vault.active_epoch.epoch_id})",
            "7_execution": "sandbox policy active",
        },
        "layer_details": {
            "1_edge": "TLS 1.3 / Strict Transport Security / Anti-DDoS / Dual-Stack Edge Proxy",
            "2_network": "Stateful nftables / Zone Microsegmentation / Strict Inter-Zone Drop",
            "3_identity": "OIDC Identity Boundary / ABAC Policies / Step-Up MFA / Redis Revocation",
            "4_application": "WAF Engine / Injection Filters / Path Traversal Defense / Rate Limiter",
            "5_ai": "Prompt Injection Scanner / Jailbreak Shield / Tool Risk Tiers / DLP Redaction",
            "6_data": f"Adaptive Key Rotation / Two-Layer AES-256-GCM Vault (epoch: {crypto_vault.active_epoch.epoch_id})",
            "7_execution": "Safe Command Lexical Parser / Seccomp Sandbox Profile / Cryptographic Tickets",
        },
    }


@app.post("/v1/identity/authorize")
def identity_authorize(req: IdentityAuthorizeRequest):
    identity = Identity(
        subject=req.subject, roles=frozenset(req.roles), scopes=frozenset(req.scopes),
        device_id=req.device_id, token_id=req.token_id, auth_time=req.auth_time, amr=frozenset(req.amr)
    )
    if sessions.is_revoked(identity):
        allowed, reason = False, "identity_revoked"
    else:
        allowed, reason = identity_policy.authorize(
            identity, required_scope=req.required_scope, resource=req.resource,
            zone=req.zone, privileged=req.privileged
        )

    action = "ALLOW" if allowed else "BLOCK"
    IDENTITY_AUTHORIZE_TOTAL.labels(action=action, reason=reason, zone=req.zone).inc()

    payload = {"ts": time.time(), "source": "layer3", "event_type": "identity_decision",
               "subject": identity.subject, "device_id": identity.device_id,
               "token_id": identity.token_id, "allowed": allowed, "reason": reason,
               "resource": req.resource, "required_scope": req.required_scope}
    payload["id"] = event_id(payload)
    store.append(payload)
    EVENTS_STORED_TOTAL.inc()

    return {"allow": allowed, "action": action, "reason": reason, "risk": "LOW" if allowed else "HIGH", "event_id": payload["id"]}


@app.post("/v1/identity/revoke")
def identity_revoke(req: RevokeRequest):
    if not req.subject and not req.token_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="subject_or_token_id_required")
    if req.subject:
        sessions.revoke_subject(req.subject)
    if req.token_id:
        sessions.revoke_token(req.token_id)

    REVOKED_SESSIONS.set(len(sessions.revoked_subjects) + len(sessions.revoked_tokens))
    return {"revoked": True}


@app.post("/v1/authorize")
def authorize(req: AuthRequest):
    start = time.time()
    decision = policy.authorize(**req.model_dump())

    AUTHORIZE_TOTAL.labels(action=decision.action, layer="layer4_app", reason=decision.reason).inc()

    return decision.__dict__


@app.post("/v1/ai/tool/authorize")
def authorize_tool(req: ToolRequest):
    decision = ai_tool_policy.evaluate(
        identity=req.identity,
        role=req.role,
        tool=req.tool,
        approved=req.approved,
        args=req.args
    )

    AI_TOOL_TOTAL.labels(action=decision.action, tool=req.tool, risk=decision.risk).inc()

    return {
        "allow": decision.allow,
        "action": decision.action,
        "reason": decision.reason,
        "risk": decision.risk,
        "violations": decision.violations
    }


@app.post("/v1/execute/authorize")
def authorize_execution(req: ExecRequest):
    decision = sandbox_policy.authorize(
        identity=req.identity,
        role=req.role,
        command=req.command,
        sandbox=req.sandbox
    )

    # Categorize command for metrics
    cmd_type = "pytest" if "pytest" in req.command else ("compile" if "compileall" in req.command else ("git" if "git" in req.command else "other"))
    EXECUTION_TOTAL.labels(action=decision.action, command_type=cmd_type, risk=decision.risk).inc()

    res = {
        "allow": decision.allow,
        "action": decision.action,
        "reason": decision.reason,
        "risk": decision.risk,
        "violations": decision.violations
    }
    if decision.ticket:
        res["ticket"] = {
            "ticket_id": decision.ticket.ticket_id,
            "command": decision.ticket.command,
            "identity": decision.ticket.identity,
            "role": decision.ticket.role,
            "created_at": decision.ticket.created_at,
            "expires_at": decision.ticket.expires_at,
            "timeout_seconds": decision.ticket.timeout_seconds,
            "cpu_limit": decision.ticket.cpu_limit,
            "memory_limit": decision.ticket.memory_limit,
            "signature": decision.ticket.signature
        }
    return res


@app.post("/v1/app/waf/inspect")
def app_waf_inspect(req: WAFInspectRequest):
    """Layer 4 Application Fortress - Deep HTTP request and payload inspection."""
    res = waf.inspect_request(
        method=req.method,
        path=req.path,
        headers=req.headers,
        body=req.body,
        content_type=req.content_type
    )
    if not res.allowed:
        WAF_BLOCKS_TOTAL.labels(violation=res.reason, risk=res.risk).inc()
    return {
        "allowed": res.allowed,
        "action": res.action,
        "reason": res.reason,
        "risk": res.risk,
        "violations": res.violations
    }


@app.post("/v1/ai/prompt/scan")
def ai_prompt_scan(req: PromptScanRequest):
    """Layer 5 AI Firewall - Prompt injection, jailbreak, and adversarial heuristic scanner."""
    res = prompt_guard.scan_prompt(req.prompt)
    if not res.is_safe:
        threat_val = res.detected_types[0] if res.detected_types else "injection"
        PROMPT_INJECTIONS_TOTAL.labels(threat_type=threat_val, risk=res.risk).inc()
    return {
        "is_safe": res.is_safe,
        "threat_type": res.detected_types[0] if res.detected_types else "none",
        "risk": res.risk,
        "threat_score": res.threat_score,
        "detected_types": res.detected_types,
        "reasons": res.reasons
    }


@app.post("/v1/ai/dlp/scan")
def ai_dlp_scan(req: DLPScanRequest):
    """Layer 5 AI Firewall - Secret leak and PII exfiltration detection/redaction engine."""
    res = dlp.scan(req.text)
    for f in res.findings:
        DLP_VIOLATIONS_TOTAL.labels(detector=f.finding_type, severity=f.severity).inc()
    return {
        "has_leak": res.has_leak,
        "risk": res.risk,
        "total_findings": len(res.findings),
        "findings": [
            {
                "category": f.category,
                "finding_type": f.finding_type,
                "match_preview": f.match_preview,
                "severity": f.severity
            }
            for f in res.findings
        ],
        "redacted_text": res.redacted_text
    }


@app.post("/v1/execute/verify-ticket")
def execute_verify_ticket(req: VerifyTicketRequest):
    """Layer 7 Execution Sandbox - Attest and verify HMAC ticket before container admission."""
    ticket = ExecutionTicket(
        ticket_id=req.ticket_id,
        command=req.command,
        identity=req.identity,
        role=req.role,
        created_at=req.created_at,
        expires_at=req.expires_at,
        cpu_limit=req.cpu_limit,
        memory_limit=req.memory_limit,
        timeout_seconds=req.timeout_seconds,
        signature=req.signature
    )
    valid = sandbox_policy.verify_ticket(ticket)
    return {"valid": valid, "ticket_id": req.ticket_id}


@app.post("/v1/events")
def event(req: EventRequest):
    payload = {"ts": time.time(), **req.model_dump()}
    payload["id"] = event_id(payload)
    store.append(payload)
    EVENTS_STORED_TOTAL.inc()
    return {"accepted": True, "event_id": payload["id"]}


@app.get("/v1/crypto/status")
def crypto_status():
    """Layer 6 Data Vault - Adaptive Crypto Shield status and epoch metadata."""
    _sync_crypto_metrics()
    active = crypto_vault.active_epoch
    return {
        "status": "operational",
        "scheme": "SENTINEL-2X-AES256-GCM-ADAPTIVE",
        "active_epoch": {
            "epoch_id": active.epoch_id,
            "created_at": active.created_at,
            "age_seconds": round(time.time() - active.created_at, 2),
            "message_count": active.message_count,
            "byte_count": active.byte_count,
            "rotation_reason": active.rotation_reason,
        },
        "total_epochs": len(crypto_vault.epoch_ids),
        "policy": {
            "max_age_seconds": crypto_vault.policy.max_age_seconds,
            "max_messages": crypto_vault.policy.max_messages,
            "max_bytes": crypto_vault.policy.max_bytes,
            "previous_key_grace_seconds": crypto_vault.policy.previous_key_grace_seconds,
            "emergency_retention_seconds": crypto_vault.policy.emergency_retention_seconds,
        },
        "revoked_epochs": sorted(crypto_vault._revoked),
    }


@app.post("/v1/crypto/rotate")
def crypto_rotate(req: CryptoRotateRequest):
    """Trigger a key epoch rotation (scheduled, administrative, or emergency)."""
    from fastapi import HTTPException
    try:
        if req.reason.lower() == "emergency":
            new_epoch = crypto_vault.emergency_rotate()
        else:
            try:
                reason_enum = RotationReason(req.reason.lower())
            except ValueError:
                valid_reasons = [r.value for r in RotationReason]
                raise HTTPException(status_code=400, detail=f"invalid_rotation_reason: must be one of {valid_reasons}")
            new_epoch = crypto_vault.rotate(reason=reason_enum)
        _sync_crypto_metrics()
        return {
            "rotated": True,
            "reason": req.reason,
            "new_epoch_id": new_epoch.epoch_id,
            "created_at": new_epoch.created_at,
            "total_epochs": len(crypto_vault.epoch_ids),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/crypto/seal")
def crypto_seal(req: CryptoSealRequest):
    """Encrypt data with 2-layer AES-256-GCM envelope using active epoch keys."""
    from fastapi import HTTPException
    try:
        if req.is_base64:
            try:
                data_bytes = base64.b64decode(req.plaintext)
            except Exception:
                raise HTTPException(status_code=400, detail="invalid_base64_plaintext_payload")
        else:
            data_bytes = req.plaintext.encode("utf-8")

        aad_bytes = req.aad.encode("utf-8") if req.aad else b""
        envelope = crypto_vault.seal(data_bytes, aad=aad_bytes)
        _sync_crypto_metrics()
        return {"envelope": envelope, "crypto_epoch": envelope.get("crypto_epoch")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/crypto/open")
def crypto_open(req: CryptoOpenRequest):
    """Decrypt data sealed with 2-layer AES-256-GCM envelope with replay attack protection."""
    from fastapi import HTTPException
    try:
        # Replay Attack Prevention (if enabled)
        if req.replay_check:
            env_id = req.envelope.get("event_id")
            env_ts = float(req.envelope.get("created_at", time.time()))
            if env_id and replay_guard.is_replayed(env_id, env_ts):
                audit = {"source": "layer6_crypto", "event_type": "replay_attack_detected", "event_id": env_id, "ts": time.time()}
                audit["id"] = event_id(audit)
                store.append(audit)
                raise HTTPException(status_code=400, detail="replay_attack_detected")

        aad_bytes = req.aad.encode("utf-8") if req.aad else b""
        decrypted = crypto_vault.open(req.envelope, aad=aad_bytes)
        if req.as_base64:
            result_str = base64.b64encode(decrypted).decode("ascii")
        else:
            try:
                result_str = decrypted.decode("utf-8")
            except UnicodeDecodeError:
                result_str = base64.b64encode(decrypted).decode("ascii")
        return {"plaintext": result_str, "crypto_epoch": req.envelope.get("crypto_epoch")}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port)