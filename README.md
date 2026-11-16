# SENTINEL Ultimate Security Fabric

A defensive 7-layer security gateway prototype for an AI ecosystem.

## Layers
1. Edge Shield — TLS 1.3 termination is delegated to a production reverse proxy; Sentinel validates trusted proxy headers and request metadata.
2. Network Fortress — zone/policy enforcement.
3. Identity Fortress — API-key/token identity and RBAC.
4. Application Fortress — request size, method, path and rate controls.
5. AI Firewall — tool risk policy and approval requirements.
6. Data Vault — AES-256-GCM encrypted security event storage.
7. Execution Sandbox — deny-by-default execution policy and command allowlist.

This repository is an MVP policy gateway, not a replacement for a kernel/network firewall. Deploy it behind a hardened TLS 1.3 reverse proxy and alongside host/network controls such as nftables/OPNsense and IDS/IPS.

## Run

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m sentinel
```

Set `SENTINEL_MASTER_KEY` to a 32-byte base64 key before production use. Generate one with:

```bash
python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

## API

- `GET /health` — Liveness health check
- `GET /ready` — Readiness dependency probe
- `GET /metrics` — Prometheus metrics endpoint
- `GET /v1/security/status` — Operational status across all 7 layers
- `POST /v1/authorize` — Layer 4 Application rate, size, and routing policy
- `POST /v1/app/waf/inspect` — Layer 4 Application Fortress deep WAF inspection
- `POST /v1/ai/tool/authorize` — Layer 5 AI Firewall tool risk & approval gate
- `POST /v1/ai/prompt/scan` — Layer 5 AI Firewall prompt injection & jailbreak scanner
- `POST /v1/ai/dlp/scan` — Layer 5 AI Firewall secret leak & PII exfiltration detection/redaction
- `POST /v1/execute/authorize` — Layer 7 Execution Sandbox command parser & ticket gate
- `POST /v1/execute/verify-ticket` — Layer 7 Execution Sandbox HMAC ticket verification
- `POST /v1/events` — Append security events to encrypted audit vault
- `POST /v1/identity/authorize` — Layer 3 Identity & RBAC/ABAC verification
- `POST /v1/identity/revoke` — Layer 3 Subject and token revocation
- `GET /v1/crypto/status` — Layer 6 Adaptive Crypto Shield status & active epoch metadata
- `POST /v1/crypto/rotate` — Layer 6 Epoch rotation (administrative, usage, or emergency)
- `POST /v1/crypto/seal` — Layer 6 Double AES-256-GCM envelope encryption
- `POST /v1/crypto/open` — Layer 6 Envelope decryption with epoch grace validation

All security decisions are deny-by-default.

## Layer Implementations

### Layer 1 — Edge Shield
- Dedicated dual-stack Nginx TLS 1.3 reverse proxy (`deploy/nginx.conf.example`).
- Edge defense headers: HSTS (2-year preload), CSP (`default-src 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`.
- Client certificate verification (mTLS) and diagnostic HTTP method blocking (`TRACE`, `TRACK`, `CONNECT`).

### Layer 2 — Network Fortress
- Stateful nftables rule generator (`layer2/zones.py`) implementing zone microsegmentation across `user`, `ai`, `server`, `iot`, and `management`.
- Default-drop policy on all ingress and forward chains.

### Layer 3 — Identity Fortress
- Token validation with OIDC/JWT claim inspection (`layer3/identity.py`, `layer3/token.py`).
- RBAC and ABAC boundary with step-up MFA signals (`amr` claims).
- Redis-backed distributed session registry with in-memory caching and real-time revocation.

### Layer 4 — Application Fortress
- Production Web Application Firewall (`layer4/waf.py`) blocking path traversal (`../`, `%2e%2e`), null-byte injection (`%00`), probe endpoints (`/.env`, `/.git`, `/wp-admin`, `/etc/passwd`), SQL injection heuristics, and cross-site scripting (XSS).
- Zone-aware sliding window rate limiter (`layer4/rate_limiter.py`) with progressive penalty box for hostile clients.

### Layer 5 — AI Firewall
- Prompt Guard (`layer5/prompt_guard.py`): Direct Prompt Injection (DPI) detection, jailbreak roleplay detection, control token spoofing (`<|im_start|>`, `[INST]`), and base64 obfuscation decoding.
- Tool Governance Engine (`layer5/tool_policy.py`): 5-tier risk taxonomy (`SAFE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), deep argument threat inspection, and dual-control approval for critical actions.
- Data Loss Prevention Engine (`layer5/dlp.py`): Real-time regex and checksum scanner detecting API keys (OpenAI, AWS, GitHub, private keys, JWTs) and PII (SSN, credit cards with Luhn check, emails) with automatic redaction.

### Layer 6 — Adaptive Crypto Shield (v1.1)
- Two-layer AES-256-GCM envelope encryption with independent keys per layer.
- Automatic key rotation based on message limits, byte volume, or time.
- Sliding-window ReplayGuard defending against envelope replay attacks.
- Grace window for retired keys and immediate emergency epoch revocation.

### Layer 7 — Execution Sandbox
- Lexical anti-evasion analyzer (`layer7/command_parser.py`) blocking shell escapes, command chaining (`;`, `&&`, `||`), pipes (`|`), substitutions (`` ` ``, `$()`), and arbitrary inline eval (`-c`).
- Zero-trust execution boundary (`layer7/sandbox_policy.py`) requiring sandboxing (`sandbox=True`) and issuing attested, HMAC-SHA256 signed `ExecutionTicket`s.
- Hardened Linux seccomp profile (`layer7/seccomp/sentinel-default.json`) blocking dangerous syscalls (`ptrace`, `bpf`, `mount`, `chroot`).

