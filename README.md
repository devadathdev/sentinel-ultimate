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
- `POST /v1/ai/tool/authorize` — Layer 5 AI Firewall tool risk & approval gate
- `POST /v1/execute/authorize` — Layer 7 Execution Sandbox command allowlist gate
- `POST /v1/events` — Append security events to encrypted audit vault
- `POST /v1/identity/authorize` — Layer 3 Identity & RBAC/ABAC verification
- `POST /v1/identity/revoke` — Layer 3 Subject and token revocation
- `GET /v1/crypto/status` — Layer 6 Adaptive Crypto Shield status & active epoch metadata
- `POST /v1/crypto/rotate` — Layer 6 Epoch rotation (administrative, usage, or emergency)
- `POST /v1/crypto/seal` — Layer 6 Double AES-256-GCM envelope encryption
- `POST /v1/crypto/open` — Layer 6 Envelope decryption with epoch grace validation

All security decisions are deny-by-default.

## Layer 3 — Identity Fortress

Layer 3 is implemented as an identity/authorization boundary. It provides OIDC/JWT claim validation, short-lived-token policy, RBAC + ABAC-style authorization, WebAuthn/MFA step-up signals, device identity hooks, and session/token revocation.

New endpoints:

- `POST /v1/identity/authorize`
- `POST /v1/identity/revoke`

The local JWT secret path exists only for deterministic tests. Production must use asymmetric OIDC/JWKS verification and a real identity provider. WebAuthn/passkey ceremony and private-key handling belong to that IdP, not to a homemade SENTINEL password system.

## Layer 6 — Adaptive Crypto Shield (v1.1)

Layer 6 adds an adaptive post-layer cryptographic double-envelope around application payloads:
1. Inner layer: authenticated encryption with independent AES-256-GCM key.
2. Outer layer: authenticated encryption with independent outer AES-256-GCM key.
3. Cryptographic epochs: automatic key rotation triggered by epoch age, message volume, byte volume, or security incidents.
4. Grace & Revocation: retired epochs remain decryptable during a bounded grace window (default 24h) and can be immediately revoked in an emergency lockdown.

New endpoints:
- `GET /v1/crypto/status`: Inspect active epoch ID, age, total epochs, message/byte count, and rotation policy.
- `POST /v1/crypto/rotate`: Trigger rotation with reasons `administrative`, `schedule`, `usage`, `security_event`, or `emergency`.
- `POST /v1/crypto/seal`: Authenticate and encrypt application plaintext under active epoch keys.
- `POST /v1/crypto/open`: Verify and decrypt sealed envelope, honoring epoch grace windows and rejecting revoked epochs.

