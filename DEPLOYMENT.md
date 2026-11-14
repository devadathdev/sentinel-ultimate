# SENTINEL Ultimate - Production Deployment Guide

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SENTINEL ULTIMATE SECURITY FABRIC                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  EXTERNAL CLIENTS                                                           │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────┐    TLS 1.3    ┌────────────────────────────────────────┐  │
│  │    NGINX    │ ◄────────────► │          SENTINEL API (7 Layers)       │  │
│  │  (Layer 1)  │  Termination  │                                        │  │
│  └─────────────┘               │  L1: Edge Guard (Rate Limit, TLS)      │  │
│       │                        │  L2: Network Fortress (Suricata)       │  │
│       ▼                        │  L3: Identity Fortress (OIDC/RBAC)     │  │
│  ┌─────────────────────────────►  L4: Application Fortress (Policy)     │  │
│  │                           │  L5: AI Firewall (Tool Risk)             │  │
│  │  INTERNAL SERVICES         │  L6: Data Vault (AES-256-GCM x2)       │  │
│  │                           │  L7: Execution Sandbox (Deny-by-default) │  │
│  └─────────────────────────────┘                                        │  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Quick Start (Docker Compose)

```bash
# 1. Clone and configure
git clone https://github.com/yourorg/sentinel-ultimate.git
cd sentinel-ultimate

# 2. Create environment file
cp deploy/environment.example .env
# Edit .env with your secrets (required: SENTINEL_MASTER_KEY, OIDC config)

# 3. Generate TLS certificates (or use Let's Encrypt)
mkdir -p tls
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
  -nodes -keyout tls/privkey.pem -out tls/fullchain.pem \
  -subj "/CN=sentinel.example.internal"

# 4. Deploy
docker compose up -d

# 5. Verify
curl -k https://localhost/health
curl -k https://localhost/metrics
```

## Production Deployment (Systemd)

### Prerequisites

- Ubuntu 22.04+ / Debian 12+ / RHEL 9+
- Python 3.13+
- Redis 7+
- NGINX
- Suricata 7+
- 2GB+ RAM, 2+ CPU cores

### Automated Deployment

```bash
# As root
curl -fsSL https://raw.githubusercontent.com/yourorg/sentinel-ultimate/main/deploy/deploy.sh | bash
```

### Manual Deployment Steps

#### 1. System Dependencies

```bash
apt-get update && apt-get install -y \
  python3.13 python3.13-venv python3.13-dev \
  gcc libffi-dev libssl-dev \
  redis-server nginx suricata \
  curl jq ca-certificates
```

#### 2. Service User

```bash
useradd -r -s /bin/false -d /opt/sentinel -c "SENTINEL Service" sentinel
```

#### 3. Application Deploy

```bash
mkdir -p /opt/sentinel/{data,logs,tmp}
chown -R sentinel:sentinel /opt/sentinel

python3.13 -m venv /opt/sentinel/.venv
/opt/sentinel/.venv/bin/pip install --upgrade pip
/opt/sentinel/.venv/bin/pip install -r requirements.txt

chown -R sentinel:sentinel /opt/sentinel/.venv
```

#### 4. Environment Configuration

```bash
mkdir -p /etc/sentinel
cp deploy/environment.example /etc/sentinel/environment
chmod 600 /etc/sentinel/environment
chown root:sentinel /etc/sentinel/environment

# EDIT /etc/sentinel/environment with your secrets:
# - SENTINEL_MASTER_KEY (generate: python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")
# - SENTINEL_OIDC_ISSUER, SENTINEL_OIDC_AUDIENCE, SENTINEL_OIDC_JWKS_URL
# - REDIS_PASSWORD
```

#### 5. NGINX TLS Termination

```bash
cp deploy/nginx.conf.example /etc/nginx/sites-available/sentinel
ln -sf /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# TLS Certificates (production: use certbot)
mkdir -p /etc/ssl/sentinel
# Option A: Let's Encrypt (recommended)
certbot --nginx -d sentinel.example.com

# Option B: Self-signed (testing only)
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 \
  -nodes -keyout /etc/ssl/sentinel/privkey.pem \
  -out /etc/ssl/sentinel/fullchain.pem \
  -subj "/CN=sentinel.example.internal"

nginx -t && systemctl reload nginx
```

#### 6. Redis Configuration

```bash
# Configure password and binding
sed -i "s/^# requirepass .*/requirepass ${REDIS_PASSWORD}/" /etc/redis/redis.conf
sed -i 's/^bind 127.0.0.1 ::1/bind 0.0.0.0/' /etc/redis/redis.conf
systemctl enable redis-server && systemctl restart redis-server
```

#### 7. Suricata IDS/IPS

```bash
mkdir -p /etc/suricata/rules
cp layer2/suricata/suricata.yaml.example /etc/suricata/suricata.yaml

# Add custom rules to /etc/suricata/rules/
# Enable and start
systemctl enable suricata && systemctl restart suricata
```

#### 8. Systemd Services

```bash
cp deploy/systemd/sentinel-api.service /etc/systemd/system/
cp deploy/systemd/sentinel-suricata-forwarder.service /etc/systemd/system/

systemctl daemon-reload
systemctl enable sentinel-api sentinel-suricata-forwarder
systemctl start sentinel-api sentinel-suricata-forwarder
```

## Configuration Reference

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SENTINEL_MASTER_KEY` | 32-byte base64 key for AES-256-GCM encryption | `base64url(secrets.token_bytes(32))` |
| `SENTINEL_OIDC_ISSUER` | OIDC provider issuer URL | `https://keycloak.example.com/realms/sentinel` |
| `SENTINEL_OIDC_AUDIENCE` | Expected JWT audience | `sentinel-api` |
| `SENTINEL_OIDC_JWKS_URL` | JWKS endpoint for RS256 verification | `https://keycloak.example.com/realms/sentinel/protocol/openid-connect/certs` |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_HOST` | `0.0.0.0` | API bind address |
| `SENTINEL_PORT` | `8080` | API port |
| `SENTINEL_MAX_BODY_BYTES` | `1048576` | Max request body (1MB) |
| `SENTINEL_RATE_LIMIT` | `120` | Requests per minute per IP |
| `SENTINEL_TRUST_PROXY` | `true` | Trust X-Forwarded-Proto header |
| `SENTINEL_ENV` | `production` | Environment name |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `REDIS_PASSWORD` | `` | Redis password |
| `SENTINEL_EVENTS_TOKEN` | `` | Bearer token for event ingestion |

## API Endpoints

| Method | Endpoint | Layer | Description |
|--------|----------|-------|-------------|
| GET | `/health` | - | Liveness probe |
| GET | `/ready` | - | Readiness probe |
| GET | `/metrics` | - | Prometheus metrics |
| GET | `/v1/security/status` | 1-7 | Security fabric status |
| POST | `/v1/authorize` | 4 | Application policy authorization |
| POST | `/v1/ai/tool/authorize` | 5 | AI tool risk authorization |
| POST | `/v1/execute/authorize` | 7 | Execution sandbox authorization |
| POST | `/v1/identity/authorize` | 3 | Identity/RBAC/ABAC authorization |
| POST | `/v1/identity/revoke` | 3 | Session/token revocation |
| POST | `/v1/events` | 6 | Security event ingestion |

## Monitoring

### Prometheus Metrics

Key metrics exposed on `/metrics`:

- `sentinel_authorize_total` - Authorization decisions by action/layer/reason
- `sentinel_rate_limited_total` - Rate limited requests
- `sentinel_ai_tool_total` - AI tool authorization decisions
- `sentinel_execution_total` - Execution authorization decisions
- `sentinel_identity_authorize_total` - Identity authorization decisions
- `sentinel_events_stored_total` - Security events stored
- `sentinel_request_duration_seconds` - Request latency histogram
- `sentinel_active_sessions` - Active sessions
- `sentinel_revoked_sessions` - Revoked sessions/tokens

### Grafana Dashboards

Pre-built dashboards available in `monitoring/grafana/dashboards/`:
- Sentinel Security Overview
- Authorization Decisions
- Identity & Access
- AI Tool Risk
- Execution Sandbox
- System Health

### Alerting Rules (Prometheus)

```yaml
groups:
  - name: sentinel
    rules:
      - alert: SentinelHighDenyRate
        expr: rate(sentinel_authorize_total{action="BLOCK"}[5m]) / rate(sentinel_authorize_total[5m]) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authorization deny rate"

      - alert: SentinelRateLimited
        expr: rate(sentinel_rate_limited_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High rate limiting activity"

      - alert: SentinelDown
        expr: up{job="sentinel-api"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Sentinel API is down"
```

## Security Hardening Checklist

- [ ] `SENTINEL_MASTER_KEY` generated and stored in secret manager
- [ ] OIDC provider configured with RS256/JWKS (no shared secrets)
- [ ] Let's Encrypt TLS certificates (not self-signed)
- [ ] Redis password set and TLS enabled
- [ ] Suricata rules tuned for environment
- [ ] NGINX rate limiting configured at edge
- [ ] Firewall rules: only 443/80 inbound, restricted outbound
- [ ] Systemd hardening applied (see service files)
- [ ] Log aggregation configured (Loki/Elastic/Splunk)
- [ ] Backup/restore tested for encrypted event store
- [ ] Penetration test scheduled
- [ ] Incident response plan documented

## Key Rotation

### Master Key Rotation

```bash
# 1. Generate new key
NEW_KEY=$(python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())")

# 2. Update environment
sed -i "s/^SENTINEL_MASTER_KEY=.*/SENTINEL_MASTER_KEY=$NEW_KEY/" /etc/sentinel/environment

# 3. Re-encrypt existing events (run as sentinel user)
/opt/sentinel/.venv/bin/python -c "
from sentinel.security import EncryptedEventStore
import base64
old = EncryptedEventStore()  # Reads old key from env
new = EncryptedEventStore()  # Uses new key
# Migration script needed for existing .enc files
"

# 4. Restart service
systemctl restart sentinel-api
```

### Crypto Epoch Rotation (Automatic)

The `AdaptiveCryptoVault` automatically rotates keys based on:
- Age (default 90 days)
- Message count (default 1M)
- Byte count (default 10GB)
- Security events (emergency rotation)

Monitor with: `sentinel_crypto_epochs_total` and `sentinel_crypto_epoch_active` metrics.

## Troubleshooting

### Service Won't Start

```bash
# Check logs
journalctl -u sentinel-api -f

# Common issues:
# - Missing SENTINEL_MASTER_KEY
# - Redis connection refused
# - Port 8080 already in use
# - Permission denied on /opt/sentinel/data
```

### High Latency

```bash
# Check metrics
curl http://localhost:8080/metrics | grep sentinel_request_duration

# Common causes:
# - Redis latency (check Redis slowlog)
# - Encryption overhead (large payloads)
# - Suricata forwarder blocking
```

### Authorization Denials

```bash
# Check recent decisions
curl http://localhost:8080/metrics | grep sentinel_authorize_total

# Check Suricata alerts
tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
```

## Backup & Recovery

### Automated Backup

```bash
#!/bin/bash
# /etc/cron.daily/sentinel-backup
BACKUP_DIR="/var/backups/sentinel/$(date +%F)"
mkdir -p "$BACKUP_DIR"

# Encrypted event store
cp /opt/sentinel/data/sentinel-events.enc "$BACKUP_DIR/"

# Configuration
cp /etc/sentinel/environment "$BACKUP_DIR/"

# Redis
redis-cli --rdb "$BACKUP_DIR/redis.rdb"

# Rotate (keep 30 days)
find /var/backups/sentinel -type d -mtime +30 -exec rm -rf {} \;
```

### Recovery

```bash
# 1. Stop services
systemctl stop sentinel-api sentinel-suricata-forwarder

# 2. Restore data
cp /var/backups/sentinel/2024-01-15/sentinel-events.enc /opt/sentinel/data/
cp /var/backups/sentinel/2024-01-15/environment /etc/sentinel/

# 3. Restore Redis
redis-cli -r /var/backups/sentinel/2024-01-15/redis.rdb

# 4. Start services
systemctl start sentinel-api sentinel-suricata-forwarder
```

## Testing

```bash
# Unit tests
pytest tests/ crypto/tests/ layer2/tests/ layer3/tests/ crypto/adaptive/tests/ -v

# Integration test (requires running services)
curl -k -X POST https://localhost/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"identity":"test","role":"admin","method":"GET","path":"/","body_size":0,"zone":"management"}'

# Load test
hey -n 10000 -c 50 -m POST \
  -H "Content-Type: application/json" \
  -d '{"identity":"load","role":"user","method":"GET","path":"/","body_size":0,"zone":"user"}' \
  https://localhost/v1/authorize
```

## Support

- Documentation: `README.md`, `layer2/docs/`, `layer3/docs/`
- Issues: GitHub Issues
- Security: Report privately to security@example.com