# Layer 4 Deployment and Operations

## Reverse Proxy Header Coordination

When running Sentinel behind Nginx or a cloud load balancer, ensure the edge proxy sets the standard tracking headers:
- `X-Forwarded-For`: Client IP address for rate limiting and penalty assignment.
- `X-Forwarded-Proto`: Scheme (`https` required).
- `Host`: Original request host.

In `sentinel/config.py`, set `SENTINEL_TRUST_PROXY=true` only when Sentinel is securely deployed behind trusted internal reverse proxies.

## Tuning False Positives

If legitimate application workloads require sending SQL queries or markup in JSON payloads (for example, in developer testing tools):
1. Restrict such operations to the `management` or `ai` zones with role `developer` or `admin`.
2. Wrap raw queries inside an encrypted Layer 6 Data Vault payload (`POST /v1/crypto/seal`) so they are transported safely inside an authenticated envelope.
