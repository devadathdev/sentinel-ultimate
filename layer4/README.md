# Layer 4 — Application Fortress

Layer 4 enforces web application firewall (WAF) controls, request payload validation, and adaptive zone-aware rate limiting for SENTINEL.

## Controls

1. **HTTP Method Enforcement**: Strict allowlist of safe and expected HTTP verbs (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`). Rejects diagnostic probes (`TRACE`, `TRACK`, `CONNECT`) with 405.
2. **Path Normalization & Traversal Prevention**: Canonicalizes multi-encoded and raw URL paths, rejecting directory traversal (`../`, `..\`, `%2e%2e`), null bytes (`%00`), and path tampering.
3. **Scanner & Probe Defense**: Automatically blocks vulnerability discovery requests (`/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `/actuator`, `/swagger-ui`).
4. **Injection Attack Detection**:
   - **SQL Injection (SQLi)**: Pattern matching for statement stacking, union selects, sleep/time-delay payloads, and comment truncations.
   - **Cross-Site Scripting (XSS)**: Script tag detection, event handler attributes (`onerror=`, `onload=`), pseudo-protocols (`javascript:`), and iframe injections.
5. **Zone-Aware Adaptive Rate Limiting**:
   - Per-zone quota enforcement (User, AI Agents, Server, IoT, Management).
   - Dynamic Penalty Box: Clients repeatedly violating WAF rules or overflowing quotas receive progressive cooling-off quarantine periods.
6. **Content-Type & Body Enforcement**: Mandatory content-type verification on mutation requests and configurable maximum body sizes.

## API Integration

Layer 4 controls execute at the application boundary in `sentinel/main.py` middleware and through direct policy verification endpoints.
