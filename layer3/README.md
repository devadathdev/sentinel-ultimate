# Layer 3 — Identity Fortress

Layer 3 establishes identity before authorization. It is intentionally an integration boundary rather than a homemade identity provider.

## Controls

- OIDC/JWT validation with issuer, audience, expiry and required claims.
- Short-lived access-token model (default 5 minutes in the reference config).
- RBAC + scope authorization with deny-by-default.
- ABAC-style checks for network zone, resource class and privileged actions.
- WebAuthn/passkey/MFA step-up signal through `amr` + `auth_time` claims.
- Device identity boundary using mTLS certificate fingerprints.
- Service identity support through the same token/device policy path.
- Subject/token revocation hooks.
- Explicit protection for management and secret resources.
- Audit-ready identity fields: subject, device, issuer, token ID, auth method and decision reason.

## Production boundary

Use a real OIDC provider (for example Keycloak, Authentik, Entra ID or another standards-compliant IdP) and its JWKS endpoint. Do **not** put passwords, private keys, or long-lived shared secrets into SENTINEL.

The included `TokenVerifier` has a local secret mode only to make unit tests deterministic. Production should use asymmetric OIDC/JWKS verification.
