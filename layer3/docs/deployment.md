# Layer 3 deployment

1. Deploy an OIDC provider and enable passkeys/WebAuthn + MFA.
2. Configure SENTINEL with the issuer URL and audience.
3. Configure JWKS/asymmetric verification; never ship an IdP private key to SENTINEL.
4. Issue 5-minute access tokens and rotate refresh credentials through the IdP/session service.
5. Require mTLS for service-to-service traffic in the AI/server/management zones.
6. Map IdP groups/roles to SENTINEL roles and scopes.
7. Require recent WebAuthn/MFA (`amr`) for privileged operations.
8. Send every allow/deny/revocation decision into the Layer 6 encrypted audit store.
9. Put the management plane behind the Layer 2 management zone and do not expose it directly to the Internet.
