from __future__ import annotations
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any

import jwt


@dataclass(frozen=True)
class Identity:
    subject: str
    roles: frozenset[str] = frozenset()
    scopes: frozenset[str] = frozenset()
    device_id: str | None = None
    issuer: str | None = None
    token_id: str | None = None
    auth_time: int | None = None
    amr: frozenset[str] = frozenset()
    acr: str | None = None
    claims: dict[str, Any] = field(default_factory=dict)


class IdentityError(ValueError):
    pass


class TokenVerifier:
    """JWT verification boundary. Production should use an OIDC issuer/JWKS, not a shared secret."""
    def __init__(self, *, issuer: str, audience: str, secret: str | None = None, algorithms: tuple[str, ...] = ("RS256",)):
        self.issuer = issuer
        self.audience = audience
        self.secret = secret
        self.algorithms = algorithms

    def verify(self, token: str) -> Identity:
        if not token:
            raise IdentityError("missing_token")
        if not self.secret:
            raise IdentityError("oidc_jwks_not_configured")
        try:
            claims = jwt.decode(
                token,
                self.secret,
                algorithms=list(self.algorithms),
                issuer=self.issuer,
                audience=self.audience,
                options={"require": ["sub", "iss", "aud", "exp", "iat"]},
            )
        except jwt.PyJWTError as exc:
            raise IdentityError("invalid_token") from exc
        return identity_from_claims(claims)


def identity_from_claims(claims: dict[str, Any]) -> Identity:
    roles = claims.get("roles", [])
    scopes = claims.get("scope", "")
    if isinstance(roles, str):
        roles = roles.split()
    if isinstance(scopes, str):
        scopes = scopes.split()
    return Identity(
        subject=str(claims["sub"]),
        roles=frozenset(str(x) for x in roles),
        scopes=frozenset(str(x) for x in scopes),
        device_id=claims.get("device_id"),
        issuer=claims.get("iss"),
        token_id=claims.get("jti"),
        auth_time=claims.get("auth_time"),
        amr=frozenset(claims.get("amr", [])),
        acr=claims.get("acr"),
        claims=dict(claims),
    )


class SessionRegistry:
    """Session and token revocation registry with optional durable Redis backing and local memory cache."""
    def __init__(self, redis_url: str | None = None) -> None:
        self.revoked_subjects: set[str] = set()
        self.revoked_tokens: set[str] = set()
        self._redis = None
        if redis_url:
            try:
                import redis
                client = redis.Redis.from_url(redis_url, socket_connect_timeout=1.5, socket_timeout=1.5)
                client.ping()
                self._redis = client
                # Warm cache from redis
                cached_subs = client.smembers("sentinel:revoked_subjects")
                self.revoked_subjects.update(s.decode() if isinstance(s, bytes) else str(s) for s in cached_subs)
                cached_tokens = client.smembers("sentinel:revoked_tokens")
                self.revoked_tokens.update(t.decode() if isinstance(t, bytes) else str(t) for t in cached_tokens)
            except Exception:
                self._redis = None

    def revoke_subject(self, subject: str) -> None:
        self.revoked_subjects.add(subject)
        if self._redis:
            try:
                self._redis.sadd("sentinel:revoked_subjects", subject)
            except Exception:
                pass

    def revoke_token(self, token_id: str) -> None:
        self.revoked_tokens.add(token_id)
        if self._redis:
            try:
                self._redis.sadd("sentinel:revoked_tokens", token_id)
            except Exception:
                pass

    def is_revoked(self, identity: Identity) -> bool:
        if identity.subject in self.revoked_subjects or bool(identity.token_id and identity.token_id in self.revoked_tokens):
            return True
        if self._redis:
            try:
                if self._redis.sismember("sentinel:revoked_subjects", identity.subject):
                    self.revoked_subjects.add(identity.subject)
                    return True
                if identity.token_id and self._redis.sismember("sentinel:revoked_tokens", identity.token_id):
                    self.revoked_tokens.add(identity.token_id)
                    return True
            except Exception:
                pass
        return False


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    fingerprint_sha256: str
    zone: str
    enabled: bool = True


class DeviceRegistry:
    def __init__(self) -> None:
        self.devices: dict[str, DeviceIdentity] = {}

    def register(self, device: DeviceIdentity) -> None:
        self.devices[device.device_id] = device

    def verify(self, device_id: str, certificate_pem: bytes) -> bool:
        device = self.devices.get(device_id)
        if not device or not device.enabled:
            return False
        digest = hashlib.sha256(certificate_pem).hexdigest()
        return digest == device.fingerprint_sha256


class IdentityPolicy:
    ROLE_SCOPES = {
        "viewer": {"read"},
        "developer": {"read", "write", "execute:sandbox"},
        "operator": {"read", "write", "operate"},
        "admin": {"read", "write", "operate", "admin", "execute:sandbox"},
    }

    def authorize(
        self,
        identity: Identity,
        *,
        required_scope: str,
        resource: str,
        zone: str,
        privileged: bool = False,
        recent_mfa_seconds: int = 300,
    ) -> tuple[bool, str]:
        if not identity.subject:
            return False, "missing_identity"
        if zone == "management" and "admin" not in identity.roles:
            return False, "management_requires_admin"
        if required_scope not in identity.scopes and not any(required_scope in self.ROLE_SCOPES.get(r, set()) for r in identity.roles):
            return False, "missing_scope"
        if privileged:
            if not (identity.amr & {"webauthn", "fido2", "mfa"}):
                return False, "privileged_action_requires_mfa"
            if identity.auth_time is None or int(time.time()) - int(identity.auth_time) > recent_mfa_seconds:
                return False, "step_up_auth_required"
        if resource.startswith("secret:") and "admin" not in identity.roles:
            return False, "secret_access_requires_admin"
        return True, "policy_pass"
