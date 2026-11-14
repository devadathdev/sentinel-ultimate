"""Automatic key-epoch rotation around SENTINEL's two AES-256-GCM layers.

The algorithm remains deliberately stable (AES-256-GCM); the independent key
material changes by epoch. Production key material must come from a KMS/HSM.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..vault import KEY_BYTES, KeyMaterial, CryptoVault, generate_key


class RotationReason(str, Enum):
    STARTUP = "startup"
    SCHEDULE = "schedule"
    USAGE = "usage"
    SECURITY_EVENT = "security_event"
    EMERGENCY = "emergency"
    ADMINISTRATIVE = "administrative"


@dataclass(frozen=True)
class RotationPolicy:
    max_age_seconds: int = 90 * 24 * 3600
    max_messages: int = 1_000_000
    max_bytes: int = 10 * 1024 * 1024 * 1024
    emergency_retention_seconds: int = 3600
    previous_key_grace_seconds: int = 24 * 3600

    def __post_init__(self) -> None:
        if self.max_age_seconds <= 0 or self.max_messages <= 0 or self.max_bytes <= 0:
            raise ValueError("rotation limits must be positive")
        if self.previous_key_grace_seconds < 0 or self.emergency_retention_seconds < 0:
            raise ValueError("retention windows cannot be negative")


@dataclass
class KeyEpoch:
    epoch_id: str
    inner: KeyMaterial
    outer: KeyMaterial
    created_at: int
    message_count: int = 0
    byte_count: int = 0
    retired_at: int | None = None
    rotation_reason: str = RotationReason.STARTUP.value

    @property
    def active(self) -> bool:
        return self.retired_at is None


AuditSink = Callable[[dict], None]


class AdaptiveCryptoVault:
    """Automatically changes encryption keys while retaining decryptability.

    Each epoch owns two independent AES-256 keys. New data is always encrypted
    with the active epoch. Retired epochs remain available only for a bounded
    grace period and can be explicitly revoked immediately.
    """

    def __init__(
        self,
        *,
        policy: RotationPolicy | None = None,
        now: Callable[[], int] | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self.policy = policy or RotationPolicy()
        self._now = now or (lambda: int(time.time()))
        self._audit_sink = audit_sink
        self._epochs: dict[str, KeyEpoch] = {}
        self._revoked: set[str] = set()
        self._active_epoch = self._new_epoch(RotationReason.STARTUP).epoch_id

    @property
    def active_epoch(self) -> KeyEpoch:
        return self._epochs[self._active_epoch]

    @property
    def epoch_ids(self) -> tuple[str, ...]:
        return tuple(self._epochs.keys())

    def status(self) -> dict:
        active = self.active_epoch
        return {
            "active_epoch": active.epoch_id,
            "created_at": active.created_at,
            "message_count": active.message_count,
            "byte_count": active.byte_count,
            "total_epochs": len(self._epochs),
            "revoked_epochs": sorted(self._revoked),
        }

    def seal(self, plaintext: bytes, *, aad: bytes = b"") -> dict:
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if self.should_rotate(len(plaintext)):
            self.rotate(RotationReason.SCHEDULE if self.age_exceeded() else RotationReason.USAGE)
        epoch = self.active_epoch
        envelope = CryptoVault(epoch.inner, epoch.outer).seal(plaintext, aad=aad)
        envelope["crypto_epoch"] = epoch.epoch_id
        epoch.message_count += 1
        epoch.byte_count += len(plaintext)
        self._audit("crypto.seal", epoch, {"bytes": len(plaintext)})
        return envelope

    def open(self, envelope: dict, *, aad: bytes = b"", max_age_seconds: int = 86400) -> bytes:
        epoch_id = envelope.get("crypto_epoch")
        if not epoch_id:
            raise ValueError("missing crypto epoch")
        if epoch_id in self._revoked:
            raise ValueError("crypto epoch revoked")
        if epoch_id not in self._epochs:
            raise ValueError("unknown crypto epoch")
        epoch = self._epochs[epoch_id]
        if epoch.retired_at is not None and self._now() - epoch.retired_at > self.policy.previous_key_grace_seconds:
            raise ValueError("crypto epoch outside grace period")
        return CryptoVault(epoch.inner, epoch.outer).open(
            envelope, aad=aad, max_age_seconds=max_age_seconds
        )

    def should_rotate(self, next_bytes: int = 0) -> bool:
        return self.age_exceeded() or self.usage_exceeded(next_bytes)

    def age_exceeded(self) -> bool:
        return self._now() - self.active_epoch.created_at >= self.policy.max_age_seconds

    def usage_exceeded(self, next_bytes: int = 0) -> bool:
        epoch = self.active_epoch
        return (
            epoch.message_count + 1 > self.policy.max_messages
            or epoch.byte_count + max(next_bytes, 0) > self.policy.max_bytes
        )

    def rotate(self, reason: RotationReason = RotationReason.ADMINISTRATIVE) -> KeyEpoch:
        old = self.active_epoch
        old.retired_at = self._now()
        self._active_epoch = self._new_epoch(reason).epoch_id
        self._audit("crypto.rotate", self.active_epoch, {
            "previous_epoch": old.epoch_id,
            "reason": reason.value,
        })
        self._prune_expired()
        return self.active_epoch

    def emergency_rotate(self) -> KeyEpoch:
        old = self.active_epoch
        new = self.rotate(RotationReason.EMERGENCY)
        # Emergency rotation can immediately revoke the old epoch rather than
        # waiting for normal grace. Existing ciphertext then requires recovery
        # procedures from the protected KMS/HSM backup if decryption is needed.
        self.revoke(old.epoch_id, reason=RotationReason.EMERGENCY)
        return new

    def revoke(self, epoch_id: str, *, reason: RotationReason = RotationReason.SECURITY_EVENT) -> None:
        if epoch_id == self._active_epoch:
            raise ValueError("cannot revoke active epoch; rotate first")
        if epoch_id not in self._epochs:
            raise KeyError(epoch_id)
        self._revoked.add(epoch_id)
        self._audit("crypto.revoke", self._epochs[epoch_id], {"reason": reason.value})
        self._prune_expired(force=True)

    def _new_epoch(self, reason: RotationReason) -> KeyEpoch:
        inner = KeyMaterial.from_b64(f"inner-{uuid.uuid4()}", generate_key())
        outer = KeyMaterial.from_b64(f"outer-{uuid.uuid4()}", generate_key())
        if inner.key == outer.key or len(inner.key) != KEY_BYTES or len(outer.key) != KEY_BYTES:
            raise RuntimeError("failed to create independent AES-256 key material")
        epoch = KeyEpoch(
            epoch_id=f"epoch-{uuid.uuid4()}",
            inner=inner,
            outer=outer,
            created_at=self._now(),
            rotation_reason=reason.value,
        )
        self._epochs[epoch.epoch_id] = epoch
        return epoch

    def _prune_expired(self, force: bool = False) -> None:
        now = self._now()
        for epoch_id, epoch in list(self._epochs.items()):
            if epoch_id == self._active_epoch or epoch.retired_at is None:
                continue
            expired = now - epoch.retired_at > self.policy.previous_key_grace_seconds
            if force and epoch_id in self._revoked:
                expired = True
            if expired:
                del self._epochs[epoch_id]

    def _audit(self, event_type: str, epoch: KeyEpoch, details: dict) -> None:
        if self._audit_sink:
            self._audit_sink({
                "event_type": event_type,
                "event_id": str(uuid.uuid4()),
                "timestamp": self._now(),
                "epoch_id": epoch.epoch_id,
                "details": details,
            })
