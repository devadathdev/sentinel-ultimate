from __future__ import annotations

from crypto.adaptive import AdaptiveCryptoVault, RotationPolicy, RotationReason


def clock():
    return clock.now
clock.now = 1_000


def test_automatic_message_rotation():
    vault = AdaptiveCryptoVault(
        policy=RotationPolicy(max_age_seconds=10_000, max_messages=2, max_bytes=10_000),
        now=clock,
    )
    first = vault.active_epoch.epoch_id
    vault.seal(b"one")
    vault.seal(b"two")
    third = vault.seal(b"three")
    assert vault.active_epoch.epoch_id != first
    assert vault.open(third) == b"three"


def test_time_rotation_and_old_epoch_grace():
    vault = AdaptiveCryptoVault(
        policy=RotationPolicy(max_age_seconds=10, max_messages=100, max_bytes=10000, previous_key_grace_seconds=20),
        now=clock,
    )
    old = vault.seal(b"old")
    old_epoch = old["crypto_epoch"]
    clock.now += 11
    new = vault.seal(b"new")
    assert new["crypto_epoch"] != old_epoch
    assert vault.open(old) == b"old"


def test_emergency_rotation_revokes_previous_epoch():
    vault = AdaptiveCryptoVault(policy=RotationPolicy(), now=clock)
    old = vault.seal(b"secret")
    old_epoch = old["crypto_epoch"]
    vault.emergency_rotate()
    try:
        vault.open(old)
    except ValueError as exc:
        assert "revoked" in str(exc)
    else:
        raise AssertionError("revoked epoch decrypted")


def test_audit_events_are_emitted():
    events = []
    vault = AdaptiveCryptoVault(policy=RotationPolicy(max_messages=1), now=clock, audit_sink=events.append)
    vault.seal(b"one")
    vault.seal(b"two")
    assert any(e["event_type"] == "crypto.rotate" for e in events)
    assert all("epoch_id" in e for e in events)


def test_independent_keys_per_epoch():
    vault = AdaptiveCryptoVault(policy=RotationPolicy(), now=clock)
    first = vault.active_epoch
    second = vault.rotate(RotationReason.SECURITY_EVENT)
    assert first.inner.key != first.outer.key
    assert second.inner.key != second.outer.key
    assert first.inner.key != second.inner.key
    assert first.outer.key != second.outer.key
