import time
from sentinel.identity import Identity, IdentityPolicy, SessionRegistry


def test_viewer_read_allowed():
    p = IdentityPolicy()
    i = Identity("u1", frozenset({"viewer"}), frozenset())
    assert p.authorize(i, required_scope="read", resource="project:1", zone="user")[0]


def test_deny_unknown_scope():
    p = IdentityPolicy()
    i = Identity("u1", frozenset({"viewer"}), frozenset())
    assert not p.authorize(i, required_scope="write", resource="project:1", zone="user")[0]


def test_management_requires_admin():
    p = IdentityPolicy()
    i = Identity("u1", frozenset({"developer"}), frozenset())
    assert p.authorize(i, required_scope="read", resource="management:config", zone="management")[1] == "management_requires_admin"


def test_privileged_requires_recent_mfa():
    p = IdentityPolicy()
    i = Identity("u1", frozenset({"admin"}), frozenset(), auth_time=int(time.time()), amr=frozenset({"webauthn"}))
    assert p.authorize(i, required_scope="admin", resource="management:config", zone="management", privileged=True)[0]


def test_privileged_rejects_old_step_up():
    p = IdentityPolicy()
    i = Identity("u1", frozenset({"admin"}), frozenset(), auth_time=int(time.time()) - 1000, amr=frozenset({"webauthn"}))
    assert p.authorize(i, required_scope="admin", resource="management:config", zone="management", privileged=True)[1] == "step_up_auth_required"


def test_revocation_blocks_identity():
    sessions = SessionRegistry()
    i = Identity("u1", frozenset({"admin"}), frozenset({"admin"}), token_id="tok-1")
    sessions.revoke_token("tok-1")
    assert sessions.is_revoked(i)
