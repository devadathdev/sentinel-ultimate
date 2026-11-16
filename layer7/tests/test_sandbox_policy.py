"""Unit tests for Layer 7 Sandbox Policy Engine and Execution Tickets."""
import time
from layer7.sandbox_policy import SandboxPolicyEngine, ExecutionTicket


def test_missing_identity_blocked():
    engine = SandboxPolicyEngine()
    decision = engine.authorize(identity="", role="admin", command="pytest", sandbox=True)
    assert not decision.allow
    assert decision.action == "BLOCK"
    assert "no_caller_identity" in decision.violations


def test_unsandboxed_execution_blocked():
    engine = SandboxPolicyEngine()
    decision = engine.authorize(identity="dev-alice", role="developer", command="pytest", sandbox=False)
    assert not decision.allow
    assert decision.action == "BLOCK"
    assert decision.risk == "CRITICAL"
    assert "unsandboxed_execution_forbidden" in decision.violations


def test_unauthorized_role_blocked():
    engine = SandboxPolicyEngine()
    decision = engine.authorize(identity="guest-user", role="viewer", command="pytest", sandbox=True)
    assert not decision.allow
    assert decision.action == "BLOCK"
    assert "role_cannot_execute" in decision.reason


def test_disallowed_command_blocked():
    engine = SandboxPolicyEngine()
    decision = engine.authorize(identity="dev-alice", role="developer", command="rm -rf /", sandbox=True)
    assert not decision.allow
    assert decision.action == "BLOCK"
    assert decision.risk in {"HIGH", "CRITICAL"}


def test_valid_sandboxed_command_generates_valid_ticket():
    engine = SandboxPolicyEngine(signing_secret="super-secret-key")
    decision = engine.authorize(
        identity="dev-alice",
        role="developer",
        command="pytest -v tests/test_api.py",
        sandbox=True,
        timeout_seconds=60,
    )
    assert decision.allow
    assert decision.action == "ALLOW"
    assert decision.ticket is not None
    assert decision.ticket.command == "pytest -v tests/test_api.py"
    assert decision.ticket.identity == "dev-alice"
    assert decision.ticket.role == "developer"
    assert len(decision.ticket.signature) == 64  # sha256 hex string
    assert engine.verify_ticket(decision.ticket) is True


def test_ticket_tampering_rejected():
    engine = SandboxPolicyEngine(signing_secret="super-secret-key")
    decision = engine.authorize(
        identity="dev-alice",
        role="developer",
        command="pytest",
        sandbox=True,
    )
    assert decision.ticket is not None

    # Tamper with the command
    tampered_ticket = ExecutionTicket(
        ticket_id=decision.ticket.ticket_id,
        command="rm -rf /",
        identity=decision.ticket.identity,
        role=decision.ticket.role,
        created_at=decision.ticket.created_at,
        expires_at=decision.ticket.expires_at,
        signature=decision.ticket.signature,
    )
    assert engine.verify_ticket(tampered_ticket) is False


def test_expired_ticket_fails_verification():
    engine = SandboxPolicyEngine(signing_secret="super-secret-key")
    expired_ticket = ExecutionTicket(
        ticket_id="tid-123",
        command="pytest",
        identity="dev-alice",
        role="developer",
        created_at=int(time.time()) - 200,
        expires_at=int(time.time()) - 100,
        signature="invalid-or-old",
    )
    assert engine.verify_ticket(expired_ticket) is False
