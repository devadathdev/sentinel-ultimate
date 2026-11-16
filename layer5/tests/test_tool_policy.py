import pytest
from layer5.tool_policy import AIToolPolicyEngine, ToolRiskTier


@pytest.fixture
def engine():
    return AIToolPolicyEngine()


def test_safe_tool_allowed(engine):
    dec = engine.evaluate(identity="brahma", role="user", tool="web_search")
    assert dec.allow is True
    assert dec.action == "ALLOW"
    assert dec.tier == ToolRiskTier.SAFE


def test_low_risk_role_check(engine):
    dec_dev = engine.evaluate(identity="brahma", role="developer", tool="read_file")
    assert dec_dev.allow is True

    dec_unauthed = engine.evaluate(identity="brahma", role="guest", tool="read_file")
    assert dec_unauthed.allow is False


def test_high_risk_approval_requirement(engine):
    # Without approval -> REQUIRE_APPROVAL
    dec = engine.evaluate(identity="brahma", role="developer", tool="shell", approved=False)
    assert dec.allow is False
    assert dec.action == "REQUIRE_APPROVAL"

    # With admin approval -> ALLOW
    dec_app = engine.evaluate(identity="brahma", role="admin", tool="shell", approved=True)
    assert dec_app.allow is True


def test_critical_dual_control(engine):
    # Single approver -> BLOCK
    dec_single = engine.evaluate(
        identity="brahma", role="admin", tool="delete_database",
        approvers=["admin-1"], mfa_verified=True
    )
    assert dec_single.allow is False
    assert dec_single.action == "BLOCK"

    # Dual distinct approvers with MFA -> ALLOW
    dec_dual = engine.evaluate(
        identity="brahma", role="admin", tool="delete_database",
        approvers=["admin-1", "admin-2"], mfa_verified=True
    )
    assert dec_dual.allow is True
    assert dec_dual.action == "ALLOW"


def test_deep_argument_threat_detection(engine):
    # Path traversal in args
    dec = engine.evaluate(
        identity="brahma", role="admin", tool="read_file",
        args={"path": "../../../etc/shadow"}, approved=True
    )
    assert dec.allow is False
    assert dec.action == "BLOCK"
    assert dec.reason == "threat_signature_detected_in_tool_args"
    assert dec.risk == "CRITICAL"
