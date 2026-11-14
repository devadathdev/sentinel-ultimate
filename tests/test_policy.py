from sentinel.security import PolicyEngine

p = PolicyEngine()

def test_default_identity_denied():
    d = p.authorize(identity="", role="user", method="GET", path="/", body_size=0, zone="user")
    assert not d.allow

def test_safe_ai_tool_allowed():
    assert p.authorize_tool(identity="brahma", role="user", tool="read_project", approved=False).allow

def test_high_risk_requires_approval():
    d = p.authorize_tool(identity="brahma", role="developer", tool="shell", approved=False)
    assert d.action == "REQUIRE_APPROVAL"

def test_unsandboxed_execution_denied():
    d = p.authorize_execution(identity="brahma", role="admin", command="python -m pytest", sandbox=False)
    assert not d.allow
