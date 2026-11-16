import pytest
from layer4.waf import WAFEngine, ViolationType


@pytest.fixture
def waf():
    return WAFEngine(max_body_bytes=1024)


def test_allowed_get_request(waf):
    res = waf.inspect_request(method="GET", path="/api/v1/status")
    assert res.allowed is True
    assert res.action == "ALLOW"
    assert res.risk == "LOW"


def test_disallowed_method(waf):
    res = waf.inspect_request(method="TRACE", path="/api/v1/status")
    assert res.allowed is False
    assert res.reason == ViolationType.METHOD_NOT_ALLOWED.value
    assert res.risk == "HIGH"


def test_path_traversal_detection(waf):
    # Plain traversal
    res = waf.inspect_request(method="GET", path="/static/../../etc/passwd")
    assert res.allowed is False
    assert res.reason == ViolationType.PATH_TRAVERSAL.value
    assert res.risk == "CRITICAL"

    # URL encoded traversal (%2e%2e%2f)
    res_enc = waf.inspect_request(method="GET", path="/files/%2e%2e%2f%2e%2e%2fetc/shadow")
    assert res_enc.allowed is False
    assert res_enc.reason == ViolationType.PATH_TRAVERSAL.value


def test_null_byte_injection(waf):
    res = waf.inspect_request(method="GET", path="/download/report.pdf%00.exe")
    assert res.allowed is False
    assert res.reason == ViolationType.PATH_TRAVERSAL.value
    assert "null_byte_injection" in res.violations


def test_probe_blocking(waf):
    res = waf.inspect_request(method="GET", path="/.env")
    assert res.allowed is False
    assert res.reason == ViolationType.SENSITIVE_PROBE.value

    res_git = waf.inspect_request(method="GET", path="/.git/config")
    assert res_git.allowed is False
    assert res_git.reason == ViolationType.SENSITIVE_PROBE.value


def test_sql_injection_detection(waf):
    payload = "id=1' OR '1'='1"
    res = waf.inspect_request(method="POST", path="/api/search", body=payload, content_type="application/json")
    assert res.allowed is False
    assert res.reason == ViolationType.SQL_INJECTION.value
    assert res.risk == "CRITICAL"

    union_payload = "1 UNION SELECT * FROM users"
    res_union = waf.inspect_request(method="POST", path="/api/query", body=union_payload, content_type="application/json")
    assert res_union.allowed is False
    assert res_union.reason == ViolationType.SQL_INJECTION.value


def test_xss_detection(waf):
    payload = "<script>alert('xss')</script>"
    res = waf.inspect_request(method="POST", path="/api/comments", body=payload, content_type="application/json")
    assert res.allowed is False
    assert res.reason == ViolationType.XSS_ATTACK.value
    assert res.risk == "HIGH"

    img_xss = "<img src=x onerror=alert(1)>"
    res_img = waf.inspect_request(method="POST", path="/api/comments", body=img_xss, content_type="application/json")
    assert res_img.allowed is False
    assert res_img.reason == ViolationType.XSS_ATTACK.value


def test_payload_size_enforcement(waf):
    large_payload = "A" * 2048
    res = waf.inspect_request(method="POST", path="/api/upload", body=large_payload, content_type="application/json")
    assert res.allowed is False
    assert res.reason == ViolationType.PAYLOAD_TOO_LARGE.value


def test_content_type_enforcement(waf):
    # Mutation without content-type
    res = waf.inspect_request(method="POST", path="/api/data", body="{'data': 1}", content_type="")
    assert res.allowed is False
    assert res.reason == ViolationType.INVALID_CONTENT_TYPE.value
