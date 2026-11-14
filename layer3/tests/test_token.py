import time
import jwt
from sentinel.identity import TokenVerifier, IdentityError


def test_hs256_test_token_verifies():
    now = int(time.time())
    token = jwt.encode({"sub":"u1","iss":"https://issuer","aud":"sentinel","iat":now,"exp":now+60,"roles":["developer"],"scope":"read write"}, "test-secret-0123456789-0123456789", algorithm="HS256")
    v = TokenVerifier(issuer="https://issuer", audience="sentinel", secret="test-secret-0123456789-0123456789", algorithms=("HS256",))
    i = v.verify(token)
    assert i.subject == "u1"
    assert "write" in i.scopes


def test_missing_secret_is_not_accepted():
    v = TokenVerifier(issuer="https://issuer", audience="sentinel")
    try:
        v.verify("anything")
    except IdentityError as e:
        assert str(e) == "oidc_jwks_not_configured"
    else:
        assert False
