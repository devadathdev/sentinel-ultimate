import time
import pytest
from layer4.rate_limiter import ApplicationRateLimiter


def test_within_rate_limit():
    limiter = ApplicationRateLimiter(default_limit=5, window_seconds=60)
    for _ in range(5):
        res = limiter.check("client-1")
        assert res.allowed is True
    
    # 6th request is rejected
    res_rejected = limiter.check("client-1")
    assert res_rejected.allowed is False
    assert res_rejected.remaining == 0


def test_zone_specific_limits():
    limiter = ApplicationRateLimiter()
    # IoT zone limit is 30
    assert limiter.ZONE_LIMITS["iot"] == 30
    # Server zone limit is 1200
    assert limiter.ZONE_LIMITS["server"] == 1200


def test_penalty_box():
    limiter = ApplicationRateLimiter(default_limit=10, penalty_duration_seconds=10)
    client = "malicious-actor"
    
    # Explicit penalty
    limiter.penalize(client, multiplier=1)
    
    res = limiter.check(client)
    assert res.allowed is False
    assert res.is_penalized is True
    assert res.penalty_remaining_seconds > 0

    # Clear penalty
    limiter.clear(client)
    res_after = limiter.check(client)
    assert res_after.allowed is True
