"""Layer 4 — Application Fortress: Zone-aware token-bucket rate limiter with progressive penalty box."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int
    is_penalized: bool = False
    penalty_remaining_seconds: int = 0


class ApplicationRateLimiter:
    """Provides sliding-window rate limiting with zone-specific quotas and malicious client penalties."""

    ZONE_LIMITS: dict[str, int] = {
        "user": 120,        # 120 req/min
        "ai": 300,          # 300 req/min for agent telemetry
        "server": 1200,     # 1200 req/min for backend services
        "iot": 30,          # 30 req/min for sensors/cameras
        "management": 60,   # 60 req/min for admin ops
    }

    def __init__(
        self,
        default_limit: int = 120,
        window_seconds: int = 60,
        penalty_duration_seconds: int = 300,
        zone_limits: dict[str, int] | None = None
    ) -> None:
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        self.penalty_duration_seconds = penalty_duration_seconds
        self.zone_limits = dict(self.ZONE_LIMITS) if zone_limits is None else zone_limits
        
        # Sliding-window hit timestamps: key -> deque([timestamps])
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        
        # Penalized entities: key -> penalty_until_timestamp
        self._penalties: dict[str, float] = {}

    def check(self, key: str, zone: str | None = None, cost: int = 1) -> RateLimitResult:
        now = time.time()

        # Check penalty box
        if key in self._penalties:
            penalty_until = self._penalties[key]
            if now < penalty_until:
                return RateLimitResult(
                    allowed=False,
                    limit=0,
                    remaining=0,
                    reset_seconds=int(penalty_until - now),
                    is_penalized=True,
                    penalty_remaining_seconds=int(penalty_until - now)
                )
            else:
                del self._penalties[key]

        limit = self.zone_limits.get(zone, self.default_limit) if zone else self.default_limit
        q = self._hits[key]

        # Prune hits outside window
        cutoff = now - self.window_seconds
        while q and q[0] <= cutoff:
            q.popleft()

        current_count = len(q)
        if current_count + cost > limit:
            # Over rate limit
            reset_sec = int(q[0] + self.window_seconds - now) if q else self.window_seconds
            return RateLimitResult(
                allowed=False,
                limit=limit,
                remaining=0,
                reset_seconds=max(1, reset_sec),
                is_penalized=False
            )

        # Record hit
        for _ in range(cost):
            q.append(now)

        remaining = max(0, limit - len(q))
        reset_sec = int(q[0] + self.window_seconds - now) if q else self.window_seconds

        return RateLimitResult(
            allowed=True,
            limit=limit,
            remaining=remaining,
            reset_seconds=max(1, reset_sec),
            is_penalized=False
        )

    def penalize(self, key: str, multiplier: int = 1) -> None:
        """Place key in penalty box for suspicious or malicious activity."""
        duration = self.penalty_duration_seconds * max(1, multiplier)
        self._penalties[key] = time.time() + duration

    def clear(self, key: str) -> None:
        """Reset counters and penalties for key."""
        self._hits.pop(key, None)
        self._penalties.pop(key, None)
