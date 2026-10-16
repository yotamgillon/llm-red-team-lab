"""Per-client token-bucket rate limiter (SECURE_MODE, LLM10).

Real, model-independent code. The client key is the socket peer address; proxy headers such as
``X-Forwarded-For`` are deliberately ignored because a client could forge them.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

MAX_TRACKED_CLIENTS = 10_000


class TokenBucketLimiter:
    """Each client holds ``capacity`` tokens, refilled at ``refill_per_second``; one per request."""

    def __init__(
        self,
        capacity: int,
        refill_per_second: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if capacity < 1 or refill_per_second <= 0:
            raise ValueError("capacity must be >= 1 and refill_per_second > 0")
        self._capacity = float(capacity)
        self._rate = refill_per_second
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def check(self, key: str) -> tuple[bool, int]:
        """Spend one token for ``key``. Return ``(allowed, retry_after_seconds)``."""
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.pop(key, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - last) * self._rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > MAX_TRACKED_CLIENTS:
                self._buckets.popitem(last=False)  # bound memory: drop the stalest client
        retry = 0 if allowed else max(1, math.ceil((1.0 - tokens) / self._rate))
        return allowed, retry

    def reset(self) -> None:
        """Forget every client (used by the lab reset endpoint between scanner attacks)."""
        with self._lock:
            self._buckets.clear()
