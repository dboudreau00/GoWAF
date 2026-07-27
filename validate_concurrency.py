#!/usr/bin/env python3
"""
Validation harness for the pure-logic components that `go build` cannot check:

  1. Admission control -- bounded concurrency (live-resizable) + bounded queue + wait timeout
  2. Circuit breaker   -- rolling outcome window + threshold + cooldown/half-open

Both are modelled here as deterministic state machines and asserted against the
invariants the Go implementation must preserve. The Go code in
internal/admission and internal/breaker is a direct port of these models.

Run:  python3 validate_concurrency.py      (or: make validate)
"""
import collections

# ----------------------------------------------------------------------------
# 1. ADMISSION CONTROL  (token-semaphore model, live-resizable)
# ----------------------------------------------------------------------------
class Admission:
    """Mirrors internal/admission.Controller.

    Concurrency is represented by a pool of `tokens`. Acquiring takes a token;
    releasing returns one. The pool is pre-filled with `limit` tokens out of a
    hard ceiling `max_cap`, which is what makes the limit resizable at runtime:

      grow(k)   -> add k tokens to the pool
      shrink(k) -> remove k idle tokens now if any exist, and record the
                   remainder as `debt`; each subsequent release then retires a
                   token instead of returning it, until the debt is paid.

    The debt mechanism is why shrinking never blocks and never kills in-flight
    work: capacity contracts as requests naturally finish.
    """
    def __init__(self, limit, queue_size, max_cap=1 << 16):
        assert 0 < limit <= max_cap
        self.max_cap = max_cap
        self.limit = limit
        self.tokens = limit      # idle capacity
        self.debt = 0            # tokens to retire on release (pending shrink)
        self.inflight = 0
        self.queue_size = queue_size
        self.waiters = collections.deque()   # (id, enqueued_at)
        # instrumentation
        self.max_inflight = 0
        self.admitted = 0
        self.rejected_full = 0
        self.rejected_timeout = 0

    # -- core ----------------------------------------------------------------
    def arrive(self, token, now):
        if self.tokens > 0:
            self._enter()
            return "admitted"
        if len(self.waiters) < self.queue_size:
            self.waiters.append((token, now))
            return "queued"
        self.rejected_full += 1
        return "rejected_full"

    def _enter(self):
        assert self.tokens > 0
        self.tokens -= 1
        self.inflight += 1
        self.admitted += 1
        self.max_inflight = max(self.max_inflight, self.inflight)

    def complete(self, now, timeout):
        """A request finishes: return or retire its token, then promote a waiter."""
        assert self.inflight > 0, "complete() with no in-flight work => bug"
        self.inflight -= 1
        if self.debt > 0:
            self.debt -= 1        # retire this token to satisfy a pending shrink
        else:
            self.tokens += 1
        # drop timed-out waiters at the head, then promote one live waiter
        while self.waiters and self.tokens > 0:
            tok, enq = self.waiters[0]
            if now - enq > timeout:
                self.waiters.popleft()
                self.rejected_timeout += 1
                continue
            self.waiters.popleft()
            self._enter()
            break

    # -- runtime resize ------------------------------------------------------
    def resize(self, new_limit):
        assert 0 < new_limit <= self.max_cap
        delta = new_limit - self.limit
        if delta > 0:
            self.tokens += delta          # grow: capacity available immediately
        elif delta < 0:
            need = -delta
            take = min(need, self.tokens)
            self.tokens -= take           # reclaim idle capacity now
            self.debt += need - take      # reclaim the rest as requests finish
        self.limit = new_limit

    def drain(self):
        while self.waiters:
            self.waiters.popleft()
            self.rejected_timeout += 1


def test_admission_capacity():
    """Hard invariant: concurrency never exceeds the configured limit."""
    N, Q, T = 4, 8, 100
    a = Admission(N, Q)
    now = 0
    for i in range(200):
        now += 1
        a.arrive(i, now)
        if a.inflight > 0 and i % 3 == 0:
            a.complete(now, T)
    now += T + 10
    while a.inflight > 0:
        now += 1
        a.complete(now, T)
    a.drain()

    assert a.max_inflight <= N, f"concurrency exceeded limit: {a.max_inflight} > {N}"
    assert a.inflight == 0, "in-flight leaked => semaphore would deadlock"
    assert a.tokens == N, f"token leak: {a.tokens} != {N}"
    assert a.rejected_full > 0, "expected hard rejections under sustained overload"
    print(f"  capacity: max_inflight={a.max_inflight} (cap {N}), admitted={a.admitted}, "
          f"shed_full={a.rejected_full}, shed_timeout={a.rejected_timeout}")


def test_admission_timeout():
    """Waiters past the timeout are shed, never admitted late."""
    N, Q, T = 1, 4, 50
    a = Admission(N, Q)
    a.arrive(0, 0)      # takes the only slot
    a.arrive(1, 1)      # queued
    a.arrive(2, 2)      # queued
    a.complete(200, T)  # slot frees long after the timeout
    assert a.rejected_timeout == 2, f"expected 2 timeouts, got {a.rejected_timeout}"
    assert a.inflight == 0, "no waiter should be promoted after its deadline"
    print("  timeout: stale waiters shed rather than admitted late")


def test_admission_grow():
    """Growing the limit makes capacity available immediately."""
    a = Admission(2, 4)
    a.arrive(0, 0); a.arrive(1, 1)          # both slots taken
    assert a.arrive(2, 2) == "queued", "should queue at capacity"
    a.resize(4)                              # grow
    assert a.arrive(3, 3) == "admitted", "grow should free capacity at once"
    assert a.max_inflight <= 4
    print(f"  grow: 2 -> 4 admitted immediately, max_inflight={a.max_inflight}")


def test_admission_shrink_drains():
    """Shrinking never kills in-flight work; capacity contracts as requests finish."""
    a = Admission(4, 4)
    for i in range(4):
        a.arrive(i, i)                       # 4 in flight, 0 idle
    assert a.inflight == 4 and a.tokens == 0
    a.resize(1)                              # shrink with nothing idle to reclaim
    assert a.debt == 3, f"expected debt=3, got {a.debt}"
    assert a.inflight == 4, "shrink must not terminate in-flight requests"
    # as requests finish, tokens are retired rather than returned
    a.complete(10, 100); a.complete(11, 100); a.complete(12, 100)
    assert a.debt == 0, f"debt should be paid off, got {a.debt}"
    assert a.tokens == 0, f"no idle tokens should exist yet, got {a.tokens}"
    a.complete(13, 100)                      # last one finishes
    assert a.inflight == 0
    assert a.tokens == 1, f"steady state should hold exactly the new limit, got {a.tokens}"
    # and the new ceiling is now enforced
    a.arrive(90, 20); a.arrive(91, 21)
    assert a.inflight == 1, "post-shrink concurrency must respect the new limit"
    print("  shrink: 4 -> 1 drained via debt, in-flight preserved, new ceiling enforced")


def test_admission_shrink_partial_idle():
    """Shrink reclaims idle capacity immediately and only defers the remainder."""
    a = Admission(4, 4)
    a.arrive(0, 0); a.arrive(1, 1)           # 2 in flight, 2 idle
    a.resize(1)                               # need 3 back; 2 are idle
    assert a.tokens == 0, f"idle tokens should be reclaimed at once, got {a.tokens}"
    assert a.debt == 1, f"only the shortfall becomes debt, got {a.debt}"
    a.complete(5, 100)
    assert a.debt == 0 and a.tokens == 0
    a.complete(6, 100)
    assert a.tokens == 1, "settles at the new limit"
    print("  shrink: idle capacity reclaimed immediately, only shortfall deferred")


def test_admission_resize_no_leak():
    """Repeated resizing under load must not leak or fabricate capacity."""
    a = Admission(8, 16)
    now = 0
    plan = [3, 12, 1, 16, 4, 8]
    for i in range(400):
        now += 1
        a.arrive(i, now)
        if i % 5 == 0:
            a.resize(plan[(i // 5) % len(plan)])
        if a.inflight > 0 and i % 2 == 0:
            a.complete(now, 100)
    while a.inflight > 0:
        now += 1
        a.complete(now, 100)
    a.drain()
    a.resize(8)
    assert a.debt == 0, f"debt should settle to 0, got {a.debt}"
    assert a.tokens == 8, f"capacity should settle to the limit, got {a.tokens}"
    assert a.inflight == 0
    print("  resize churn: 400 requests across 6 limit changes, no capacity leak")


# ----------------------------------------------------------------------------
# 2. CIRCUIT BREAKER
# ----------------------------------------------------------------------------
class Breaker:
    """Mirrors internal/breaker: rolling window of the last W outcomes. Trips
    OPEN when the error ratio exceeds the threshold once >= min_samples are
    seen. After cooldown a single HALF-OPEN probe decides on its own outcome."""
    CLOSED, OPEN, HALF = "closed", "open", "half"

    def __init__(self, W, threshold, min_samples, cooldown):
        self.W, self.threshold = W, threshold
        self.min_samples, self.cooldown = min_samples, cooldown
        self.win = collections.deque(maxlen=W)
        self.state = self.CLOSED
        self.opened_at = None

    def allow(self, now):
        if self.state == self.OPEN:
            if now - self.opened_at >= self.cooldown:
                self.state = self.HALF
                return True
            return False
        return True

    def record(self, ok, now):
        self.win.append(0 if ok else 1)
        if len(self.win) < self.min_samples:
            return
        if self.state == self.HALF:
            # The probe's own outcome is decisive. The stale pre-cooldown window
            # must NOT prevent re-closing -- this was a real bug caught here.
            if ok:
                self.state = self.CLOSED
                self.win.clear()
            else:
                self.state = self.OPEN
                self.opened_at = now
            return
        if self.state == self.CLOSED:
            if sum(self.win) / len(self.win) > self.threshold:
                self.state = self.OPEN
                self.opened_at = now


def test_breaker():
    b = Breaker(W=10, threshold=0.5, min_samples=5, cooldown=1000)
    now = 0
    for _ in range(10):
        now += 1; b.record(True, now)
    assert b.state == Breaker.CLOSED and b.allow(now)
    for _ in range(10):
        now += 1; b.record(False, now)
    assert b.state == Breaker.OPEN, f"should be OPEN, is {b.state}"
    assert not b.allow(now), "open breaker must reject before cooldown"
    now += 500
    assert not b.allow(now), "still inside cooldown"
    now += 600
    assert b.allow(now) and b.state == Breaker.HALF, "cooldown elapsed => probe allowed"
    now += 1; b.record(True, now)
    assert b.state == Breaker.CLOSED, f"healthy probe should re-close, is {b.state}"
    print("  breaker: opens on faults, blocks during cooldown, probes, re-closes on recovery")


def test_breaker_failed_probe_reopens():
    b = Breaker(W=10, threshold=0.5, min_samples=5, cooldown=100)
    now = 0
    for _ in range(10):
        now += 1; b.record(False, now)
    assert b.state == Breaker.OPEN
    now += 200
    assert b.allow(now) and b.state == Breaker.HALF
    now += 1; b.record(False, now)
    assert b.state == Breaker.OPEN, "failed probe must re-open"
    assert not b.allow(now), "and the cooldown clock must restart"
    print("  breaker: failed probe re-opens and restarts the cooldown")


def test_breaker_flap_guard():
    b = Breaker(W=20, threshold=0.5, min_samples=5, cooldown=1000)
    now = 0
    for i in range(20):
        now += 1; b.record(ok=(i != 7), now=now)
    assert b.state == Breaker.CLOSED, "an isolated error must not trip the breaker"
    print("  breaker: isolated errors don't trip it")


if __name__ == "__main__":
    print("Admission control:")
    test_admission_capacity()
    test_admission_timeout()
    test_admission_grow()
    test_admission_shrink_drains()
    test_admission_shrink_partial_idle()
    test_admission_resize_no_leak()
    print("Circuit breaker:")
    test_breaker()
    test_breaker_failed_probe_reopens()
    test_breaker_flap_guard()
    print("\nALL INVARIANTS PASSED")
