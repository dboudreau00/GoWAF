// Package admission implements capacity-based admission control: at most
// `limit` requests are allowed in flight through the WAF and upstream at once.
// When saturated, further requests wait in a bounded queue for up to a timeout;
// beyond that they are shed with 503 so the service degrades gracefully instead
// of collapsing.
//
// Capacity is a pool of tokens held in a buffered channel sized to a fixed
// ceiling (MaxCapacity). Acquiring takes a token, releasing returns one, and the
// limit is changed at runtime by adding or retiring tokens -- which is what
// makes maxConcurrent tunable without a restart.
//
// This logic is a direct port of the model in validate_concurrency.py, which
// asserts the invariants: concurrency never exceeds the limit, overload is shed
// (queue-full and wait-timeout), shrinking never terminates in-flight work, and
// repeated resizing leaks no capacity.
package admission

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/gowafyourself/internal/metrics"
)

// MaxCapacity is the hard ceiling on maxConcurrent. The backing channel is
// allocated at this size up front; because the element type is zero-width, a
// large capacity costs no additional memory.
const MaxCapacity = 65536

type Controller struct {
	sem chan struct{} // holds one token per unit of *available* capacity

	// resize state
	mu    sync.Mutex   // serializes resizes
	limit atomic.Int32 // current configured concurrency limit
	debt  atomic.Int32 // tokens still to retire to complete a pending shrink

	maxWait  atomic.Int32 // queue capacity
	timeout  atomic.Int64 // queue wait timeout, in nanoseconds
	waiting  atomic.Int32 // requests currently waiting for a slot
	inflight atomic.Int32 // requests currently holding a slot

	m *metrics.Metrics
}

// New builds a controller. maxConcurrent is clamped to [1, MaxCapacity].
func New(maxConcurrent, queueSize, timeoutMs int, m *metrics.Metrics) *Controller {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if maxConcurrent > MaxCapacity {
		maxConcurrent = MaxCapacity
	}
	if queueSize < 0 {
		queueSize = 0
	}
	c := &Controller{sem: make(chan struct{}, MaxCapacity), m: m}
	c.limit.Store(int32(maxConcurrent))
	c.maxWait.Store(int32(queueSize))
	c.timeout.Store(int64(time.Duration(timeoutMs) * time.Millisecond))
	// Pre-fill the pool with the starting capacity.
	for i := 0; i < maxConcurrent; i++ {
		c.sem <- struct{}{}
	}
	return c
}

// Acquire obtains a slot. It returns (release, true) on success; the caller MUST
// invoke release exactly once (defer it). It returns (nil, false) when the
// request is shed -- the queue is full, the wait timed out, or the client
// disconnected.
func (c *Controller) Acquire(ctx context.Context) (func(), bool) {
	// Fast path: capacity is immediately available.
	select {
	case <-c.sem:
		c.inflight.Add(1)
		c.m.IncInflight()
		return c.releaser(), true
	default:
	}

	// Saturated: try to enter the bounded waiting room.
	w := c.waiting.Add(1)
	c.m.SetQueued(int(w))
	if w > c.maxWait.Load() {
		c.waiting.Add(-1)
		c.m.SetQueued(int(c.waiting.Load()))
		return nil, false // queue full -> shed
	}
	defer func() {
		c.waiting.Add(-1)
		c.m.SetQueued(int(c.waiting.Load()))
	}()

	timer := time.NewTimer(time.Duration(c.timeout.Load()))
	defer timer.Stop()
	select {
	case <-c.sem:
		c.inflight.Add(1)
		c.m.IncInflight()
		return c.releaser(), true
	case <-timer.C:
		return nil, false // waited too long -> shed
	case <-ctx.Done():
		return nil, false // client gave up
	}
}

// releaser returns a single-use function that gives the slot back.
func (c *Controller) releaser() func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			c.returnToken()
			c.inflight.Add(-1)
			c.m.DecInflight()
		})
	}
}

// returnToken hands capacity back to the pool -- unless a shrink is pending, in
// which case the token is retired instead, which is how the limit contracts
// without interrupting in-flight requests.
func (c *Controller) returnToken() {
	for {
		d := c.debt.Load()
		if d <= 0 {
			break
		}
		if c.debt.CompareAndSwap(d, d-1) {
			return // token retired to satisfy a pending shrink
		}
	}
	select {
	case c.sem <- struct{}{}:
	default:
		// Unreachable: the channel is sized to MaxCapacity and we never hold
		// more tokens than that. Dropping here would leak capacity, so it is
		// deliberately a no-op rather than a block.
	}
}

// SetLimit changes maxConcurrent at runtime.
//
// Growing makes capacity available immediately (and first cancels any pending
// shrink). Shrinking reclaims idle tokens right away and defers the remainder
// as debt, so in-flight requests are never terminated -- capacity contracts as
// they finish.
//
// Note: a release racing an in-progress shrink can leave the effective ceiling
// transiently above the new limit by at most the number of concurrent releases.
// It self-corrects as the debt is paid. Keeping the release path lock-free is
// worth that small transient, since resizing is a rare operator action while
// releasing happens on every request.
func (c *Controller) SetLimit(newLimit int) error {
	if newLimit < 1 {
		return fmt.Errorf("admission: maxConcurrent must be >= 1")
	}
	if newLimit > MaxCapacity {
		return fmt.Errorf("admission: maxConcurrent must be <= %d", MaxCapacity)
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	delta := newLimit - int(c.limit.Load())
	switch {
	case delta > 0:
		// Cancel outstanding debt before minting new tokens.
		for delta > 0 {
			d := c.debt.Load()
			if d <= 0 {
				break
			}
			pay := d
			if int(pay) > delta {
				pay = int32(delta)
			}
			if c.debt.CompareAndSwap(d, d-pay) {
				delta -= int(pay)
			}
		}
		for i := 0; i < delta; i++ {
			select {
			case c.sem <- struct{}{}:
			default:
			}
		}
	case delta < 0:
		need := -delta
		for need > 0 {
			select {
			case <-c.sem: // reclaim an idle token immediately
				need--
			default:
				c.debt.Add(int32(need)) // reclaim the rest as requests finish
				need = 0
			}
		}
	}
	c.limit.Store(int32(newLimit))
	return nil
}

// SetQueue changes the waiting-room depth and wait timeout at runtime.
func (c *Controller) SetQueue(queueSize, timeoutMs int) {
	if queueSize < 0 {
		queueSize = 0
	}
	if timeoutMs < 0 {
		timeoutMs = 0
	}
	c.maxWait.Store(int32(queueSize))
	c.timeout.Store(int64(time.Duration(timeoutMs) * time.Millisecond))
}

// Stats reports current occupancy, for the control panel.
func (c *Controller) Stats() (inflight, waiting, limit, queueCap int) {
	return int(c.inflight.Load()), int(c.waiting.Load()),
		int(c.limit.Load()), int(c.maxWait.Load())
}

// Available reports idle capacity, and Debt reports capacity still to be
// reclaimed by a pending shrink. Both are exposed for tests and diagnostics.
func (c *Controller) Available() int { return len(c.sem) }
func (c *Controller) Debt() int      { return int(c.debt.Load()) }

// Limit returns the current concurrency limit.
func (c *Controller) Limit() int { return int(c.limit.Load()) }
