package admission

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/example/gowafyourself/internal/metrics"
)

func newTestController(limit, queue, timeoutMs int) *Controller {
	return New(limit, queue, timeoutMs, metrics.New())
}

// TestNeverExceedsLimit is the hard invariant: no matter how much load arrives,
// the number of simultaneous holders never exceeds the configured limit.
func TestNeverExceedsLimit(t *testing.T) {
	const limit = 8
	c := newTestController(limit, 64, 500)

	var cur, max atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, ok := c.Acquire(context.Background())
			if !ok {
				return
			}
			defer release()
			n := cur.Add(1)
			for {
				m := max.Load()
				if n <= m || max.CompareAndSwap(m, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			cur.Add(-1)
		}()
	}
	wg.Wait()

	if got := max.Load(); got > limit {
		t.Fatalf("concurrency exceeded limit: peak %d > %d", got, limit)
	}
	if inflight, _, _, _ := c.Stats(); inflight != 0 {
		t.Fatalf("in-flight leaked: %d still held", inflight)
	}
	if c.Available() != limit {
		t.Fatalf("token leak: %d available, want %d", c.Available(), limit)
	}
}

// TestQueueFullSheds verifies that load past capacity+queue is rejected rather
// than queued indefinitely.
func TestQueueFullSheds(t *testing.T) {
	c := newTestController(1, 1, 2000)

	r1, ok := c.Acquire(context.Background())
	if !ok {
		t.Fatal("first acquire should succeed")
	}
	defer r1()

	// One goroutine occupies the single queue slot.
	entered := make(chan struct{})
	go func() {
		close(entered)
		if r, ok := c.Acquire(context.Background()); ok {
			r()
		}
	}()
	<-entered
	time.Sleep(50 * time.Millisecond)

	// The next arrival finds both the slot and the queue occupied.
	done := make(chan bool, 1)
	go func() {
		_, ok := c.Acquire(context.Background())
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("expected the request to be shed when the queue is full")
		}
	case <-time.After(time.Second):
		t.Fatal("shed decision should be immediate, not a wait")
	}
}

// TestWaitTimeoutSheds verifies a queued request gives up at the deadline.
func TestWaitTimeoutSheds(t *testing.T) {
	c := newTestController(1, 4, 60)

	release, ok := c.Acquire(context.Background())
	if !ok {
		t.Fatal("first acquire should succeed")
	}
	defer release() // held for the duration, so the waiter must time out

	start := time.Now()
	_, ok = c.Acquire(context.Background())
	elapsed := time.Since(start)
	if ok {
		t.Fatal("expected the queued request to be shed at its deadline")
	}
	if elapsed < 40*time.Millisecond {
		t.Fatalf("gave up too early: %v", elapsed)
	}
	if elapsed > 800*time.Millisecond {
		t.Fatalf("waited well past the timeout: %v", elapsed)
	}
}

// TestContextCancelSheds verifies a disconnected client stops waiting.
func TestContextCancelSheds(t *testing.T) {
	c := newTestController(1, 4, 5000)
	release, _ := c.Acquire(context.Background())
	defer release()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, ok := c.Acquire(ctx); ok {
		t.Fatal("expected acquire to abort when the caller's context is cancelled")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("cancellation did not interrupt the wait")
	}
}

// TestGrowAddsCapacityImmediately mirrors test_admission_grow in the model.
func TestGrowAddsCapacityImmediately(t *testing.T) {
	c := newTestController(2, 0, 10)

	r1, _ := c.Acquire(context.Background())
	r2, _ := c.Acquire(context.Background())
	defer r1()
	defer r2()

	if _, ok := c.Acquire(context.Background()); ok {
		t.Fatal("should be at capacity before growing")
	}
	if err := c.SetLimit(4); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	r3, ok := c.Acquire(context.Background())
	if !ok {
		t.Fatal("growing should make capacity available immediately")
	}
	r3()
}

// TestShrinkDrainsWithoutInterrupting mirrors test_admission_shrink_drains:
// shrinking must not kill in-flight work; capacity contracts as it finishes.
func TestShrinkDrainsWithoutInterrupting(t *testing.T) {
	c := newTestController(4, 0, 10)

	releases := make([]func(), 0, 4)
	for i := 0; i < 4; i++ {
		r, ok := c.Acquire(context.Background())
		if !ok {
			t.Fatalf("acquire %d should succeed", i)
		}
		releases = append(releases, r)
	}

	if err := c.SetLimit(1); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	if got := c.Debt(); got != 3 {
		t.Fatalf("expected debt 3 after shrinking 4->1 with none idle, got %d", got)
	}
	if inflight, _, _, _ := c.Stats(); inflight != 4 {
		t.Fatalf("shrink must not terminate in-flight work, have %d", inflight)
	}

	for _, r := range releases {
		r()
	}
	if got := c.Debt(); got != 0 {
		t.Fatalf("debt should be paid off after releases, got %d", got)
	}
	if got := c.Available(); got != 1 {
		t.Fatalf("capacity should settle at the new limit, got %d available", got)
	}

	// The new ceiling is now enforced.
	r1, ok := c.Acquire(context.Background())
	if !ok {
		t.Fatal("one slot should be available at the new limit")
	}
	defer r1()
	if _, ok := c.Acquire(context.Background()); ok {
		t.Fatal("post-shrink concurrency must respect the new limit")
	}
}

// TestShrinkReclaimsIdleFirst mirrors test_admission_shrink_partial_idle.
func TestShrinkReclaimsIdleFirst(t *testing.T) {
	c := newTestController(4, 0, 10)
	r1, _ := c.Acquire(context.Background())
	r2, _ := c.Acquire(context.Background())

	if err := c.SetLimit(1); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	if got := c.Available(); got != 0 {
		t.Fatalf("idle capacity should be reclaimed at once, got %d", got)
	}
	if got := c.Debt(); got != 1 {
		t.Fatalf("only the shortfall should become debt, got %d", got)
	}
	r1()
	r2()
	if got := c.Available(); got != 1 {
		t.Fatalf("should settle at the new limit, got %d", got)
	}
}

// TestResizeChurnDoesNotLeak mirrors test_admission_resize_no_leak.
func TestResizeChurnDoesNotLeak(t *testing.T) {
	c := newTestController(8, 32, 50)
	plan := []int{3, 12, 1, 16, 4, 8}

	var wg sync.WaitGroup
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if r, ok := c.Acquire(context.Background()); ok {
				time.Sleep(time.Millisecond)
				r()
			}
		}(i)
		if i%25 == 0 {
			if err := c.SetLimit(plan[(i/25)%len(plan)]); err != nil {
				t.Errorf("SetLimit: %v", err)
			}
		}
	}
	wg.Wait()

	if err := c.SetLimit(8); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	// Give any last releases a moment to settle their tokens.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Debt() == 0 && c.Available() == 8 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c.Debt() != 0 {
		t.Fatalf("debt should settle to 0, got %d", c.Debt())
	}
	if c.Available() != 8 {
		t.Fatalf("capacity should settle to the limit, got %d", c.Available())
	}
	if inflight, _, _, _ := c.Stats(); inflight != 0 {
		t.Fatalf("in-flight should settle to 0, got %d", inflight)
	}
}

func TestSetLimitRejectsOutOfRange(t *testing.T) {
	c := newTestController(4, 4, 10)
	if err := c.SetLimit(0); err == nil {
		t.Fatal("expected an error for a limit below 1")
	}
	if err := c.SetLimit(MaxCapacity + 1); err == nil {
		t.Fatal("expected an error for a limit above MaxCapacity")
	}
	if c.Limit() != 4 {
		t.Fatalf("a rejected resize must not change the limit, got %d", c.Limit())
	}
}

// TestReleaseIsIdempotent guards the single-use contract: a double release must
// not fabricate capacity.
func TestReleaseIsIdempotent(t *testing.T) {
	c := newTestController(1, 0, 10)
	r, ok := c.Acquire(context.Background())
	if !ok {
		t.Fatal("acquire should succeed")
	}
	r()
	r()
	r()
	if got := c.Available(); got != 1 {
		t.Fatalf("repeated release must not mint tokens, got %d available", got)
	}
}
