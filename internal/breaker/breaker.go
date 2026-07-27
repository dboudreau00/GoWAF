// Package breaker implements a per-backend circuit breaker over a rolling
// window of request outcomes. It trips OPEN when the recent error ratio exceeds
// a threshold, fast-fails while OPEN, then permits a single HALF-OPEN probe
// after a cooldown; a healthy probe re-closes it.
//
// The state machine (including the half-open reset that validate_concurrency.py
// caught as a bug) is mirrored from that validated model.
package breaker

import (
	"sync"
	"time"

	"github.com/example/gowafyourself/internal/config"
	"github.com/example/gowafyourself/internal/metrics"
)

type State int

const (
	Closed State = iota
	Open
	HalfOpen
)

func (s State) String() string {
	switch s {
	case Open:
		return "open"
	case HalfOpen:
		return "half-open"
	default:
		return "closed"
	}
}

type breaker struct {
	mu        sync.Mutex
	ring      []uint8 // 0=ok, 1=fail
	idx       int
	filled    int
	fails     int
	state     State
	openedAt  time.Time
	size      int
	threshold float64
	minReq    int
	cooldown  time.Duration
}

func newBreaker(size int, threshold float64, minReq int, cooldown time.Duration) *breaker {
	if size < 1 {
		size = 1
	}
	return &breaker{
		ring:      make([]uint8, size),
		size:      size,
		threshold: threshold,
		minReq:    minReq,
		cooldown:  cooldown,
		state:     Closed,
	}
}

func (b *breaker) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == Open {
		if now.Sub(b.openedAt) >= b.cooldown {
			b.state = HalfOpen // permit exactly one probe
			return true
		}
		return false
	}
	return true
}

func (b *breaker) record(ok bool, now time.Time) State {
	b.mu.Lock()
	defer b.mu.Unlock()

	var v uint8
	if !ok {
		v = 1
	}
	b.fails += int(v) - int(b.ring[b.idx])
	b.ring[b.idx] = v
	b.idx = (b.idx + 1) % b.size
	if b.filled < b.size {
		b.filled++
	}

	// A half-open probe is decisive on its own outcome: success closes and
	// resets the window; failure re-opens. The stale pre-cooldown window must
	// not influence this decision.
	if b.state == HalfOpen {
		if ok {
			b.reset()
			b.state = Closed
		} else {
			b.state = Open
			b.openedAt = now
		}
		return b.state
	}

	if b.state == Closed && b.filled >= b.minReq {
		if float64(b.fails)/float64(b.filled) > b.threshold {
			b.state = Open
			b.openedAt = now
		}
	}
	return b.state
}

func (b *breaker) reset() {
	for i := range b.ring {
		b.ring[i] = 0
	}
	b.idx, b.filled, b.fails = 0, 0, 0
}

func (b *breaker) currentState() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Group manages one breaker per backend key.
type Group struct {
	mu       sync.RWMutex
	breakers map[string]*breaker
	cfg      config.BreakerConfig
	m        *metrics.Metrics
}

func NewGroup(cfg config.BreakerConfig, m *metrics.Metrics) *Group {
	return &Group{breakers: map[string]*breaker{}, cfg: cfg, m: m}
}

func (g *Group) get(key string) *breaker {
	g.mu.RLock()
	b := g.breakers[key]
	cfg := g.cfg
	g.mu.RUnlock()
	if b != nil {
		return b
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if b = g.breakers[key]; b != nil {
		return b
	}
	b = newBreaker(cfg.WindowSize, cfg.ErrorThreshold, cfg.MinRequests,
		time.Duration(cfg.CooldownMs)*time.Millisecond)
	g.breakers[key] = b
	g.m.SetBreakerState(key, b.state.String())
	return b
}

// Allow reports whether a request to the backend should proceed. When the
// breaker is disabled it always allows.
func (g *Group) Allow(key string) bool {
	if !g.cfg.Enabled {
		return true
	}
	return g.get(key).allow(time.Now())
}

// Record feeds an outcome for the backend and publishes any state change.
func (g *Group) Record(key string, ok bool) {
	if !g.cfg.Enabled {
		return
	}
	st := g.get(key).record(ok, time.Now())
	g.m.SetBreakerState(key, st.String())
}

// State returns the current breaker state string for a backend.
func (g *Group) State(key string) string {
	if !g.cfg.Enabled {
		return "disabled"
	}
	return g.get(key).currentState().String()
}

// UpdateConfig swaps in new breaker settings (used on hot-reload). Existing
// per-backend state is cleared so new thresholds take effect cleanly.
func (g *Group) UpdateConfig(cfg config.BreakerConfig) {
	g.mu.Lock()
	g.cfg = cfg
	g.breakers = map[string]*breaker{}
	g.mu.Unlock()
}
