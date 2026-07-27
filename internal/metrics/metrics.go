// Package metrics provides lock-free counters and gauges for the data plane.
// The hot path performs only atomic adds; the control panel reads a
// consistent-enough Snapshot for display.
package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// Verdict is the outcome recorded for a single request. The rolling window of
// these drives the decision strip in the control panel.
type Verdict uint8

const (
	VerdictNone Verdict = iota
	VerdictAllow
	VerdictDetect
	VerdictBlock
	VerdictShed
	VerdictError
)

func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictDetect:
		return "detect"
	case VerdictBlock:
		return "block"
	case VerdictShed:
		return "shed"
	case VerdictError:
		return "error"
	default:
		return "none"
	}
}

// VerdictWindow is how many recent request outcomes are retained for display.
const VerdictWindow = 120

type Metrics struct {
	startedAt time.Time

	// counters (monotonic)
	total          atomic.Int64
	blocked        atomic.Int64
	blockedResp    atomic.Int64 // response-phase blocks
	wouldBlock     atomic.Int64 // detect-mode matches
	queueRejected  atomic.Int64
	wafErrors      atomic.Int64
	wafPanics      atomic.Int64
	upstreamErr    atomic.Int64
	noRoute        atomic.Int64
	bypassed       atomic.Int64
	bytesIn        atomic.Int64
	bytesOut       atomic.Int64

	// gauges (current value)
	inflight atomic.Int64
	queued   atomic.Int64

	// per-backend breaker state, guarded by mu (read rarely, by the panel)
	mu       sync.RWMutex
	breakers map[string]string

	// rolling verdict ring, guarded by vmu
	vmu      sync.Mutex
	verdicts [VerdictWindow]Verdict
	vidx     int
	vfilled  int
}

func New() *Metrics {
	return &Metrics{startedAt: time.Now(), breakers: map[string]string{}}
}

func (m *Metrics) IncTotal()         { m.total.Add(1) }
func (m *Metrics) IncBlocked()       { m.blocked.Add(1) }
func (m *Metrics) IncBlockedResp()   { m.blockedResp.Add(1) }
func (m *Metrics) IncWouldBlock()    { m.wouldBlock.Add(1) }
func (m *Metrics) IncQueueRejected() { m.queueRejected.Add(1) }
func (m *Metrics) IncWAFError()      { m.wafErrors.Add(1) }
func (m *Metrics) IncWAFPanic()      { m.wafPanics.Add(1) }
func (m *Metrics) IncUpstreamErr()   { m.upstreamErr.Add(1) }
func (m *Metrics) IncNoRoute()       { m.noRoute.Add(1) }
func (m *Metrics) IncBypassed()      { m.bypassed.Add(1) }

func (m *Metrics) AddBytesIn(n int64)  { m.bytesIn.Add(n) }
func (m *Metrics) AddBytesOut(n int64) { m.bytesOut.Add(n) }

func (m *Metrics) IncInflight()    { m.inflight.Add(1) }
func (m *Metrics) DecInflight()    { m.inflight.Add(-1) }
func (m *Metrics) SetQueued(n int) { m.queued.Store(int64(n)) }

// WAFPanics exposes the running panic count (used by the auto-bypass valve).
func (m *Metrics) WAFPanics() int64 { return m.wafPanics.Load() }

func (m *Metrics) SetBreakerState(backend, state string) {
	m.mu.Lock()
	m.breakers[backend] = state
	m.mu.Unlock()
}

// RecordVerdict appends one request outcome to the rolling window.
func (m *Metrics) RecordVerdict(v Verdict) {
	m.vmu.Lock()
	m.verdicts[m.vidx] = v
	m.vidx = (m.vidx + 1) % VerdictWindow
	if m.vfilled < VerdictWindow {
		m.vfilled++
	}
	m.vmu.Unlock()
}

// recentVerdicts returns the window oldest-first.
func (m *Metrics) recentVerdicts() []string {
	m.vmu.Lock()
	defer m.vmu.Unlock()
	out := make([]string, 0, m.vfilled)
	start := (m.vidx - m.vfilled + VerdictWindow) % VerdictWindow
	for i := 0; i < m.vfilled; i++ {
		out = append(out, m.verdicts[(start+i)%VerdictWindow].String())
	}
	return out
}

// Snapshot is an immutable view of the metrics at a point in time.
type Snapshot struct {
	UptimeSeconds  int64             `json:"uptimeSeconds"`
	Total          int64             `json:"total"`
	Blocked        int64             `json:"blocked"`
	BlockedResp    int64             `json:"blockedResponse"`
	WouldBlock     int64             `json:"wouldBlock"`
	QueueRejected  int64             `json:"queueRejected"`
	WAFErrors      int64             `json:"wafErrors"`
	WAFPanics      int64             `json:"wafPanics"`
	UpstreamErr    int64             `json:"upstreamErrors"`
	NoRoute        int64             `json:"noRoute"`
	Bypassed       int64             `json:"bypassed"`
	BytesIn        int64             `json:"bytesIn"`
	BytesOut       int64             `json:"bytesOut"`
	Inflight       int64             `json:"inflight"`
	Queued         int64             `json:"queued"`
	Breakers       map[string]string `json:"breakers"`
	RecentVerdicts []string          `json:"recentVerdicts"`
}

func (m *Metrics) Snapshot() Snapshot {
	m.mu.RLock()
	br := make(map[string]string, len(m.breakers))
	for k, v := range m.breakers {
		br[k] = v
	}
	m.mu.RUnlock()
	return Snapshot{
		UptimeSeconds:  int64(time.Since(m.startedAt).Seconds()),
		Total:          m.total.Load(),
		Blocked:        m.blocked.Load(),
		BlockedResp:    m.blockedResp.Load(),
		WouldBlock:     m.wouldBlock.Load(),
		QueueRejected:  m.queueRejected.Load(),
		WAFErrors:      m.wafErrors.Load(),
		WAFPanics:      m.wafPanics.Load(),
		UpstreamErr:    m.upstreamErr.Load(),
		NoRoute:        m.noRoute.Load(),
		Bypassed:       m.bypassed.Load(),
		BytesIn:        m.bytesIn.Load(),
		BytesOut:       m.bytesOut.Load(),
		Inflight:       m.inflight.Load(),
		Queued:         m.queued.Load(),
		Breakers:       br,
		RecentVerdicts: m.recentVerdicts(),
	}
}
