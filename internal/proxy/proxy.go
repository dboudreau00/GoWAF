// Package proxy is the GoWAFyourself data plane. For every request it resolves
// the upstream by Host, applies admission control, runs request-phase WAF rules,
// load balances across healthy backends, proxies the request, runs response-phase
// rules on the way back, feeds the circuit breaker, and logs the outcome.
//
// "Bridge if malfunctioning" is realized three ways: a global bypass switch (with
// an optional auto-trip after N WAF panics) skips the WAF entirely, WAF evaluation
// fails open on any internal error or panic, and the per-backend circuit breaker
// fast-fails a sick upstream instead of hammering it.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/example/gowafyourself/internal/admission"
	"github.com/example/gowafyourself/internal/breaker"
	"github.com/example/gowafyourself/internal/config"
	"github.com/example/gowafyourself/internal/logstore"
	"github.com/example/gowafyourself/internal/metrics"
	"github.com/example/gowafyourself/internal/waf"
)

type ctxKey int

const stateCtxKey ctxKey = 0

// errResponseBlocked signals from ModifyResponse to ErrorHandler that the WAF
// rejected the upstream response (as opposed to a transport failure).
var errResponseBlocked = errors.New("response blocked by WAF")

// backendTarget is one resolved upstream backend.
type backendTarget struct {
	raw string
	url *url.URL
}

func backendKey(u *url.URL) string { return u.Scheme + "://" + u.Host }

// reqState is the per-request state shared between ServeHTTP and the
// ReverseProxy callbacks (Rewrite, ModifyResponse, ErrorHandler).
type reqState struct {
	target   *backendTarget
	tx       *waf.Tx
	mode     string
	result   *waf.Result // set when the response phase interrupts
	terminal string      // terminal action decided inside a callback
}

func stateFrom(ctx context.Context) *reqState {
	st, _ := ctx.Value(stateCtxKey).(*reqState)
	return st
}

// upstream holds the compiled routing state for one Host.
type upstream struct {
	host    string
	mode    string // effective WAF mode (block|detect|off)
	bypass  bool   // per-upstream bridge
	targets []*backendTarget
	rr      atomic.Uint32
	proxy   *httputil.ReverseProxy

	// WAF settings captured at build time; Rebuild() runs on every config
	// change, so these stay in step with the live config.
	inspectReqBody  bool
	maxReqBody      int64
	inspectResp     bool
	inspectRespBody bool
	maxRespBody     int64
}

// pick selects the next healthy backend (round-robin), consulting the breaker.
// Returns (nil,false) when every backend is open and none is ready to probe.
func (up *upstream) pick(g *breaker.Group) (*backendTarget, bool) {
	n := len(up.targets)
	start := int(up.rr.Add(1))
	for i := 0; i < n; i++ {
		t := up.targets[(start+i)%n]
		if g.Allow(backendKey(t.url)) {
			return t, true
		}
	}
	return nil, false
}

type runtimeState struct {
	hosts map[string]*upstream
}

// DataPlane is the top-level http.Handler for proxied traffic.
type DataPlane struct {
	cfg     *config.Manager
	metrics *metrics.Metrics
	admit   *admission.Controller
	breaker *breaker.Group
	logger  *logstore.Logger
	bt      *breakerTransport

	engine atomic.Pointer[waf.Engine] // swapped when rule-affecting config changes
	bypass atomic.Bool                // global bridge switch (operational, not persisted)
	rt     atomic.Pointer[runtimeState]
}

// SetEngine swaps in a newly built rule engine. In-flight requests keep using
// the engine they started with, since each holds its own transaction.
func (dp *DataPlane) SetEngine(e *waf.Engine) { dp.engine.Store(e) }

func NewDataPlane(mgr *config.Manager, m *metrics.Metrics, admit *admission.Controller,
	br *breaker.Group, engine *waf.Engine, logger *logstore.Logger) (*DataPlane, error) {
	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	dp := &DataPlane{cfg: mgr, metrics: m, admit: admit, breaker: br, logger: logger}
	dp.engine.Store(engine)
	dp.bt = &breakerTransport{base: base, br: br}
	if err := dp.Rebuild(); err != nil {
		return nil, err
	}
	return dp, nil
}

// Rebuild recompiles routing and proxy state from the current config. Called at
// startup and after every config change (SIGHUP reload or panel edit).
func (dp *DataPlane) Rebuild() error {
	cfg := dp.cfg.Get()
	hosts := make(map[string]*upstream, len(cfg.Upstreams))
	for _, uc := range cfg.Upstreams {
		up, err := dp.buildUpstream(uc, cfg)
		if err != nil {
			return err
		}
		hosts[strings.ToLower(uc.Host)] = up
	}
	dp.rt.Store(&runtimeState{hosts: hosts})
	return nil
}

func (dp *DataPlane) buildUpstream(uc config.UpstreamConfig, cfg *config.Config) (*upstream, error) {
	var targets []*backendTarget
	for _, raw := range uc.Backends() {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("proxy: upstream %q target %q: %w", uc.Host, raw, err)
		}
		targets = append(targets, &backendTarget{raw: raw, url: u})
	}
	up := &upstream{
		host:            uc.Host,
		mode:            cfg.EffectiveMode(uc),
		bypass:          uc.Bypass,
		targets:         targets,
		inspectReqBody:  cfg.WAF.InspectBody,
		maxReqBody:      cfg.WAF.MaxBodyBytes,
		inspectResp:     cfg.WAF.InspectResponse,
		inspectRespBody: cfg.WAF.InspectResponseBody,
		maxRespBody:     cfg.WAF.MaxResponseBodyBytes,
	}

	up.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			t := up.targets[0]
			if st := stateFrom(pr.In.Context()); st != nil && st.target != nil {
				t = st.target
			}
			pr.SetURL(t.url)
			pr.SetXForwarded()
			// Preserve the client's Host header for vhosted backends.
			pr.Out.Host = pr.In.Host
		},

		// Response-phase inspection happens here, on the same transaction that
		// evaluated the request, so CRS outbound rules score against inbound state.
		ModifyResponse: func(resp *http.Response) error {
			if !up.inspectResp || resp.Request == nil {
				return nil
			}
			st := stateFrom(resp.Request.Context())
			if st == nil || st.tx == nil || st.mode == config.ModeOff {
				return nil
			}
			res, err := st.tx.EvaluateResponse(resp, up.maxRespBody, up.inspectRespBody)
			if err != nil {
				dp.metrics.IncWAFError()
				if errors.Is(err, waf.ErrPanic) {
					dp.metrics.IncWAFPanic()
					dp.maybeAutoBypass()
				}
				return nil // fail open
			}
			if !res.Interrupted {
				return nil
			}
			st.result = &res
			if st.mode == config.ModeBlock {
				return errResponseBlocked
			}
			// detect mode: record the hit but let the response through
			dp.metrics.IncWouldBlock()
			st.terminal = "detect"
			return nil
		},

		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			st := stateFrom(r.Context())
			if errors.Is(err, errResponseBlocked) && st != nil && st.result != nil {
				dp.metrics.IncBlocked()
				dp.metrics.IncBlockedResp()
				st.terminal = "block"
				writeBlocked(w, *st.result)
				return
			}
			dp.metrics.IncUpstreamErr()
			if st != nil {
				st.terminal = "upstream_error"
			}
			w.Header().Set("Retry-After", "5")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream unavailable\n"))
		},

		Transport: dp.bt,
	}
	return up, nil
}

func (dp *DataPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	dp.metrics.IncTotal()
	if r.ContentLength > 0 {
		dp.metrics.AddBytesIn(r.ContentLength)
	}

	host := stripPort(r.Host)
	up := dp.rt.Load().hosts[host]
	if up == nil {
		dp.metrics.IncNoRoute()
		dp.metrics.RecordVerdict(metrics.VerdictError)
		dp.log(r, logEntry{action: "no_route", status: http.StatusBadGateway, start: start})
		http.Error(w, "no upstream configured for this host", http.StatusBadGateway)
		return
	}

	bridged := dp.bypass.Load() || up.bypass
	doWAF := !bridged && up.mode != config.ModeOff
	if bridged {
		dp.metrics.IncBypassed()
	}

	// Admission control: shed excess load rather than collapse under it.
	release, ok := dp.admit.Acquire(r.Context())
	if !ok {
		dp.metrics.IncQueueRejected()
		dp.metrics.RecordVerdict(metrics.VerdictShed)
		dp.log(r, logEntry{action: "queue_rejected", status: http.StatusServiceUnavailable, start: start})
		w.Header().Set("Retry-After", "2")
		http.Error(w, "server busy, try again shortly", http.StatusServiceUnavailable)
		return
	}
	defer release()

	st := &reqState{mode: up.mode}

	// Request-phase WAF. The transaction stays open for the response phase.
	if doWAF {
		st.tx = dp.engine.Load().NewTx()
		defer st.tx.Close()

		res, err := st.tx.EvaluateRequest(r, up.maxReqBody, up.inspectReqBody)
		switch {
		case err != nil:
			dp.metrics.IncWAFError()
			if errors.Is(err, waf.ErrPanic) {
				dp.metrics.IncWAFPanic()
				dp.maybeAutoBypass()
			}
			// fail open: fall through and proxy

		case res.Interrupted && up.mode == config.ModeBlock:
			dp.metrics.IncBlocked()
			dp.metrics.RecordVerdict(metrics.VerdictBlock)
			dp.log(r, logEntry{
				action: "block", phase: "request", status: res.Status,
				ruleID: res.RuleID, ruleMsg: res.Msg, start: start, mode: up.mode,
			})
			writeBlocked(w, res)
			return

		case res.Interrupted:
			// detect mode: record the match, let the request through
			dp.metrics.IncWouldBlock()
			dp.metrics.RecordVerdict(metrics.VerdictDetect)
			dp.log(r, logEntry{
				action: "detect", phase: "request", ruleID: res.RuleID,
				ruleMsg: res.Msg, start: start, mode: up.mode,
			})
		}
	}

	// Health-aware backend selection.
	target, picked := up.pick(dp.breaker)
	if !picked {
		dp.metrics.IncUpstreamErr()
		dp.metrics.RecordVerdict(metrics.VerdictError)
		dp.log(r, logEntry{action: "upstream_error", status: http.StatusBadGateway, start: start, mode: up.mode})
		w.Header().Set("Retry-After", "5")
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	st.target = target

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	rr := r.WithContext(context.WithValue(r.Context(), stateCtxKey, st))
	up.proxy.ServeHTTP(rec, rr)

	dp.metrics.AddBytesOut(rec.bytes)

	// Decide the terminal action: a callback may have already settled it.
	action, phase := st.terminal, ""
	switch action {
	case "block", "detect":
		phase = "response"
	case "":
		action = "allow"
		if rec.status >= 500 {
			action = "upstream_error"
		}
	}
	switch action {
	case "block":
		dp.metrics.RecordVerdict(metrics.VerdictBlock)
	case "detect":
		dp.metrics.RecordVerdict(metrics.VerdictDetect)
	case "upstream_error":
		dp.metrics.RecordVerdict(metrics.VerdictError)
	default:
		dp.metrics.RecordVerdict(metrics.VerdictAllow)
	}

	e := logEntry{
		action: action, phase: phase, status: rec.status, backend: target.raw,
		start: start, bytesOut: rec.bytes, mode: up.mode,
	}
	if st.result != nil {
		e.ruleID, e.ruleMsg = st.result.RuleID, st.result.Msg
	}
	dp.log(r, e)
}

// maybeAutoBypass trips the global bridge once WAF panics exceed the configured
// threshold, so a persistently broken rule engine cannot keep costing traffic.
func (dp *DataPlane) maybeAutoBypass() {
	n := dp.cfg.Get().WAF.AutoBypassOnPanics
	if n > 0 && dp.metrics.WAFPanics() >= int64(n) && dp.bypass.CompareAndSwap(false, true) {
		log.Printf("gowafyourself: auto-enabled global bridge after %d WAF panics", dp.metrics.WAFPanics())
	}
}

// SetBypass and GetBypass implement the bridge control used by the panel.
func (dp *DataPlane) SetBypass(on bool) { dp.bypass.Store(on) }
func (dp *DataPlane) GetBypass() bool   { return dp.bypass.Load() }

type logEntry struct {
	action   string
	phase    string
	status   int
	backend  string
	ruleID   int
	ruleMsg  string
	start    time.Time
	bytesOut int64
	mode     string
}

func (dp *DataPlane) log(r *http.Request, e logEntry) {
	dp.logger.Log(logstore.Event{
		Time:       e.start,
		RemoteAddr: r.RemoteAddr,
		Host:       r.Host,
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		UserAgent:  r.UserAgent(),
		Action:     e.action,
		Phase:      e.phase,
		RuleID:     e.ruleID,
		RuleMsg:    e.ruleMsg,
		Status:     e.status,
		Backend:    e.backend,
		LatencyMs:  time.Since(e.start).Milliseconds(),
		BytesIn:    r.ContentLength,
		BytesOut:   e.bytesOut,
		WAFMode:    e.mode,
	})
}

func writeBlocked(w http.ResponseWriter, res waf.Result) {
	status := res.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "Request blocked by WAF (rule %d)\n", res.RuleID)
}

// breakerTransport records each upstream outcome into the circuit breaker,
// keyed by target, so one sick backend does not condemn its healthy siblings.
// A transport error or a 5xx counts as a failure.
type breakerTransport struct {
	base http.RoundTripper
	br   *breaker.Group
}

func (t *breakerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	ok := err == nil && (resp == nil || resp.StatusCode < 500)
	t.br.Record(backendKey(req.URL), ok)
	return resp, err
}

// statusRecorder captures the response status and byte count while delegating to
// the underlying ResponseWriter. Flusher and Hijacker are preserved so streaming
// and websocket upgrades keep working through the proxy.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func stripPort(hostport string) string {
	if hostport == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(hostport)
}
