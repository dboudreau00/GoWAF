// Package panel is the GoWAFyourself control plane: a basic-auth web console,
// served on its own port, for watching live traffic decisions and changing
// settings -- WAF mode, the bridge, capacity limits, and the upstream list.
// Changes are persisted through config.Manager and applied via an onChange hook,
// so nothing here requires a restart.
package panel

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/example/gowafyourself/internal/config"
	"github.com/example/gowafyourself/internal/logstore"
	"github.com/example/gowafyourself/internal/metrics"
)

// BypassController is the slice of the data plane the panel needs to work the
// bridge. Implemented by *proxy.DataPlane; kept as an interface to avoid an
// import cycle.
type BypassController interface {
	GetBypass() bool
	SetBypass(bool)
}

// CapacityController is the slice of admission control the panel can tune.
// Implemented by *admission.Controller.
type CapacityController interface {
	SetLimit(int) error
	SetQueue(queueSize, timeoutMs int)
	Stats() (inflight, waiting, limit, queueCap int)
}

type Panel struct {
	mgr      *config.Manager
	metrics  *metrics.Metrics
	bypass   BypassController
	capacity CapacityController
	logger   *logstore.Logger
	onChange func() error
	tmpl     *template.Template
}

func New(mgr *config.Manager, m *metrics.Metrics, bypass BypassController,
	capacity CapacityController, logger *logstore.Logger, onChange func() error) *Panel {
	return &Panel{
		mgr:      mgr,
		metrics:  m,
		bypass:   bypass,
		capacity: capacity,
		logger:   logger,
		onChange: onChange,
		tmpl:     template.Must(template.New("console").Parse(consoleHTML)),
	}
}

// Handler returns the basic-auth-wrapped control-plane mux.
func (p *Panel) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.auth(p.handleConsole))
	mux.HandleFunc("/mode", p.auth(p.handleMode))
	mux.HandleFunc("/bridge", p.auth(p.handleBridge))
	mux.HandleFunc("/capacity", p.auth(p.handleCapacity))
	mux.HandleFunc("/inspection", p.auth(p.handleInspection))
	mux.HandleFunc("/upstreams/add", p.auth(p.handleAddUpstream))
	mux.HandleFunc("/upstreams/remove", p.auth(p.handleRemoveUpstream))
	mux.HandleFunc("/api/stats", p.auth(p.handleStats))
	return mux
}

func (p *Panel) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := p.mgr.Get()
		if cfg.Panel.User == "" || cfg.Panel.Pass == "" {
			http.Error(w, "Set panel.user and panel.pass in the config file to use the console.",
				http.StatusServiceUnavailable)
			return
		}
		u, pw, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(u), []byte(cfg.Panel.User)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pw), []byte(cfg.Panel.Pass)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoWAFyourself"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

type consoleData struct {
	Snap     metrics.Snapshot
	Cfg      *config.Config
	Bridge   bool
	Dropped  int64
	Inflight int
	Waiting  int
	Limit    int
	QueueCap int
	LoadPct  int // in-flight as a percentage of the concurrency limit
	QueuePct int // queue occupancy as a percentage of queue depth
	Notice   string
}

// pct returns n/total as a percentage clamped to 0..100 (0 when total is 0).
func pct(n, total int) int {
	if total <= 0 {
		return 0
	}
	v := n * 100 / total
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func (p *Panel) handleConsole(w http.ResponseWriter, r *http.Request) {
	inflight, waiting, limit, queueCap := p.capacity.Stats()
	data := consoleData{
		Snap:     p.metrics.Snapshot(),
		Cfg:      p.mgr.Get(),
		Bridge:   p.bypass.GetBypass(),
		Dropped:  p.logger.Dropped(),
		Inflight: inflight,
		Waiting:  waiting,
		Limit:    limit,
		QueueCap: queueCap,
		LoadPct:  pct(inflight, limit),
		QueuePct: pct(waiting, queueCap),
		Notice:   r.URL.Query().Get("notice"),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.tmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (p *Panel) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, p.metrics.Snapshot())
}

func (p *Panel) handleMode(w http.ResponseWriter, r *http.Request) {
	if !p.requirePost(w, r) {
		return
	}
	mode := r.FormValue("mode")
	switch mode {
	case config.ModeBlock, config.ModeDetect, config.ModeOff:
	default:
		p.fail(w, r, "Mode must be block, detect, or off.")
		return
	}
	cur := *p.mgr.Get()
	cur.WAF.Mode = mode
	if err := p.apply(&cur); err != nil {
		p.fail(w, r, err.Error())
		return
	}
	p.done(w, r, "WAF mode set to "+mode+".")
}

func (p *Panel) handleBridge(w http.ResponseWriter, r *http.Request) {
	if !p.requirePost(w, r) {
		return
	}
	on := r.FormValue("open") == "true"
	p.bypass.SetBypass(on)
	if on {
		p.done(w, r, "Bridge open. Traffic is passing through without inspection.")
		return
	}
	p.done(w, r, "Bridge closed. The WAF is inline again.")
}

// handleCapacity retunes admission control live -- no restart needed.
func (p *Panel) handleCapacity(w http.ResponseWriter, r *http.Request) {
	if !p.requirePost(w, r) {
		return
	}
	maxConc, err1 := strconv.Atoi(strings.TrimSpace(r.FormValue("maxConcurrent")))
	queueSize, err2 := strconv.Atoi(strings.TrimSpace(r.FormValue("queueSize")))
	timeoutMs, err3 := strconv.Atoi(strings.TrimSpace(r.FormValue("queueTimeoutMs")))
	if err1 != nil || err2 != nil || err3 != nil {
		p.fail(w, r, "Capacity values must be whole numbers.")
		return
	}
	cur := *p.mgr.Get()
	cur.Admission.MaxConcurrent = maxConc
	cur.Admission.QueueSize = queueSize
	cur.Admission.QueueTimeoutMs = timeoutMs
	if err := p.apply(&cur); err != nil {
		p.fail(w, r, err.Error())
		return
	}
	// Apply to the running controller as well as the persisted config.
	if err := p.capacity.SetLimit(maxConc); err != nil {
		p.fail(w, r, err.Error())
		return
	}
	p.capacity.SetQueue(queueSize, timeoutMs)
	p.done(w, r, "Capacity updated. In-flight requests were not interrupted.")
}

// handleInspection toggles which phases and bodies are inspected. Changing these
// rebuilds the rule engine, so the change is applied by the onChange hook.
func (p *Panel) handleInspection(w http.ResponseWriter, r *http.Request) {
	if !p.requirePost(w, r) {
		return
	}
	cur := *p.mgr.Get()
	cur.WAF.InspectBody = r.FormValue("inspectBody") == "on"
	cur.WAF.InspectResponse = r.FormValue("inspectResponse") == "on"
	cur.WAF.InspectResponseBody = r.FormValue("inspectResponseBody") == "on"
	if err := p.apply(&cur); err != nil {
		p.fail(w, r, err.Error())
		return
	}
	p.done(w, r, "Inspection settings updated.")
}

func (p *Panel) handleAddUpstream(w http.ResponseWriter, r *http.Request) {
	if !p.requirePost(w, r) {
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	target := strings.TrimSpace(r.FormValue("target"))
	if host == "" || target == "" {
		p.fail(w, r, "Add an upstream by entering both a host and a target.")
		return
	}
	cur := *p.mgr.Get()
	ups := make([]config.UpstreamConfig, len(cur.Upstreams))
	copy(ups, cur.Upstreams)
	ups = append(ups, config.UpstreamConfig{Host: host, Target: target})
	cur.Upstreams = ups
	if err := p.apply(&cur); err != nil {
		p.fail(w, r, err.Error())
		return
	}
	p.done(w, r, "Added "+host+".")
}

func (p *Panel) handleRemoveUpstream(w http.ResponseWriter, r *http.Request) {
	if !p.requirePost(w, r) {
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	cur := *p.mgr.Get()
	ups := make([]config.UpstreamConfig, 0, len(cur.Upstreams))
	for _, u := range cur.Upstreams {
		if !strings.EqualFold(u.Host, host) {
			ups = append(ups, u)
		}
	}
	cur.Upstreams = ups
	if err := p.apply(&cur); err != nil {
		p.fail(w, r, err.Error())
		return
	}
	p.done(w, r, "Removed "+host+".")
}

// apply persists a new config and triggers a data-plane rebuild.
func (p *Panel) apply(c *config.Config) error {
	if err := p.mgr.Set(c); err != nil {
		return err
	}
	if p.onChange != nil {
		return p.onChange()
	}
	return nil
}

func (p *Panel) requirePost(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (p *Panel) done(w http.ResponseWriter, r *http.Request, notice string) {
	http.Redirect(w, r, "/?notice="+template.URLQueryEscaper(notice), http.StatusSeeOther)
}

func (p *Panel) fail(w http.ResponseWriter, r *http.Request, notice string) {
	http.Redirect(w, r, "/?notice="+template.URLQueryEscaper(notice), http.StatusSeeOther)
}
