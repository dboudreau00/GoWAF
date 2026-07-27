// Package waf wraps the Coraza engine loaded with the OWASP Core Rule Set.
//
// The engine is built once at startup and reused. Each request opens a short
// lived transaction (Tx) that spans the whole exchange, so the same transaction
// can evaluate the request on the way in and the response on the way out --
// Coraza's response-phase rules (outbound data leakage, error disclosure) need
// the request-phase state to score against.
//
// Every evaluation is wrapped in recover() so a bug or panic inside rule
// processing FAILS OPEN (traffic is allowed) rather than taking the proxy down,
// which is the "bridge if malfunctioning" requirement.
//
// NOTE on Coraza/CRS versions: the include names below (@coraza.conf-recommended,
// @crs-setup.conf.example, @owasp_crs/*.conf) and the paranoia-level tx variable
// names (tx.blocking_paranoia_level / tx.detection_paranoia_level, which are CRS
// v4 names) follow the current Coraza + coraza-coreruleset/v4 quickstart. If you
// pin a different CRS major version, these are the two things to adjust.
package waf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"

	"github.com/example/gowafyourself/internal/config"
)

// ErrPanic indicates rule evaluation panicked and the request was failed open.
var ErrPanic = errors.New("waf: evaluation panicked (failed open)")

type Engine struct {
	waf coraza.WAF
}

// Result summarizes a WAF decision.
type Result struct {
	Interrupted bool
	Phase       string // "request" or "response"
	RuleID      int
	Status      int // status suggested by the interruption (typically 403)
	Action      string
	Msg         string
}

// New builds the WAF engine from configuration.
func New(cfg config.WAFConfig) (*Engine, error) {
	directives, err := buildDirectives(cfg)
	if err != nil {
		return nil, err
	}
	w, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(coreruleset.FS).
			WithDirectives(directives),
	)
	if err != nil {
		return nil, fmt.Errorf("waf: build engine: %w", err)
	}
	return &Engine{waf: w}, nil
}

// buildDirectives assembles the full SecLang program: base config, CRS setup,
// tuning, the rule set itself, and finally any site-specific custom rules.
func buildDirectives(cfg config.WAFConfig) (string, error) {
	var b strings.Builder
	b.WriteString("Include @coraza.conf-recommended\n")
	b.WriteString("Include @crs-setup.conf.example\n")
	// Always enforcing at the engine level; the app layer decides block vs
	// detect per request based on the effective mode.
	b.WriteString("SecRuleEngine On\n")

	if cfg.InspectBody {
		b.WriteString("SecRequestBodyAccess On\n")
		fmt.Fprintf(&b, "SecRequestBodyLimit %d\n", cfg.MaxBodyBytes)
		b.WriteString("SecRequestBodyLimitAction ProcessPartial\n")
	} else {
		b.WriteString("SecRequestBodyAccess Off\n")
	}

	if cfg.InspectResponseBody {
		b.WriteString("SecResponseBodyAccess On\n")
		fmt.Fprintf(&b, "SecResponseBodyLimit %d\n", cfg.MaxResponseBodyBytes)
		b.WriteString("SecResponseBodyLimitAction ProcessPartial\n")
		b.WriteString("SecResponseBodyMimeType text/plain text/html text/xml application/json\n")
	} else {
		b.WriteString("SecResponseBodyAccess Off\n")
	}

	// Paranoia level + anomaly threshold (CRS v4 variable names).
	fmt.Fprintf(&b, "SecAction \"id:900000,phase:1,nolog,pass,t:none,setvar:tx.blocking_paranoia_level=%d\"\n", cfg.ParanoiaLevel)
	fmt.Fprintf(&b, "SecAction \"id:900001,phase:1,nolog,pass,t:none,setvar:tx.detection_paranoia_level=%d\"\n", cfg.ParanoiaLevel)
	fmt.Fprintf(&b, "SecAction \"id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=%d\"\n", cfg.AnomalyThreshold)
	if cfg.OutboundAnomalyThreshold > 0 {
		fmt.Fprintf(&b, "SecAction \"id:900111,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=%d\"\n", cfg.OutboundAnomalyThreshold)
	}

	b.WriteString("Include @owasp_crs/*.conf\n")

	// Custom rules are appended as literal directive text. A plain `Include
	// <path>` would resolve against the embedded CRS filesystem, not the host
	// disk, so the file is read and inlined instead.
	if cfg.CustomRulesPath != "" {
		extra, err := readFile(cfg.CustomRulesPath)
		if err != nil {
			return "", fmt.Errorf("waf: read custom rules %q: %w", cfg.CustomRulesPath, err)
		}
		b.WriteString("\n# ---- site-specific rules ----\n")
		b.WriteString(extra)
		b.WriteString("\n")
	}
	return b.String(), nil
}

// Tx is a single request/response transaction. Create one per exchange with
// NewTx and always Close it (defer) to release engine resources.
type Tx struct {
	tx types.Transaction
}

// NewTx opens a transaction for one HTTP exchange.
func (e *Engine) NewTx() *Tx { return &Tx{tx: e.waf.NewTransaction()} }

// Close finalizes logging and releases the transaction.
func (t *Tx) Close() {
	if t == nil || t.tx == nil {
		return
	}
	defer func() { _ = recover() }() // never let teardown take down a request
	t.tx.ProcessLogging()
	_ = t.tx.Close()
	t.tx = nil
}

// matchedRulesProvider is satisfied by Coraza transactions; used to enrich the
// log message with human-readable rule text when available.
type matchedRulesProvider interface {
	MatchedRules() []types.MatchedRule
}

// EvaluateRequest runs request-phase inspection. When inspectBody is set it
// buffers the body (bounded by maxBody) for the rule engine, and always restores
// r.Body intact so the reverse proxy forwards the request unchanged.
func (t *Tx) EvaluateRequest(r *http.Request, maxBody int64, inspectBody bool) (res Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			res = Result{}
			err = fmt.Errorf("%w: %v", ErrPanic, rec)
		}
	}()
	tx := t.tx

	client, cport := splitHostPort(r.RemoteAddr)
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

	for k, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return interruption(tx, it, "request"), nil
	}

	if inspectBody && r.Body != nil && tx.IsRequestBodyAccessible() {
		inspect, restore, rerr := boundedRead(r.Body, maxBody)
		r.Body = restore
		if rerr != nil {
			return Result{}, rerr
		}
		if len(inspect) > 0 {
			// A fully buffered body has a known length; an oversized one is
			// streamed, so leave ContentLength alone in that case.
			if int64(len(inspect)) < maxBody {
				r.ContentLength = int64(len(inspect))
			}
			if it, _, werr := tx.WriteRequestBody(inspect); werr != nil {
				return Result{}, werr
			} else if it != nil {
				return interruption(tx, it, "request"), nil
			}
		}
		if it, perr := tx.ProcessRequestBody(); perr != nil {
			return Result{}, perr
		} else if it != nil {
			return interruption(tx, it, "request"), nil
		}
	}
	return Result{}, nil
}

// EvaluateResponse runs response-phase inspection on the upstream reply. Like
// the request path it restores resp.Body so the response can still be streamed
// to the client when it is allowed through.
func (t *Tx) EvaluateResponse(resp *http.Response, maxBody int64, inspectBody bool) (res Result, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			res = Result{}
			err = fmt.Errorf("%w: %v", ErrPanic, rec)
		}
	}()
	tx := t.tx

	for k, vals := range resp.Header {
		for _, v := range vals {
			tx.AddResponseHeader(k, v)
		}
	}
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if it := tx.ProcessResponseHeaders(resp.StatusCode, proto); it != nil {
		return interruption(tx, it, "response"), nil
	}

	if inspectBody && resp.Body != nil && tx.IsResponseBodyAccessible() {
		inspect, restore, rerr := boundedRead(resp.Body, maxBody)
		resp.Body = restore
		if rerr != nil {
			return Result{}, rerr
		}
		if len(inspect) > 0 {
			if it, _, werr := tx.WriteResponseBody(inspect); werr != nil {
				return Result{}, werr
			} else if it != nil {
				return interruption(tx, it, "response"), nil
			}
		}
		if it, perr := tx.ProcessResponseBody(); perr != nil {
			return Result{}, perr
		} else if it != nil {
			return interruption(tx, it, "response"), nil
		}
	}
	return Result{}, nil
}

// boundedRead reads up to maxBody bytes for inspection while guaranteeing the
// caller can still forward the *entire* stream. It returns the bytes to inspect
// and a replacement ReadCloser carrying the full original content.
//
// Reading maxBody+1 is what distinguishes "the whole body fit" from "there is
// more to come": in the oversized case the buffered prefix is chained back in
// front of the unread remainder so nothing is ever truncated in transit.
func boundedRead(rc io.ReadCloser, maxBody int64) ([]byte, io.ReadCloser, error) {
	if maxBody < 0 {
		maxBody = 0
	}
	buf := make([]byte, maxBody+1)
	n, err := io.ReadFull(rc, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, io.NopCloser(bytes.NewReader(buf[:n])), err
	}
	consumed := buf[:n]

	if int64(n) > maxBody {
		// Oversized: inspect the bounded prefix, forward prefix + remainder.
		return consumed[:maxBody], io.NopCloser(io.MultiReader(bytes.NewReader(consumed), rc)), nil
	}
	// Whole body fit within the limit.
	_ = rc.Close()
	return consumed, io.NopCloser(bytes.NewReader(consumed)), nil
}

func interruption(tx types.Transaction, it *types.Interruption, phase string) Result {
	msg := it.Data
	if mp, ok := tx.(matchedRulesProvider); ok {
		for _, mr := range mp.MatchedRules() {
			if mr.Rule().ID() == it.RuleID && mr.Message() != "" {
				msg = mr.Message()
				break
			}
		}
	}
	status := it.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	return Result{
		Interrupted: true,
		Phase:       phase,
		RuleID:      it.RuleID,
		Status:      status,
		Action:      it.Action,
		Msg:         msg,
	}
}
