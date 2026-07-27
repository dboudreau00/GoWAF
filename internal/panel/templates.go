package panel

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// consoleHTML is the control console. Design intent: this is an instrument
// panel, not a marketing page. Everything is monospace because everything on it
// is data; colour is reserved for verdict semantics (pass / detect / block /
// shed) and never used decoratively. The decision strip at the top is the one
// signature element -- one tick per recent request, height and colour encoding
// what the WAF did with it.
const consoleHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GoWAFyourself console</title>
<style>
  :root {
    --bg:#0B1017; --surface:#131B26; --surface2:#1A2432; --line:#22303F;
    --text:#E3ECF5; --dim:#8296AB;
    --signal:#4FC3E8; --pass:#43D9A3; --warn:#F2B75C; --alarm:#FF5D6C;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin:0; padding:28px 22px 60px; background:var(--bg); color:var(--text);
    font-family:var(--mono); font-size:13px; line-height:1.55;
    max-width:1080px; margin-inline:auto;
    -webkit-font-smoothing:antialiased;
  }

  /* ---- wordmark: the name carries the accent, so nothing else has to ---- */
  .top { display:flex; align-items:baseline; gap:16px; flex-wrap:wrap; margin-bottom:4px; }
  .mark { font-size:20px; font-weight:700; letter-spacing:-0.02em; }
  .mark .go { color:var(--dim); }
  .mark .waf { color:var(--signal); }
  .mark .you { color:var(--text); }
  .tag { color:var(--dim); font-size:11px; letter-spacing:0.14em; text-transform:uppercase; }
  .top .right { margin-left:auto; display:flex; gap:8px; align-items:center; }

  .pill { font-size:11px; padding:3px 9px; border-radius:2px; border:1px solid var(--line);
          color:var(--dim); letter-spacing:0.06em; text-transform:uppercase; white-space:nowrap; }
  .pill.block { color:var(--pass); border-color:#2A5B49; }
  .pill.detect { color:var(--warn); border-color:#5C4A29; }
  .pill.off { color:var(--dim); }
  .pill.alarm { color:var(--alarm); border-color:#5C2A31; background:#1E1116; }

  .notice { margin:14px 0 0; padding:9px 12px; border-left:2px solid var(--signal);
            background:var(--surface); color:var(--text); font-size:12px; }

  /* ---- signature element: one tick per request ---- */
  .strip-wrap { margin:22px 0 8px; padding:16px 18px 12px; background:var(--surface);
                border:1px solid var(--line); border-radius:3px; }
  .strip-head { display:flex; align-items:baseline; gap:10px; margin-bottom:12px; }
  .strip-head h2 { margin:0; font-size:12px; font-weight:600; letter-spacing:0.12em;
                   text-transform:uppercase; color:var(--dim); }
  .strip-head .count { color:var(--dim); font-size:11px; margin-left:auto; }
  .strip { display:flex; align-items:flex-end; gap:1px; height:46px;
           border-bottom:1px solid var(--line); padding-bottom:1px; }
  .strip i { display:block; width:4px; flex:0 0 4px; border-radius:1px 1px 0 0; }
  .strip i.allow  { height:26%; background:#2C6B57; }
  .strip i.detect { height:64%; background:var(--warn); }
  .strip i.block  { height:100%; background:var(--alarm); }
  .strip i.shed   { height:46%; background:#3E4E60; }
  .strip i.error  { height:80%; background:#8C3B45; }
  .strip .empty { color:var(--dim); font-size:11px; padding-bottom:14px; }
  .legend { display:flex; gap:16px; margin-top:10px; flex-wrap:wrap; color:var(--dim); font-size:11px; }
  .legend span { display:flex; align-items:center; gap:6px; }
  .legend b { width:8px; height:8px; border-radius:1px; display:inline-block; }

  /* ---- counters ---- */
  .grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(132px,1fr)); gap:1px;
          background:var(--line); border:1px solid var(--line); border-radius:3px; overflow:hidden; }
  .cell { background:var(--surface); padding:11px 13px; }
  .cell .n { font-size:19px; font-weight:600; letter-spacing:-0.01em; }
  .cell .l { color:var(--dim); font-size:10px; letter-spacing:0.1em; text-transform:uppercase; margin-top:2px; }
  .cell.hot .n { color:var(--alarm); }
  .cell.warm .n { color:var(--warn); }

  h2.sec { font-size:12px; font-weight:600; letter-spacing:0.12em; text-transform:uppercase;
           color:var(--dim); margin:30px 0 10px; }
  .two { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
  @media (max-width:760px) { .two { grid-template-columns:1fr; } }

  .card { background:var(--surface); border:1px solid var(--line); border-radius:3px; padding:14px 16px; }

  /* ---- capacity meter ---- */
  .meter { height:6px; background:var(--surface2); border-radius:1px; overflow:hidden; margin:8px 0 4px; }
  .meter i { display:block; height:100%; background:var(--signal); }
  .meter.queue i { background:var(--warn); }
  .kv { display:flex; justify-content:space-between; color:var(--dim); font-size:11px; }

  table { border-collapse:collapse; width:100%; font-size:12px; }
  th { text-align:left; color:var(--dim); font-weight:500; font-size:10px;
       letter-spacing:0.1em; text-transform:uppercase; padding:0 8px 7px 0; border-bottom:1px solid var(--line); }
  td { padding:7px 8px 7px 0; border-bottom:1px solid var(--line); vertical-align:top; }
  tr:last-child td { border-bottom:0; }
  .state-closed { color:var(--pass); }
  .state-open { color:var(--alarm); }
  .state-half { color:var(--warn); }
  .muted { color:var(--dim); }

  input, button, select {
    font-family:var(--mono); font-size:12px; color:var(--text);
    background:var(--surface2); border:1px solid var(--line); border-radius:2px; padding:6px 9px;
  }
  input[type=number] { width:88px; }
  button { cursor:pointer; }
  button:hover { border-color:var(--signal); color:var(--signal); }
  button.danger:hover { border-color:var(--alarm); color:var(--alarm); }
  button.primary { border-color:#2A5B49; color:var(--pass); }
  button:focus-visible, input:focus-visible, a:focus-visible {
    outline:2px solid var(--signal); outline-offset:2px;
  }
  form.inline { display:inline; }
  .row { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .field { display:flex; flex-direction:column; gap:4px; }
  .field label { color:var(--dim); font-size:10px; letter-spacing:0.08em; text-transform:uppercase; }
  .check { display:flex; align-items:center; gap:7px; color:var(--text); font-size:12px; margin:5px 0; }
  code { color:var(--signal); }
  footer { margin-top:34px; padding-top:14px; border-top:1px solid var(--line);
           color:var(--dim); font-size:11px; display:flex; gap:18px; flex-wrap:wrap; }
  @media (prefers-reduced-motion:no-preference) { .strip i { transition:height .2s ease; } }
</style>
</head>
<body>

  <div class="top">
    <div class="mark"><span class="go">Go</span><span class="waf">WAF</span><span class="you">yourself</span></div>
    <div class="tag">web application firewall</div>
    <div class="right">
      <span class="pill {{.Cfg.WAF.Mode}}">mode: {{.Cfg.WAF.Mode}}</span>
      {{if .Bridge}}<span class="pill alarm">bridge open &mdash; waf skipped</span>
      {{else}}<span class="pill">bridge closed</span>{{end}}
    </div>
  </div>

  {{if .Notice}}<div class="notice">{{.Notice}}</div>{{end}}

  <!-- signature: last N request verdicts, newest at the right -->
  <div class="strip-wrap">
    <div class="strip-head">
      <h2>Decisions</h2>
      <span class="muted">newest right</span>
      <span class="count">last <span id="vcount">{{len .Snap.RecentVerdicts}}</span> requests</span>
    </div>
    <div class="strip" id="strip">
      {{if .Snap.RecentVerdicts}}
        {{range .Snap.RecentVerdicts}}<i class="{{.}}"></i>{{end}}
      {{else}}
        <span class="empty">No traffic yet. Send a request through the proxy and it will appear here.</span>
      {{end}}
    </div>
    <div class="legend">
      <span><b style="background:#2C6B57"></b>allowed</span>
      <span><b style="background:var(--warn)"></b>detected</span>
      <span><b style="background:var(--alarm)"></b>blocked</span>
      <span><b style="background:#3E4E60"></b>shed</span>
      <span><b style="background:#8C3B45"></b>upstream error</span>
    </div>
  </div>

  <div class="grid">
    <div class="cell"><div class="n" id="m-total">{{.Snap.Total}}</div><div class="l">Requests</div></div>
    <div class="cell{{if .Snap.Blocked}} hot{{end}}"><div class="n" id="m-blocked">{{.Snap.Blocked}}</div><div class="l">Blocked</div></div>
    <div class="cell"><div class="n" id="m-blockedresp">{{.Snap.BlockedResp}}</div><div class="l">Blocked (resp)</div></div>
    <div class="cell{{if .Snap.WouldBlock}} warm{{end}}"><div class="n" id="m-detect">{{.Snap.WouldBlock}}</div><div class="l">Detected</div></div>
    <div class="cell"><div class="n" id="m-inflight">{{.Snap.Inflight}}</div><div class="l">In flight</div></div>
    <div class="cell"><div class="n" id="m-queued">{{.Snap.Queued}}</div><div class="l">Queued</div></div>
    <div class="cell{{if .Snap.QueueRejected}} warm{{end}}"><div class="n" id="m-shed">{{.Snap.QueueRejected}}</div><div class="l">Shed</div></div>
    <div class="cell{{if .Snap.UpstreamErr}} hot{{end}}"><div class="n" id="m-upstream">{{.Snap.UpstreamErr}}</div><div class="l">Upstream errs</div></div>
    <div class="cell"><div class="n" id="m-noroute">{{.Snap.NoRoute}}</div><div class="l">No route</div></div>
    <div class="cell"><div class="n" id="m-bypassed">{{.Snap.Bypassed}}</div><div class="l">Bridged</div></div>
    <div class="cell{{if .Snap.WAFPanics}} hot{{end}}"><div class="n" id="m-panics">{{.Snap.WAFPanics}}</div><div class="l">WAF panics</div></div>
    <div class="cell"><div class="n" id="m-dropped">{{.Dropped}}</div><div class="l">Logs dropped</div></div>
  </div>

  <div class="two">
    <div>
      <h2 class="sec">Enforcement</h2>
      <div class="card">
        <div class="row">
          <form class="inline" method="post" action="/mode"><input type="hidden" name="mode" value="block"><button class="primary">Block traffic</button></form>
          <form class="inline" method="post" action="/mode"><input type="hidden" name="mode" value="detect"><button>Detect only</button></form>
          <form class="inline" method="post" action="/mode"><input type="hidden" name="mode" value="off"><button>Turn WAF off</button></form>
        </div>
        <p class="muted" style="margin:12px 0 0">
          Detect logs what it would have blocked and lets it through. Off skips inspection entirely.
        </p>
      </div>

      <h2 class="sec">Bridge</h2>
      <div class="card">
        {{if .Bridge}}
          <p style="margin:0 0 10px">Traffic is bypassing the WAF and going straight to your backends.</p>
          <form class="inline" method="post" action="/bridge">
            <input type="hidden" name="open" value="false"><button class="primary">Close bridge &mdash; put the WAF back inline</button>
          </form>
        {{else}}
          <p style="margin:0 0 10px">The WAF is inline. Open the bridge to pass traffic through untouched if inspection is causing trouble.</p>
          <form class="inline" method="post" action="/bridge">
            <input type="hidden" name="open" value="true"><button class="danger">Open bridge &mdash; skip the WAF</button>
          </form>
        {{end}}
        {{if .Cfg.WAF.AutoBypassOnPanics}}
          <p class="muted" style="margin:10px 0 0">Opens automatically after {{.Cfg.WAF.AutoBypassOnPanics}} WAF panics.</p>
        {{end}}
      </div>
    </div>

    <div>
      <h2 class="sec">Capacity</h2>
      <div class="card">
        <div class="kv"><span>In flight</span><span><span id="c-inflight">{{.Inflight}}</span> / {{.Limit}}</span></div>
        <div class="meter"><i style="width:{{.LoadPct}}%"></i></div>
        <div class="kv" style="margin-top:10px"><span>Queued</span><span><span id="c-waiting">{{.Waiting}}</span> / {{.QueueCap}}</span></div>
        <div class="meter queue"><i style="width:{{.QueuePct}}%"></i></div>

        <form method="post" action="/capacity" style="margin-top:14px">
          <div class="row">
            <div class="field"><label for="mc">Max concurrent</label>
              <input id="mc" type="number" name="maxConcurrent" min="1" max="65536" value="{{.Cfg.Admission.MaxConcurrent}}"></div>
            <div class="field"><label for="qs">Queue depth</label>
              <input id="qs" type="number" name="queueSize" min="0" value="{{.Cfg.Admission.QueueSize}}"></div>
            <div class="field"><label for="qt">Wait timeout (ms)</label>
              <input id="qt" type="number" name="queueTimeoutMs" min="0" value="{{.Cfg.Admission.QueueTimeoutMs}}"></div>
          </div>
          <button style="margin-top:10px">Apply capacity</button>
        </form>
        <p class="muted" style="margin:10px 0 0">Applies immediately. Lowering the limit lets in-flight requests finish.</p>
      </div>

      <h2 class="sec">Inspection</h2>
      <div class="card">
        <form method="post" action="/inspection">
          <label class="check"><input type="checkbox" name="inspectBody" {{if .Cfg.WAF.InspectBody}}checked{{end}}> Inspect request bodies</label>
          <label class="check"><input type="checkbox" name="inspectResponse" {{if .Cfg.WAF.InspectResponse}}checked{{end}}> Inspect responses</label>
          <label class="check"><input type="checkbox" name="inspectResponseBody" {{if .Cfg.WAF.InspectResponseBody}}checked{{end}}> Inspect response bodies</label>
          <button style="margin-top:8px">Save inspection</button>
        </form>
        <p class="muted" style="margin:10px 0 0">
          Paranoia {{.Cfg.WAF.ParanoiaLevel}} &middot; anomaly threshold {{.Cfg.WAF.AnomalyThreshold}}.
          Response body inspection buffers up to {{.Cfg.WAF.MaxResponseBodyBytes}} bytes per reply.
        </p>
      </div>
    </div>
  </div>

  <h2 class="sec">Backends</h2>
  <div class="card">
    {{if .Snap.Breakers}}
    <table>
      <tr><th>Backend</th><th>Circuit</th></tr>
      {{range $k, $v := .Snap.Breakers}}
      <tr><td><code>{{$k}}</code></td>
        <td class="state-{{$v}}">{{$v}}</td></tr>
      {{end}}
    </table>
    {{else}}<p class="muted" style="margin:0">No backend traffic yet. Circuits appear here once requests start flowing.</p>{{end}}
  </div>

  <h2 class="sec">Upstreams</h2>
  <div class="card">
    <table>
      <tr><th>Host &mdash; point a CNAME or A record here</th><th>Targets</th><th>Mode</th><th>Bridge</th><th></th></tr>
      {{range .Cfg.Upstreams}}
      <tr>
        <td><code>{{.Host}}</code></td>
        <td>{{range .Backends}}<div><code>{{.}}</code></div>{{end}}</td>
        <td>{{if .WAF}}{{.WAF}}{{else}}<span class="muted">global</span>{{end}}</td>
        <td>{{if .Bypass}}<span class="state-open">open</span>{{else}}<span class="muted">closed</span>{{end}}</td>
        <td><form class="inline" method="post" action="/upstreams/remove" onsubmit="return confirm('Remove {{.Host}}?')">
          <input type="hidden" name="host" value="{{.Host}}"><button class="danger">Remove</button></form></td>
      </tr>
      {{end}}
    </table>
    <form method="post" action="/upstreams/add" style="margin-top:14px">
      <div class="row">
        <div class="field"><label for="h">Host</label><input id="h" name="host" placeholder="app.example.com" required></div>
        <div class="field"><label for="t">Target</label><input id="t" name="target" size="30" placeholder="http://127.0.0.1:3000" required></div>
        <button style="align-self:flex-end">Add upstream</button>
      </div>
    </form>
    <p class="muted" style="margin:12px 0 0">
      Routing is by Host header and SNI, so a CNAME and an A record behave identically.
    </p>
  </div>

  <footer>
    <span>http <code>{{.Cfg.Listen.HTTP}}</code></span>
    <span>https <code>{{.Cfg.Listen.HTTPS}}</code> ({{.Cfg.TLS.Mode}})</span>
    <span>console <code>{{.Cfg.Listen.Panel}}</code></span>
    <span>logs <code>{{.Cfg.Logging.Sink}}</code></span>
    <span>up {{.Snap.UptimeSeconds}}s</span>
  </footer>

<script>
// Live refresh without a full page reload, so a form in progress is never lost.
// Everything below is server-rendered first, so the console works with JS off.
(function () {
  var ids = {
    total:"m-total", blocked:"m-blocked", blockedResponse:"m-blockedresp",
    wouldBlock:"m-detect", inflight:"m-inflight", queued:"m-queued",
    queueRejected:"m-shed", upstreamErrors:"m-upstream", noRoute:"m-noroute",
    bypassed:"m-bypassed", wafPanics:"m-panics"
  };
  function paint(s) {
    Object.keys(ids).forEach(function (k) {
      var el = document.getElementById(ids[k]);
      if (el && typeof s[k] === "number") el.textContent = s[k];
    });
    var ci = document.getElementById("c-inflight"); if (ci) ci.textContent = s.inflight;
    var cw = document.getElementById("c-waiting"); if (cw) cw.textContent = s.queued;
    var strip = document.getElementById("strip");
    var v = s.recentVerdicts || [];
    if (strip && v.length) {
      strip.innerHTML = v.map(function (x) { return '<i class="' + x + '"></i>'; }).join("");
    }
    var vc = document.getElementById("vcount"); if (vc) vc.textContent = v.length;
  }
  function poll() {
    fetch("/api/stats", { credentials: "same-origin" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) { if (s) paint(s); })
      .catch(function () { /* console keeps showing the last good values */ });
  }
  setInterval(poll, 3000);
})();
</script>
</body>
</html>`
