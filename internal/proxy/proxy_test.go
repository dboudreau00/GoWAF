package proxy

import (
	"net/url"
	"testing"

	"github.com/example/gowafyourself/internal/breaker"
	"github.com/example/gowafyourself/internal/config"
	"github.com/example/gowafyourself/internal/metrics"
)

func TestStripPort(t *testing.T) {
	cases := map[string]string{
		"app.example.com:8080":  "app.example.com",
		"app.example.com":       "app.example.com",
		"APP.Example.COM:443":   "app.example.com",
		"[2001:db8::1]:8443":    "2001:db8::1",
		"":                      "",
	}
	for in, want := range cases {
		if got := stripPort(in); got != want {
			t.Errorf("stripPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustUpstream(t *testing.T, targets ...string) *upstream {
	t.Helper()
	up := &upstream{}
	for _, raw := range targets {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		up.targets = append(up.targets, &backendTarget{raw: raw, url: u})
	}
	return up
}

func disabledBreakers() *breaker.Group {
	return breaker.NewGroup(config.BreakerConfig{Enabled: false}, metrics.New())
}

func TestPickRoundRobins(t *testing.T) {
	up := mustUpstream(t, "http://a:1", "http://b:2", "http://c:3")
	g := disabledBreakers()

	seen := map[string]int{}
	for i := 0; i < 30; i++ {
		target, ok := up.pick(g)
		if !ok {
			t.Fatal("pick should succeed when backends are healthy")
		}
		seen[target.raw]++
	}
	if len(seen) != 3 {
		t.Fatalf("expected all 3 backends to be used, got %v", seen)
	}
	for backend, n := range seen {
		if n != 10 {
			t.Errorf("backend %s served %d of 30, want an even 10", backend, n)
		}
	}
}

func TestPickSkipsOpenBreakers(t *testing.T) {
	up := mustUpstream(t, "http://a:1", "http://b:2")
	g := breaker.NewGroup(config.BreakerConfig{
		Enabled: true, WindowSize: 10, ErrorThreshold: 0.5, CooldownMs: 60000, MinRequests: 5,
	}, metrics.New())

	// Drive the first backend's circuit open.
	for i := 0; i < 10; i++ {
		g.Record("http://a:1", false)
	}
	if g.State("http://a:1") != "open" {
		t.Fatal("precondition: backend a should be open")
	}

	for i := 0; i < 10; i++ {
		target, ok := up.pick(g)
		if !ok {
			t.Fatal("a healthy sibling remains, so pick should succeed")
		}
		if target.raw != "http://b:2" {
			t.Fatalf("pick returned %s, want the healthy backend", target.raw)
		}
	}
}

func TestPickFailsWhenAllOpen(t *testing.T) {
	up := mustUpstream(t, "http://a:1", "http://b:2")
	g := breaker.NewGroup(config.BreakerConfig{
		Enabled: true, WindowSize: 10, ErrorThreshold: 0.5, CooldownMs: 60000, MinRequests: 5,
	}, metrics.New())
	for i := 0; i < 10; i++ {
		g.Record("http://a:1", false)
		g.Record("http://b:2", false)
	}
	if _, ok := up.pick(g); ok {
		t.Fatal("pick should fail when every backend circuit is open")
	}
}

func TestBackendKeyIgnoresPath(t *testing.T) {
	u, _ := url.Parse("http://backend:8080/some/path?q=1")
	if got := backendKey(u); got != "http://backend:8080" {
		t.Errorf("backendKey = %q, want the scheme and host only", got)
	}
}
