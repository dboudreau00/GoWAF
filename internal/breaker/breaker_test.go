package breaker

import (
	"testing"
	"time"

	"github.com/example/gowafyourself/internal/config"
	"github.com/example/gowafyourself/internal/metrics"
)

func testConfig() config.BreakerConfig {
	return config.BreakerConfig{
		Enabled:        true,
		WindowSize:     10,
		ErrorThreshold: 0.5,
		CooldownMs:     50,
		MinRequests:    5,
	}
}

const backend = "http://127.0.0.1:3000"

func newGroup(t *testing.T, cfg config.BreakerConfig) *Group {
	t.Helper()
	return NewGroup(cfg, metrics.New())
}

func TestClosedWhileHealthy(t *testing.T) {
	g := newGroup(t, testConfig())
	for i := 0; i < 20; i++ {
		if !g.Allow(backend) {
			t.Fatalf("healthy backend should be allowed (iteration %d)", i)
		}
		g.Record(backend, true)
	}
	if got := g.State(backend); got != "closed" {
		t.Fatalf("state = %q, want closed", got)
	}
}

func TestOpensOnSustainedFailure(t *testing.T) {
	g := newGroup(t, testConfig())
	for i := 0; i < 10; i++ {
		g.Record(backend, false)
	}
	if got := g.State(backend); got != "open" {
		t.Fatalf("state = %q, want open after sustained failure", got)
	}
	if g.Allow(backend) {
		t.Fatal("an open breaker must fast-fail during cooldown")
	}
}

func TestMinRequestsGuard(t *testing.T) {
	g := newGroup(t, testConfig())
	// Below MinRequests the breaker must not trip, even at a 100% error rate.
	for i := 0; i < 4; i++ {
		g.Record(backend, false)
	}
	if got := g.State(backend); got != "closed" {
		t.Fatalf("state = %q, want closed below the minimum sample count", got)
	}
}

func TestIsolatedErrorDoesNotTrip(t *testing.T) {
	cfg := testConfig()
	cfg.WindowSize = 20
	g := newGroup(t, cfg)
	for i := 0; i < 20; i++ {
		g.Record(backend, i != 7) // one blip in an otherwise healthy window
	}
	if got := g.State(backend); got != "closed" {
		t.Fatalf("state = %q, want closed; an isolated error must not trip it", got)
	}
}

// TestHalfOpenProbeCloses is the regression test for the bug the model caught:
// a successful probe must close the breaker outright, even though the stale
// pre-cooldown window is still full of failures.
func TestHalfOpenProbeCloses(t *testing.T) {
	g := newGroup(t, testConfig())
	for i := 0; i < 10; i++ {
		g.Record(backend, false)
	}
	if g.State(backend) != "open" {
		t.Fatal("precondition: breaker should be open")
	}

	time.Sleep(70 * time.Millisecond) // outlast the 50ms cooldown

	if !g.Allow(backend) {
		t.Fatal("a probe should be permitted once the cooldown elapses")
	}
	if got := g.State(backend); got != "half-open" {
		t.Fatalf("state = %q, want half-open after the cooldown", got)
	}

	g.Record(backend, true)
	if got := g.State(backend); got != "closed" {
		t.Fatalf("state = %q, want closed; a healthy probe must re-close the breaker "+
			"despite the stale failure window", got)
	}
}

func TestHalfOpenFailureReopens(t *testing.T) {
	g := newGroup(t, testConfig())
	for i := 0; i < 10; i++ {
		g.Record(backend, false)
	}
	time.Sleep(70 * time.Millisecond)
	if !g.Allow(backend) {
		t.Fatal("probe should be permitted")
	}
	g.Record(backend, false)
	if got := g.State(backend); got != "open" {
		t.Fatalf("state = %q, want open after a failed probe", got)
	}
	if g.Allow(backend) {
		t.Fatal("a failed probe must restart the cooldown")
	}
}

func TestBackendsAreIsolated(t *testing.T) {
	g := newGroup(t, testConfig())
	const sick = "http://127.0.0.1:3001"
	for i := 0; i < 10; i++ {
		g.Record(sick, false)
		g.Record(backend, true)
	}
	if g.State(sick) != "open" {
		t.Fatal("the failing backend should be open")
	}
	if got := g.State(backend); got != "closed" {
		t.Fatalf("healthy backend state = %q; one sick backend must not condemn its siblings", got)
	}
	if !g.Allow(backend) {
		t.Fatal("the healthy backend should still accept traffic")
	}
}

func TestDisabledAlwaysAllows(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	g := newGroup(t, cfg)
	for i := 0; i < 50; i++ {
		g.Record(backend, false)
		if !g.Allow(backend) {
			t.Fatal("a disabled breaker must never block")
		}
	}
	if got := g.State(backend); got != "disabled" {
		t.Fatalf("state = %q, want disabled", got)
	}
}

func TestUpdateConfigResetsState(t *testing.T) {
	g := newGroup(t, testConfig())
	for i := 0; i < 10; i++ {
		g.Record(backend, false)
	}
	if g.State(backend) != "open" {
		t.Fatal("precondition: breaker should be open")
	}
	g.UpdateConfig(testConfig())
	if got := g.State(backend); got != "closed" {
		t.Fatalf("state = %q, want closed; reconfiguring should clear breaker state", got)
	}
}
