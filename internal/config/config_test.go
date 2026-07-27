package config

import (
	"os"
	"path/filepath"
	"testing"
)

func validConfig() *Config {
	c := &Config{
		Upstreams: []UpstreamConfig{{Host: "app.example.com", Target: "http://127.0.0.1:3000"}},
	}
	c.applyDefaults()
	return c
}

func TestDefaultsAreUsable(t *testing.T) {
	c := validConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("a config with only upstreams set should validate, got: %v", err)
	}
	if c.WAF.Mode != ModeBlock {
		t.Errorf("default waf mode = %q, want %q", c.WAF.Mode, ModeBlock)
	}
	if c.Admission.MaxConcurrent <= 0 {
		t.Error("maxConcurrent should get a positive default")
	}
	if c.Listen.Panel == "" {
		t.Error("the console should get a default bind address")
	}
	if c.WAF.MaxResponseBodyBytes <= 0 {
		t.Error("maxResponseBodyBytes should get a positive default")
	}
}

func TestResponseBodyImpliesResponsePhase(t *testing.T) {
	c := validConfig()
	c.WAF.InspectResponseBody = true
	c.WAF.InspectResponse = false
	c.applyDefaults()
	if !c.WAF.InspectResponse {
		t.Error("inspecting response bodies must imply the response phase runs")
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no upstreams", func(c *Config) { c.Upstreams = nil }},
		{"empty host", func(c *Config) { c.Upstreams[0].Host = "" }},
		{"no target", func(c *Config) { c.Upstreams[0].Target = ""; c.Upstreams[0].Targets = nil }},
		{"bad target url", func(c *Config) { c.Upstreams[0].Target = "not-a-url" }},
		{"bad waf mode", func(c *Config) { c.WAF.Mode = "maybe" }},
		{"bad upstream mode", func(c *Config) { c.Upstreams[0].WAF = "sometimes" }},
		{"bad tls mode", func(c *Config) { c.TLS.Mode = "wishful" }},
		{"paranoia too high", func(c *Config) { c.WAF.ParanoiaLevel = 9 }},
		{"concurrency zero", func(c *Config) { c.Admission.MaxConcurrent = 0 }},
		{"threshold above one", func(c *Config) { c.Breaker.ErrorThreshold = 1.5 }},
		{"duplicate hosts", func(c *Config) {
			c.Upstreams = append(c.Upstreams, UpstreamConfig{
				Host: "APP.example.com", Target: "http://127.0.0.1:4000"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig()
			tc.mutate(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
		})
	}
}

func TestManualTLSRequiresCertAndKey(t *testing.T) {
	c := validConfig()
	c.TLS.Mode = "manual"
	c.Listen.HTTPS = ":8443"
	if err := c.Validate(); err == nil {
		t.Fatal("manual TLS without cert/key should be rejected")
	}
	c.TLS.CertFile, c.TLS.KeyFile = "cert.pem", "key.pem"
	if err := c.Validate(); err != nil {
		t.Fatalf("manual TLS with cert/key should validate, got: %v", err)
	}
}

func TestTLSRequiresHTTPSListener(t *testing.T) {
	c := validConfig()
	c.TLS.Mode = "acme"
	c.Listen.HTTPS = ""
	if err := c.Validate(); err == nil {
		t.Fatal("enabling TLS without an https listen address should be rejected")
	}
}

func TestBackendsPrefersTargetsList(t *testing.T) {
	u := UpstreamConfig{Target: "http://a", Targets: []string{"http://b", "http://c"}}
	got := u.Backends()
	if len(got) != 2 || got[0] != "http://b" {
		t.Fatalf("Backends() = %v, want the targets list to win", got)
	}
	single := UpstreamConfig{Target: "http://a"}
	if got := single.Backends(); len(got) != 1 || got[0] != "http://a" {
		t.Fatalf("Backends() = %v, want the single target", got)
	}
	if got := (UpstreamConfig{}).Backends(); len(got) != 0 {
		t.Fatalf("Backends() = %v, want empty when nothing is configured", got)
	}
}

func TestEffectiveModeOverride(t *testing.T) {
	c := validConfig()
	c.WAF.Mode = ModeBlock
	if got := c.EffectiveMode(UpstreamConfig{}); got != ModeBlock {
		t.Errorf("an upstream with no mode should inherit the global one, got %q", got)
	}
	if got := c.EffectiveMode(UpstreamConfig{WAF: ModeDetect}); got != ModeDetect {
		t.Errorf("an upstream mode should override the global one, got %q", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	orig := validConfig()
	orig.WAF.Mode = ModeDetect
	orig.Admission.MaxConcurrent = 42
	orig.WAF.InspectResponse = true
	if err := Save(path, orig); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.WAF.Mode != ModeDetect {
		t.Errorf("mode did not survive the round trip: %q", loaded.WAF.Mode)
	}
	if loaded.Admission.MaxConcurrent != 42 {
		t.Errorf("maxConcurrent did not survive the round trip: %d", loaded.Admission.MaxConcurrent)
	}
	if !loaded.WAF.InspectResponse {
		t.Error("inspectResponse did not survive the round trip")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{"upstreams":[{"host":"a.example.com","target":"http://127.0.0.1:1"}],"nonsense":true}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a typo'd config key should be reported, not silently ignored")
	}
}

func TestManagerHotSwap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	initial := validConfig()
	if err := Save(path, initial); err != nil {
		t.Fatal(err)
	}
	m := NewManager(path, initial)

	next := validConfig()
	next.WAF.Mode = ModeOff
	if err := m.Set(next); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if m.Get().WAF.Mode != ModeOff {
		t.Error("Set should swap in the new config")
	}

	// Set persists, so a Reload from disk must see the same value.
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if m.Get().WAF.Mode != ModeOff {
		t.Error("Set should have persisted the change to disk")
	}
}

func TestManagerRejectsInvalidSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	initial := validConfig()
	if err := Save(path, initial); err != nil {
		t.Fatal(err)
	}
	m := NewManager(path, initial)

	bad := validConfig()
	bad.Upstreams = nil
	if err := m.Set(bad); err == nil {
		t.Fatal("Set should reject an invalid config")
	}
	if len(m.Get().Upstreams) == 0 {
		t.Fatal("a rejected Set must leave the live config untouched")
	}
}
