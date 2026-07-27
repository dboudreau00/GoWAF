// Package config defines the on-disk configuration schema for gowafyourself and a
// thread-safe holder that supports atomic hot-reload (used by SIGHUP and by
// the control panel when it mutates settings).
package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

// Config is the full configuration document (serialized as JSON on disk).
type Config struct {
	Listen    ListenConfig     `json:"listen"`
	TLS       TLSConfig        `json:"tls"`
	Upstreams []UpstreamConfig `json:"upstreams"`
	Admission AdmissionConfig  `json:"admission"`
	Breaker   BreakerConfig    `json:"breaker"`
	WAF       WAFConfig        `json:"waf"`
	Logging   LoggingConfig    `json:"logging"`
	Panel     PanelConfig      `json:"panel"`
}

type ListenConfig struct {
	HTTP  string `json:"http"`  // e.g. ":8080" ("" disables the plaintext listener)
	HTTPS string `json:"https"` // e.g. ":8443" ("" disables the TLS listener)
	Panel string `json:"panel"` // e.g. "127.0.0.1:9000" (bind to loopback in production)
}

// TLSConfig selects how the HTTPS listener obtains certificates.
//
//	mode "off"    -> no HTTPS listener
//	mode "manual" -> load CertFile/KeyFile from disk
//	mode "acme"   -> CertMagic auto-provisions per-host certs via Let's Encrypt
type TLSConfig struct {
	Mode         string `json:"mode"`
	CertFile     string `json:"certFile"`
	KeyFile      string `json:"keyFile"`
	ACMEEmail    string `json:"acmeEmail"`
	ACMEStaging  bool   `json:"acmeStaging"`  // use LE staging endpoint while testing
	ACMECacheDir string `json:"acmeCacheDir"` // where CertMagic stores certs/keys
}

// UpstreamConfig maps an inbound Host header to one or more backend targets.
// A customer points a CNAME or A record at this proxy; we route on Host/SNI, so
// either DNS record type works identically.
type UpstreamConfig struct {
	Host    string   `json:"host"`            // e.g. "app.example.com"
	Target  string   `json:"target"`          // single backend, e.g. "http://127.0.0.1:3000"
	Targets []string `json:"targets"`         // optional pool for round-robin load balancing
	WAF     string   `json:"waf,omitempty"`   // "" inherits global; else "block"|"detect"|"off"
	Bypass  bool     `json:"bypass"`          // per-upstream bridge (force passthrough)
}

// Backends returns the effective target list (Targets if set, else the single Target).
func (u UpstreamConfig) Backends() []string {
	if len(u.Targets) > 0 {
		return u.Targets
	}
	if u.Target != "" {
		return []string{u.Target}
	}
	return nil
}

type AdmissionConfig struct {
	MaxConcurrent  int `json:"maxConcurrent"`  // in-flight requests allowed to reach the WAF/upstream
	QueueSize      int `json:"queueSize"`      // waiting room depth once MaxConcurrent is saturated
	QueueTimeoutMs int `json:"queueTimeoutMs"` // max time a request may wait in the queue
}

type BreakerConfig struct {
	Enabled        bool    `json:"enabled"`
	WindowSize     int     `json:"windowSize"`     // rolling sample count per backend
	ErrorThreshold float64 `json:"errorThreshold"` // 0..1; trip when error ratio exceeds this
	CooldownMs     int     `json:"cooldownMs"`     // open duration before a half-open probe
	MinRequests    int     `json:"minRequests"`    // min samples before the breaker may trip
}

// WAFMode is the enforcement posture.
const (
	ModeBlock  = "block"  // matched requests are rejected
	ModeDetect = "detect" // matched requests are logged but allowed through
	ModeOff    = "off"    // WAF evaluation skipped entirely
)

type WAFConfig struct {
	Mode         string `json:"mode"`         // block|detect|off (global default)
	InspectBody  bool   `json:"inspectBody"`  // buffer & inspect request bodies
	MaxBodyBytes int64  `json:"maxBodyBytes"` // cap on buffered request body (bytes)

	// Response-phase inspection. Headers are always inspected when a phase is
	// run; body inspection additionally buffers up to MaxResponseBodyBytes,
	// which costs memory and latency, so it is opt-in.
	InspectResponse          bool  `json:"inspectResponse"`          // run response-phase rules at all
	InspectResponseBody      bool  `json:"inspectResponseBody"`      // also buffer & inspect response bodies
	MaxResponseBodyBytes     int64 `json:"maxResponseBodyBytes"`     // cap on buffered response body (bytes)
	OutboundAnomalyThreshold int   `json:"outboundAnomalyThreshold"` // CRS outbound anomaly score threshold (0=CRS default)

	ParanoiaLevel      int    `json:"paranoiaLevel"`      // CRS paranoia level 1..4
	AnomalyThreshold   int    `json:"anomalyThreshold"`   // CRS inbound anomaly score threshold
	CustomRulesPath    string `json:"customRulesPath"`    // optional extra SecLang file to inline
	AutoBypassOnPanics int    `json:"autoBypassOnPanics"` // if >0, flip global bypass after N WAF panics (0=off)
}

type LoggingConfig struct {
	Sink            string   `json:"sink"`            // "disk"|"s3"|"both"|"stdout"|"none"
	DiskPath        string   `json:"diskPath"`        // JSONL file path for the disk sink
	RotateMB        int      `json:"rotateMB"`        // rotate the disk file at this size (0=never)
	FlushIntervalMs int      `json:"flushIntervalMs"` // max latency before buffered events are flushed
	BufferSize      int      `json:"bufferSize"`      // in-memory event channel capacity
	S3              S3Config `json:"s3"`
}

type S3Config struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region"`
	Prefix          string `json:"prefix"`          // key prefix, e.g. "waf-logs/"
	AccessKeyID     string `json:"accessKeyId"`     // optional; empty => default AWS cred chain (env/role)
	SecretAccessKey string `json:"secretAccessKey"` // optional; pairs with AccessKeyID
	Endpoint        string `json:"endpoint"`        // optional; for S3-compatible stores (MinIO, R2)
	BatchSize       int    `json:"batchSize"`       // events per uploaded object
	FlushIntervalMs int    `json:"flushIntervalMs"` // max latency before a partial batch is uploaded
}

type PanelConfig struct {
	Enabled bool   `json:"enabled"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
}

// Load reads and parses a config file, then applies defaults and validates it.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Save atomically writes the config back to disk (write-temp-then-rename).
func Save(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (c *Config) applyDefaults() {
	if c.Listen.HTTP == "" && c.Listen.HTTPS == "" {
		c.Listen.HTTP = ":8080"
	}
	if c.Listen.Panel == "" {
		c.Listen.Panel = "127.0.0.1:9000"
	}
	if c.TLS.Mode == "" {
		c.TLS.Mode = "off"
	}
	if c.TLS.ACMECacheDir == "" {
		c.TLS.ACMECacheDir = "./certs"
	}
	if c.Admission.MaxConcurrent <= 0 {
		c.Admission.MaxConcurrent = 256
	}
	if c.Admission.QueueSize < 0 {
		c.Admission.QueueSize = 0
	}
	if c.Admission.QueueTimeoutMs <= 0 {
		c.Admission.QueueTimeoutMs = 3000
	}
	if c.Breaker.WindowSize <= 0 {
		c.Breaker.WindowSize = 50
	}
	if c.Breaker.ErrorThreshold <= 0 {
		c.Breaker.ErrorThreshold = 0.5
	}
	if c.Breaker.CooldownMs <= 0 {
		c.Breaker.CooldownMs = 10000
	}
	if c.Breaker.MinRequests <= 0 {
		c.Breaker.MinRequests = 20
	}
	if c.WAF.Mode == "" {
		c.WAF.Mode = ModeBlock
	}
	if c.WAF.MaxBodyBytes <= 0 {
		c.WAF.MaxBodyBytes = 1 << 20 // 1 MiB
	}
	if c.WAF.MaxResponseBodyBytes <= 0 {
		c.WAF.MaxResponseBodyBytes = 512 << 10 // 512 KiB
	}
	// Body inspection implies the response phase runs at all.
	if c.WAF.InspectResponseBody {
		c.WAF.InspectResponse = true
	}
	if c.WAF.ParanoiaLevel <= 0 {
		c.WAF.ParanoiaLevel = 1
	}
	if c.WAF.AnomalyThreshold <= 0 {
		c.WAF.AnomalyThreshold = 5
	}
	if c.Logging.Sink == "" {
		c.Logging.Sink = "disk"
	}
	if c.Logging.DiskPath == "" {
		c.Logging.DiskPath = "./logs/events.jsonl"
	}
	if c.Logging.FlushIntervalMs <= 0 {
		c.Logging.FlushIntervalMs = 1000
	}
	if c.Logging.BufferSize <= 0 {
		c.Logging.BufferSize = 4096
	}
	if c.Logging.S3.BatchSize <= 0 {
		c.Logging.S3.BatchSize = 500
	}
	if c.Logging.S3.FlushIntervalMs <= 0 {
		c.Logging.S3.FlushIntervalMs = 5000
	}
	if c.Logging.S3.Prefix == "" {
		c.Logging.S3.Prefix = "waf-logs/"
	}
}

// Validate performs basic sanity checks that would otherwise surface as
// confusing runtime failures.
func (c *Config) Validate() error {
	if len(c.Upstreams) == 0 {
		return fmt.Errorf("config: at least one upstream is required")
	}
	seen := map[string]bool{}
	for i, u := range c.Upstreams {
		if u.Host == "" {
			return fmt.Errorf("config: upstreams[%d].host is empty", i)
		}
		host := strings.ToLower(u.Host)
		if seen[host] {
			return fmt.Errorf("config: duplicate upstream host %q", u.Host)
		}
		seen[host] = true
		backends := u.Backends()
		if len(backends) == 0 {
			return fmt.Errorf("config: upstream %q has no target/targets", u.Host)
		}
		for _, b := range backends {
			pu, err := url.Parse(b)
			if err != nil || pu.Scheme == "" || pu.Host == "" {
				return fmt.Errorf("config: upstream %q has invalid target %q", u.Host, b)
			}
		}
		if u.WAF != "" && u.WAF != ModeBlock && u.WAF != ModeDetect && u.WAF != ModeOff {
			return fmt.Errorf("config: upstream %q has invalid waf mode %q", u.Host, u.WAF)
		}
	}
	switch c.TLS.Mode {
	case "off", "manual", "acme":
	default:
		return fmt.Errorf("config: tls.mode must be off|manual|acme, got %q", c.TLS.Mode)
	}
	if c.TLS.Mode == "manual" && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return fmt.Errorf("config: tls.mode=manual requires certFile and keyFile")
	}
	if c.TLS.Mode != "off" && c.Listen.HTTPS == "" {
		return fmt.Errorf("config: tls.mode=%s requires listen.https to be set", c.TLS.Mode)
	}
	switch c.WAF.Mode {
	case ModeBlock, ModeDetect, ModeOff:
	default:
		return fmt.Errorf("config: waf.mode must be block|detect|off, got %q", c.WAF.Mode)
	}
	if c.WAF.ParanoiaLevel < 1 || c.WAF.ParanoiaLevel > 4 {
		return fmt.Errorf("config: waf.paranoiaLevel must be 1..4, got %d", c.WAF.ParanoiaLevel)
	}
	// Keep in step with admission.MaxCapacity (duplicated here so the config
	// package stays free of internal imports).
	const maxConcurrentCeiling = 65536
	if c.Admission.MaxConcurrent < 1 || c.Admission.MaxConcurrent > maxConcurrentCeiling {
		return fmt.Errorf("config: admission.maxConcurrent must be 1..%d, got %d",
			maxConcurrentCeiling, c.Admission.MaxConcurrent)
	}
	if c.Breaker.ErrorThreshold <= 0 || c.Breaker.ErrorThreshold > 1 {
		return fmt.Errorf("config: breaker.errorThreshold must be in (0,1], got %v", c.Breaker.ErrorThreshold)
	}
	return nil
}

// Manager holds the active *Config behind an atomic pointer so readers on the
// hot path never take a lock, while reloads swap the whole document at once.
type Manager struct {
	path string
	cur  atomic.Pointer[Config]
}

func NewManager(path string, initial *Config) *Manager {
	m := &Manager{path: path}
	m.cur.Store(initial)
	return m
}

// Get returns the current config snapshot. Safe for concurrent use.
func (m *Manager) Get() *Config { return m.cur.Load() }

// Path returns the backing file path.
func (m *Manager) Path() string { return m.path }

// Set validates and swaps in a new config, persisting it to disk.
func (m *Manager) Set(c *Config) error {
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return err
	}
	if err := Save(m.path, c); err != nil {
		return err
	}
	m.cur.Store(c)
	return nil
}

// Reload re-reads the config file from disk and swaps it in.
func (m *Manager) Reload() error {
	c, err := Load(m.path)
	if err != nil {
		return err
	}
	m.cur.Store(c)
	return nil
}

// EffectiveMode resolves a per-upstream mode against the global default.
func (c *Config) EffectiveMode(u UpstreamConfig) string {
	if u.WAF != "" {
		return u.WAF
	}
	return c.WAF.Mode
}
