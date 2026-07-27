// Command gowafyourself is a Web Application Firewall reverse proxy: a data
// plane that inspects and forwards traffic, plus a control console for
// operating it live.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/caddyserver/certmagic"

	"github.com/example/gowafyourself/internal/admission"
	"github.com/example/gowafyourself/internal/breaker"
	"github.com/example/gowafyourself/internal/config"
	"github.com/example/gowafyourself/internal/logstore"
	"github.com/example/gowafyourself/internal/metrics"
	"github.com/example/gowafyourself/internal/panel"
	"github.com/example/gowafyourself/internal/proxy"
	"github.com/example/gowafyourself/internal/waf"
)

// version is overridable at build time:
//
//	go build -ldflags "-X main.version=1.0.0" ./cmd/gowafyourself
var version = "dev"

func main() {
	configPath := flag.String("config", "config.json", "path to the JSON config file")
	checkOnly := flag.Bool("check", false, "validate the config and rule set, then exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("gowafyourself", version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("gowafyourself: %v", err)
	}
	mgr := config.NewManager(*configPath, cfg)

	m := metrics.New()

	logger, err := logstore.New(cfg.Logging)
	if err != nil {
		log.Fatalf("gowafyourself: logging: %v", err)
	}

	engine, err := waf.New(cfg.WAF)
	if err != nil {
		log.Fatalf("gowafyourself: waf: %v", err)
	}

	// --check compiles everything (config + full rule set) and exits, so a bad
	// deploy fails in CI rather than at runtime.
	if *checkOnly {
		_ = logger.Close()
		fmt.Printf("config OK: %d upstream(s), waf=%s, rules compiled\n", len(cfg.Upstreams), cfg.WAF.Mode)
		return
	}

	admit := admission.New(cfg.Admission.MaxConcurrent, cfg.Admission.QueueSize, cfg.Admission.QueueTimeoutMs, m)
	brk := breaker.NewGroup(cfg.Breaker, m)

	dp, err := proxy.NewDataPlane(mgr, m, admit, brk, engine, logger)
	if err != nil {
		log.Fatalf("gowafyourself: data plane: %v", err)
	}

	// applyConfig re-applies the current config to every live component. It is
	// the single path used by both SIGHUP and console edits, so the two can
	// never drift apart.
	//
	// The rule engine is only rebuilt when a directive-affecting setting
	// changed: recompiling the CRS is expensive, and the common operations
	// (flipping mode, editing upstreams) do not need it.
	var applyMu sync.Mutex
	engineFP := waf.Fingerprint(cfg.WAF)
	applyConfig := func() error {
		applyMu.Lock()
		defer applyMu.Unlock()

		c := mgr.Get()
		brk.UpdateConfig(c.Breaker)
		if err := admit.SetLimit(c.Admission.MaxConcurrent); err != nil {
			return err
		}
		admit.SetQueue(c.Admission.QueueSize, c.Admission.QueueTimeoutMs)

		if fp := waf.Fingerprint(c.WAF); fp != engineFP {
			newEngine, err := waf.New(c.WAF)
			if err != nil {
				// Keep serving with the engine we have rather than going dark.
				return fmt.Errorf("rule engine rebuild failed, keeping previous rules: %w", err)
			}
			dp.SetEngine(newEngine)
			engineFP = fp
			log.Printf("gowafyourself: rule engine rebuilt")
		}
		return dp.Rebuild()
	}

	pnl := panel.New(mgr, m, dp, admit, logger, applyConfig)

	var servers []*http.Server

	// Plaintext HTTP data plane.
	if cfg.Listen.HTTP != "" {
		s := &http.Server{Addr: cfg.Listen.HTTP, Handler: dp, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, s)
		go func() {
			log.Printf("gowafyourself: http data plane on %s", s.Addr)
			if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("gowafyourself: http listener: %v", err)
			}
		}()
	}

	// TLS data plane.
	if cfg.Listen.HTTPS != "" && cfg.TLS.Mode != "off" {
		s, certFile, keyFile, err := buildHTTPSServer(cfg, dp)
		if err != nil {
			log.Fatalf("gowafyourself: tls setup: %v", err)
		}
		servers = append(servers, s)
		go func() {
			log.Printf("gowafyourself: https data plane on %s (tls=%s)", s.Addr, cfg.TLS.Mode)
			if err := s.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("gowafyourself: https listener: %v", err)
			}
		}()
	}

	// Control console.
	if cfg.Panel.Enabled {
		if cfg.Panel.User == "" || cfg.Panel.Pass == "" {
			log.Printf("gowafyourself: console enabled but panel.user/panel.pass are unset — it will refuse requests until they are configured")
		}
		ps := &http.Server{Addr: cfg.Listen.Panel, Handler: pnl.Handler(), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, ps)
		go func() {
			log.Printf("gowafyourself: console on %s", ps.Addr)
			if err := ps.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("gowafyourself: console listener: %v", err)
			}
		}()
	}

	if len(servers) == 0 {
		log.Fatalf("gowafyourself: nothing to serve (check listen.http, listen.https, and panel.enabled)")
	}

	// SIGHUP reloads config; SIGINT/SIGTERM drain and exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		switch s {
		case syscall.SIGHUP:
			if err := mgr.Reload(); err != nil {
				log.Printf("gowafyourself: reload failed, keeping current config: %v", err)
				continue
			}
			if err := applyConfig(); err != nil {
				log.Printf("gowafyourself: reload applied partially: %v", err)
				continue
			}
			log.Printf("gowafyourself: config reloaded")

		case syscall.SIGINT, syscall.SIGTERM:
			log.Printf("gowafyourself: draining...")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			var wg sync.WaitGroup
			for _, srv := range servers {
				wg.Add(1)
				go func(sv *http.Server) {
					defer wg.Done()
					_ = sv.Shutdown(ctx)
				}(srv)
			}
			wg.Wait()
			cancel()
			_ = logger.Close()
			log.Printf("gowafyourself: stopped")
			return
		}
	}
}

// buildHTTPSServer prepares the HTTPS data-plane server. For manual TLS it
// returns the cert/key paths to hand to ListenAndServeTLS; for ACME it attaches
// a CertMagic-managed tls.Config and returns empty paths.
//
// NOTE: the CertMagic API used here (DefaultACME fields, NewDefault, ManageSync,
// TLSConfig) follows the current caddyserver/certmagic release; adjust if you
// pin a materially different version.
func buildHTTPSServer(cfg *config.Config, h http.Handler) (*http.Server, string, string, error) {
	s := &http.Server{Addr: cfg.Listen.HTTPS, Handler: h, ReadHeaderTimeout: 10 * time.Second}

	if cfg.TLS.Mode == "manual" {
		return s, cfg.TLS.CertFile, cfg.TLS.KeyFile, nil
	}

	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.Email = cfg.TLS.ACMEEmail
	if cfg.TLS.ACMEStaging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	} else {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	}
	certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.TLS.ACMECacheDir}

	magic := certmagic.NewDefault()
	domains := gatherDomains(cfg)
	if len(domains) == 0 {
		log.Printf("gowafyourself: tls.mode=acme but no upstream hosts to obtain certificates for")
	}
	if err := magic.ManageSync(context.Background(), domains); err != nil {
		return nil, "", "", err
	}
	tlsCfg := magic.TLSConfig()
	tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	tlsCfg.MinVersion = tls.VersionTLS12
	s.TLSConfig = tlsCfg
	return s, "", "", nil
}

// gatherDomains collects unique upstream hostnames for certificate issuance.
func gatherDomains(cfg *config.Config) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range cfg.Upstreams {
		if u.Host != "" && !seen[u.Host] {
			seen[u.Host] = true
			out = append(out, u.Host)
		}
	}
	return out
}
