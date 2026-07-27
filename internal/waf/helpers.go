package waf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/example/gowafyourself/internal/config"
)

// splitHostPort splits "ip:port" (as found in http.Request.RemoteAddr) into a
// host string and integer port, tolerating a missing or malformed port.
func splitHostPort(remoteAddr string) (string, int) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, 0 // no port present; treat it all as the host
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

// readFile returns the textual contents of a file.
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Fingerprint summarizes every setting that affects the compiled rule set.
// The caller rebuilds the engine only when this value changes, which keeps the
// cheap operations cheap: switching between block/detect/off does not alter the
// fingerprint, because the engine always runs enforcing and the data plane
// decides what to do with an interruption.
//
// The custom rules file is hashed by content rather than by path, so editing
// rules in place and sending SIGHUP does pick up the change.
func Fingerprint(c config.WAFConfig) string {
	h := sha256.New()
	fmt.Fprintf(h, "reqbody=%v:%d\n", c.InspectBody, c.MaxBodyBytes)
	fmt.Fprintf(h, "resp=%v respbody=%v:%d\n", c.InspectResponse, c.InspectResponseBody, c.MaxResponseBodyBytes)
	fmt.Fprintf(h, "pl=%d in=%d out=%d\n", c.ParanoiaLevel, c.AnomalyThreshold, c.OutboundAnomalyThreshold)
	fmt.Fprintf(h, "rules=%s\n", c.CustomRulesPath)
	if c.CustomRulesPath != "" {
		if b, err := os.ReadFile(c.CustomRulesPath); err == nil {
			h.Write(b)
		} else {
			// An unreadable rules file is itself a distinct state: fingerprinting
			// the error means a later successful read triggers a rebuild.
			fmt.Fprintf(h, "unreadable:%v\n", err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
