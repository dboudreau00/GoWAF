package waf

import (
	"io"
	"strings"
	"testing"
)

// TestBoundedReadSmallBody: a body under the limit is inspected whole and
// forwarded whole.
func TestBoundedReadSmallBody(t *testing.T) {
	const body = "hello world"
	inspect, restore, err := boundedRead(io.NopCloser(strings.NewReader(body)), 1024)
	if err != nil {
		t.Fatalf("boundedRead: %v", err)
	}
	if string(inspect) != body {
		t.Errorf("inspected %q, want the whole body %q", inspect, body)
	}
	forwarded, _ := io.ReadAll(restore)
	if string(forwarded) != body {
		t.Errorf("forwarded %q, want %q", forwarded, body)
	}
}

// TestBoundedReadExactlyAtLimit: a body exactly at the limit is not treated as
// oversized.
func TestBoundedReadExactlyAtLimit(t *testing.T) {
	body := strings.Repeat("x", 64)
	inspect, restore, err := boundedRead(io.NopCloser(strings.NewReader(body)), 64)
	if err != nil {
		t.Fatalf("boundedRead: %v", err)
	}
	if len(inspect) != 64 {
		t.Errorf("inspected %d bytes, want 64", len(inspect))
	}
	forwarded, _ := io.ReadAll(restore)
	if string(forwarded) != body {
		t.Errorf("forwarded %d bytes, want the full 64", len(forwarded))
	}
}

// TestBoundedReadOversizedForwardsEverything is the regression test for the
// truncation bug: only the bounded prefix is inspected, but the ENTIRE body
// must still reach the upstream. Truncating here would silently corrupt large
// uploads.
func TestBoundedReadOversizedForwardsEverything(t *testing.T) {
	const total = 5000
	const limit = 1000
	body := strings.Repeat("A", limit) + strings.Repeat("B", total-limit)

	inspect, restore, err := boundedRead(io.NopCloser(strings.NewReader(body)), limit)
	if err != nil {
		t.Fatalf("boundedRead: %v", err)
	}
	if len(inspect) != limit {
		t.Errorf("inspected %d bytes, want the bounded prefix of %d", len(inspect), limit)
	}
	if strings.Contains(string(inspect), "B") {
		t.Error("inspection buffer should stop at the limit")
	}

	forwarded, err := io.ReadAll(restore)
	if err != nil {
		t.Fatalf("reading the restored body: %v", err)
	}
	if len(forwarded) != total {
		t.Fatalf("forwarded %d bytes, want the full %d — the body was truncated in transit",
			len(forwarded), total)
	}
	if string(forwarded) != body {
		t.Error("forwarded body does not match the original byte-for-byte")
	}
}

func TestBoundedReadEmptyBody(t *testing.T) {
	inspect, restore, err := boundedRead(io.NopCloser(strings.NewReader("")), 1024)
	if err != nil {
		t.Fatalf("boundedRead: %v", err)
	}
	if len(inspect) != 0 {
		t.Errorf("inspected %d bytes, want 0", len(inspect))
	}
	forwarded, _ := io.ReadAll(restore)
	if len(forwarded) != 0 {
		t.Errorf("forwarded %d bytes, want 0", len(forwarded))
	}
}

func TestBoundedReadZeroLimitStillForwards(t *testing.T) {
	const body = "payload"
	inspect, restore, err := boundedRead(io.NopCloser(strings.NewReader(body)), 0)
	if err != nil {
		t.Fatalf("boundedRead: %v", err)
	}
	if len(inspect) != 0 {
		t.Errorf("inspected %d bytes, want 0 with a zero limit", len(inspect))
	}
	forwarded, _ := io.ReadAll(restore)
	if string(forwarded) != body {
		t.Errorf("forwarded %q, want the body intact even when nothing is inspected", forwarded)
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"192.0.2.10:54321", "192.0.2.10", 54321},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"192.0.2.10", "192.0.2.10", 0},
		{"", "", 0},
	}
	for _, tc := range cases {
		host, port := splitHostPort(tc.in)
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)",
				tc.in, host, port, tc.wantHost, tc.wantPort)
		}
	}
}
