// Package logstore provides an asynchronous, non-blocking event log for the
// data plane. Requests hand events to Log() which never blocks: if the buffer
// is full the event is dropped and counted, so logging pressure can never stall
// live traffic. A background goroutine batches events and fans them out to the
// configured sinks (disk JSONL and/or S3).
package logstore

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/gowafyourself/internal/config"
)

// Event is a single access/decision record.
type Event struct {
	Time       time.Time `json:"time"`
	RemoteAddr string    `json:"remoteAddr"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Query      string    `json:"query,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	Action     string    `json:"action"`          // allow|block|detect|queue_rejected|no_route|upstream_error
	Phase      string    `json:"phase,omitempty"` // request|response (which phase matched)
	RuleID     int       `json:"ruleId,omitempty"`
	RuleMsg    string    `json:"ruleMsg,omitempty"`
	Status     int       `json:"status"`
	Backend    string    `json:"backend,omitempty"`
	LatencyMs  int64     `json:"latencyMs,omitempty"`
	BytesIn    int64     `json:"bytesIn,omitempty"`
	BytesOut   int64     `json:"bytesOut,omitempty"`
	WAFMode    string    `json:"wafMode,omitempty"`
}

// Sink consumes batches of events. Implementations must be safe for use from
// the single pipeline goroutine and must not panic.
type Sink interface {
	Write(evts []Event) error
	Close() error
}

type Logger struct {
	ch      chan Event
	sinks   []Sink
	flush   time.Duration
	dropped atomic.Int64
	quit    chan struct{}
	done    chan struct{}
	once    sync.Once
}

// New builds a Logger from configuration, wiring up the requested sinks.
func New(cfg config.LoggingConfig) (*Logger, error) {
	var sinks []Sink
	switch cfg.Sink {
	case "none":
		// no sinks; events are still drained and discarded
	case "stdout":
		sinks = append(sinks, newStdoutSink())
	case "disk":
		d, err := newDiskSink(cfg.DiskPath, cfg.RotateMB)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, d)
	case "s3":
		s, err := newS3Sink(cfg.S3)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, s)
	case "both":
		d, err := newDiskSink(cfg.DiskPath, cfg.RotateMB)
		if err != nil {
			return nil, err
		}
		s, err := newS3Sink(cfg.S3)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, d, s)
	default:
		return nil, fmt.Errorf("logging: unknown sink %q (want disk|s3|both|stdout|none)", cfg.Sink)
	}

	l := &Logger{
		ch:    make(chan Event, cfg.BufferSize),
		sinks: sinks,
		flush: time.Duration(cfg.FlushIntervalMs) * time.Millisecond,
		quit:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go l.loop()
	return l, nil
}

// Log enqueues an event without blocking. If the buffer is full the event is
// dropped and the dropped counter is incremented.
func (l *Logger) Log(e Event) {
	select {
	case l.ch <- e:
	default:
		l.dropped.Add(1)
	}
}

// Dropped returns the number of events dropped due to buffer pressure.
func (l *Logger) Dropped() int64 { return l.dropped.Load() }

func (l *Logger) loop() {
	defer close(l.done)
	ticker := time.NewTicker(l.flush)
	defer ticker.Stop()

	batch := make([]Event, 0, 512)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		for _, s := range l.sinks {
			if err := s.Write(batch); err != nil {
				fmt.Fprintf(os.Stderr, "logstore: sink write error: %v\n", err)
			}
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-l.ch:
			batch = append(batch, e)
			if len(batch) >= 1024 {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-l.quit:
			// Drain whatever remains, then flush and exit.
			for {
				select {
				case e := <-l.ch:
					batch = append(batch, e)
				default:
					flush()
					return
				}
			}
		}
	}
}

// Close stops the pipeline, flushes buffered events, and closes all sinks.
func (l *Logger) Close() error {
	l.once.Do(func() {
		close(l.quit)
		<-l.done
		for _, s := range l.sinks {
			_ = s.Close()
		}
	})
	return nil
}
