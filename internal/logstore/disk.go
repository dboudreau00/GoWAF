package logstore

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// diskSink appends events as newline-delimited JSON and rotates the file once
// it exceeds rotateBytes (0 disables rotation).
type diskSink struct {
	mu          sync.Mutex
	path        string
	rotateBytes int64
	f           *os.File
	w           *bufio.Writer
	size        int64
}

func newDiskSink(path string, rotateMB int) (*diskSink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("logstore/disk: mkdir: %w", err)
	}
	d := &diskSink{path: path, rotateBytes: int64(rotateMB) << 20}
	if err := d.open(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *diskSink) open() error {
	f, err := os.OpenFile(d.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("logstore/disk: open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	d.f = f
	d.w = bufio.NewWriter(f)
	d.size = info.Size()
	return nil
}

func (d *diskSink) rotate() error {
	if err := d.w.Flush(); err != nil {
		return err
	}
	if err := d.f.Close(); err != nil {
		return err
	}
	ts := time.Now().Format("20060102-150405")
	if err := os.Rename(d.path, d.path+"."+ts); err != nil {
		return err
	}
	return d.open()
}

func (d *diskSink) Write(evts []Event) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range evts {
		b, err := json.Marshal(e)
		if err != nil {
			continue // skip an unserializable event rather than fail the batch
		}
		b = append(b, '\n')
		n, err := d.w.Write(b)
		if err != nil {
			return err
		}
		d.size += int64(n)
		if d.rotateBytes > 0 && d.size >= d.rotateBytes {
			if err := d.rotate(); err != nil {
				return err
			}
		}
	}
	return d.w.Flush()
}

func (d *diskSink) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.w != nil {
		_ = d.w.Flush()
	}
	if d.f != nil {
		return d.f.Close()
	}
	return nil
}

// stdoutSink writes events as JSON lines to stdout (useful for container logging
// or piping into a collector).
type stdoutSink struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func newStdoutSink() *stdoutSink {
	return &stdoutSink{w: bufio.NewWriter(os.Stdout)}
}

func (s *stdoutSink) Write(evts []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enc := json.NewEncoder(s.w)
	for _, e := range evts {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return s.w.Flush()
}

func (s *stdoutSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Flush()
}
