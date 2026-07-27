package logstore

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	appcfg "github.com/example/gowafyourself/internal/config"
)

// s3Sink accumulates events and periodically flushes them to S3 as gzipped
// NDJSON objects. Request signing (SigV4) is handled entirely by the AWS SDK,
// so there is no hand-rolled cryptography here.
type s3Sink struct {
	client    *s3.Client
	bucket    string
	prefix    string
	batchSize int
	flush     time.Duration

	mu   sync.Mutex
	buf  []Event
	quit chan struct{}
	done chan struct{}
	once sync.Once
}

func newS3Sink(cfg appcfg.S3Config) (*s3Sink, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("logstore/s3: bucket is required for the s3 sink")
	}

	loadOpts := []func(*awscfg.LoadOptions) error{}
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awscfg.WithRegion(cfg.Region))
	}
	// If explicit keys are provided use them, otherwise fall back to the default
	// AWS credential chain (environment, shared config, or IAM instance role).
	if cfg.AccessKeyID != "" {
		loadOpts = append(loadOpts, awscfg.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		))
	}
	awsConf, err := awscfg.LoadDefaultConfig(context.Background(), loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("logstore/s3: load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsConf, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			// For S3-compatible stores (MinIO, Cloudflare R2, etc.).
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true
		}
	})

	s := &s3Sink{
		client:    client,
		bucket:    cfg.Bucket,
		prefix:    cfg.Prefix,
		batchSize: cfg.BatchSize,
		flush:     time.Duration(cfg.FlushIntervalMs) * time.Millisecond,
		quit:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

func (s *s3Sink) Write(evts []Event) error {
	s.mu.Lock()
	s.buf = append(s.buf, evts...)
	n := len(s.buf)
	s.mu.Unlock()
	if n >= s.batchSize {
		s.flushNow()
	}
	return nil
}

func (s *s3Sink) loop() {
	defer close(s.done)
	ticker := time.NewTicker(s.flush)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.flushNow()
		case <-s.quit:
			s.flushNow()
			return
		}
	}
}

// flushNow swaps out the current buffer and uploads it as one object.
func (s *s3Sink) flushNow() {
	s.mu.Lock()
	if len(s.buf) == 0 {
		s.mu.Unlock()
		return
	}
	batch := s.buf
	s.buf = nil
	s.mu.Unlock()

	payload, err := gzipNDJSON(batch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logstore/s3: encode: %v\n", err)
		return
	}

	key := s.objectKey(time.Now())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:          aws.String(s.bucket),
		Key:             aws.String(key),
		Body:            bytes.NewReader(payload),
		ContentType:     aws.String("application/x-ndjson"),
		ContentEncoding: aws.String("gzip"),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "logstore/s3: put %s: %v\n", key, err)
	}
}

func (s *s3Sink) objectKey(t time.Time) string {
	prefix := s.prefix
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	var r [6]byte
	_, _ = rand.Read(r[:])
	return fmt.Sprintf("%s%s/%s.ndjson.gz",
		prefix,
		t.UTC().Format("2006/01/02"),
		t.UTC().Format("15-04-05")+"-"+hex.EncodeToString(r[:]),
	)
}

func (s *s3Sink) Close() error {
	s.once.Do(func() {
		close(s.quit)
		<-s.done
	})
	return nil
}

func gzipNDJSON(evts []Event) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for _, e := range evts {
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
