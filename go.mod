module github.com/example/gowafyourself

go 1.23

// Dependencies are intentionally not pinned here. Run `go mod tidy` (or
// `make deps`) on a machine with network access to resolve them and generate
// go.sum. The modules pulled in will be:
//
//   github.com/corazawaf/coraza/v3               (WAF engine)
//   github.com/corazawaf/coraza-coreruleset/v4   (embedded OWASP Core Rule Set)
//   github.com/caddyserver/certmagic             (automatic TLS via ACME)
//   github.com/aws/aws-sdk-go-v2                  (S3 log sink)
//   github.com/aws/aws-sdk-go-v2/config
//   github.com/aws/aws-sdk-go-v2/credentials
//   github.com/aws/aws-sdk-go-v2/service/s3
