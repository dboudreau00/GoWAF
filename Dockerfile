# Build stage -- needs network to resolve modules.
FROM golang:1.23-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod ./
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=docker" \
        -o /out/gowafyourself ./cmd/gowafyourself

# Runtime stage -- the OWASP rule set is embedded in the binary, so this stays tiny.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    adduser -D -H -u 10001 gowaf
WORKDIR /app
COPY --from=build /out/gowafyourself /usr/local/bin/gowafyourself
COPY rules/ /app/rules/
COPY config.example.json /app/config.example.json

# Logs and ACME certificates need to outlive the container.
VOLUME ["/app/logs", "/app/certs"]
EXPOSE 8080 8443 9000
USER gowaf

# The console binds to loopback by default; publish it deliberately or reach it
# through the container network rather than exposing it to the internet.
ENTRYPOINT ["gowafyourself"]
CMD ["-config", "/app/config.json"]
