BINARY  := gowafyourself
PKG     := ./cmd/gowafyourself
VERSION ?= dev

.PHONY: all deps build test vet fmt run check validate mockup docker clean

all: build

## deps: resolve modules and generate go.sum (needs network)
deps:
	go mod tidy

## build: compile the binary into ./bin
build: deps
	mkdir -p bin
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) $(PKG)

## test: run the Go unit tests
test:
	go test ./... -race -count=1

## vet / fmt: standard hygiene
vet:
	go vet ./...

fmt:
	go fmt ./...

## run: build and run against config.json (override with CONFIG=path)
CONFIG ?= config.json
run: build
	./bin/$(BINARY) -config $(CONFIG)

## check: validate config + compile the rule set, then exit (good for CI)
check: build
	./bin/$(BINARY) -config $(CONFIG) -check

## validate: run the standalone concurrency-logic model (no Go toolchain needed)
validate:
	python3 validate_concurrency.py

## mockup: regenerate the console design mockups (SVG) and screenshots (PNG)
mockup:
	python3 docs/gen_mockup.py
	python3 docs/rasterize.py

## docker: build the container image
docker:
	docker build -t $(BINARY):$(VERSION) .

clean:
	rm -rf bin
