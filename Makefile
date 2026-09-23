.PHONY: build test vet

GOCACHE ?= /tmp/jerrysrevenge-go-cache

build:
	mkdir -p bin
	GOCACHE=$(GOCACHE) go build -buildvcs=false -trimpath -o bin/jerrysrevenge ./cmd/jerrysrevenge
	chmod 0755 bin/jerrysrevenge

test:
	GOCACHE=$(GOCACHE) go test ./...

vet:
	GOCACHE=$(GOCACHE) go vet ./...
