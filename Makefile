GO      ?= go
BIN     := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export CGO_ENABLED=0

.PHONY: build test itest lint clean
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/ ./cmd/...
	$(GO) build -o $(BIN)/vpncell-lab ./test/labcmd

test:
	$(GO) vet ./...
	$(GO) test ./internal/... ./cmd/...

# Root integration tests (DESIGN.md §15.4). RUN=regexp selects tests.
itest: build
	$(GO) test -c -tags integration -o $(BIN)/itest ./test/integration
	cd test/integration && sudo ../../$(BIN)/itest -test.v -test.timeout 60m $(if $(RUN),-test.run '$(RUN)')

clean:
	rm -rf $(BIN)
