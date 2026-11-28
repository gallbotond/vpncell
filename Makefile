GO      ?= go
BIN     := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
export CGO_ENABLED=0

.PHONY: build test itest lint clean extension
build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/ ./cmd/...
	$(GO) build -o $(BIN)/vpncell-lab ./test/labcmd

# Unsigned .xpi (DECISIONS.md: signing is done by the user with
# packaging/amo-sign.sh).
extension:
	cd extension && (test -d node_modules || npm ci --no-audit --no-fund) && npm run -s build
	mkdir -p $(BIN)
	python3 -c 'import zipfile,os,sys; z=zipfile.ZipFile("$(BIN)/vpncell.xpi","w",zipfile.ZIP_DEFLATED); [z.write(os.path.join("extension/dist",f),f) for f in sorted(os.listdir("extension/dist"))]; z.close()'

test:
	cd extension && (test -d node_modules || npm ci --no-audit --no-fund) && npm test --silent
	$(GO) vet ./...
	$(GO) test ./internal/... ./cmd/...

# Root integration tests (DESIGN.md §15.4). RUN=regexp selects tests.
itest: build extension
	$(GO) test -c -tags integration -o $(BIN)/itest ./test/integration
	cd test/integration && sudo $(ITEST_ENV) ../../$(BIN)/itest -test.v -test.timeout 60m $(if $(RUN),-test.run '$(RUN)')

clean:
	rm -rf $(BIN)
