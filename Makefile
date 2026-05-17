BIN ?= bin/mnemox
GO ?= go
NPM ?= npm

.PHONY: build backend web test clean

build: web backend

backend:
	mkdir -p $(dir $(BIN))
	$(GO) build -o $(BIN) ./cmd/mnemox

web: web/node_modules/.package-lock.json
	cd web && $(NPM) run build

web/node_modules/.package-lock.json: web/package.json web/package-lock.json
	cd web && $(NPM) ci
	touch $@

test: web/node_modules/.package-lock.json
	$(GO) test ./...
	cd web && $(NPM) test

clean:
	rm -f $(BIN)
