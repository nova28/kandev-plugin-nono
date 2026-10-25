.PHONY: build run test check-format fmt vet validate package package-host package-file verify-package verify-package-host clean

BIN := bin/kandev-plugin-nono
VERSION := 0.1.0
STAGE := .build/stage
PKG_OUT := $(notdir $(BIN))-$(VERSION).tar.gz
KANDEV_SDK := ../kdlbs-kandev/apps/backend

build:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(BIN) ./server

run: build
	./$(BIN)

test:
	go test -race ./server/...
	python3 scripts/test_runtime_package.py
	sh scripts/test-verify-release-version.sh

check-format:
	@test -z "$$(gofmt -l server)" || { echo "gofmt needed:"; gofmt -l server; exit 1; }

fmt:
	gofmt -w server

vet:
	go vet ./server/...

validate: check-format vet test

package:
	rm -rf $(STAGE)
	mkdir -p $(STAGE)/server $(STAGE)/licenses
	cp manifest.yaml runtime-lock.json LICENSE $(STAGE)/
	cp licenses/NONO-APACHE-2.0.txt $(STAGE)/licenses/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(STAGE)/server/plugin-linux-amd64 ./server
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o $(STAGE)/server/plugin-darwin-arm64 ./server
	python3 scripts/runtime_package.py prepare $(STAGE)/runtime/nono-linux-amd64 linux-amd64
	python3 scripts/runtime_package.py prepare $(STAGE)/runtime/nono-darwin-arm64 darwin-arm64
	cd $(KANDEV_SDK) && go run ./cmd/plugin-pack -dir $(CURDIR)/$(STAGE) -out $(CURDIR)/$(PKG_OUT)
	rm -rf $(STAGE)

package-host: package

verify-package: package
	@set -eu; \
		package_tmp="$$(mktemp -d)"; \
		trap 'rm -rf "$$package_tmp"' EXIT; \
		tar -xzf "$(PKG_OUT)" -C "$$package_tmp"; \
		python3 scripts/runtime_package.py verify "$$package_tmp"

verify-package-host: verify-package

package-file:
	@printf '%s\n' "$(PKG_OUT)"

clean:
	rm -rf bin $(STAGE) $(notdir $(BIN))-*.tar.gz
