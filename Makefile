.PHONY: help build run clean test fmt fmt-check tidy-check vulncheck hadolint format lint coverage sbom docker-build docker-run docker-run-interactive docker-tag docker-push docker-clean all renovate renovate-summary hooks secrets trivy

# Variables
BINARY_NAME = syslog_sniffer
LEGACY_NAME = sniffer
DOCKER = docker
IMAGE_NAME = syslog_sniffer
IMAGE_TAG = latest
REGISTRY ?= # e.g. docker.io/username
VERSION ?= $(shell tr -d '[:space:]' < VERSION 2>/dev/null || echo "0.1.0")
GO_MOD_VERSION ?= $(shell grep '^go ' go.mod 2>/dev/null | awk '{print $$2}')
ifneq ($(GO_MOD_VERSION),)
GOTOOLCHAIN ?= go$(GO_MOD_VERSION)
export GOTOOLCHAIN
endif

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Go application
	go build -ldflags="-s -w -X github.com/hellqvio86/go_syslog_sniffer/internal/config.Version=$(VERSION)" -o $(BINARY_NAME) main.go
	ln -sf $(BINARY_NAME) $(LEGACY_NAME)

$(LEGACY_NAME): build

run: build ## Run the application
	sudo ./$(BINARY_NAME)

clean: ## Clean build artifacts
	rm -f $(BINARY_NAME) $(LEGACY_NAME) coverage.out coverage.html sniffer_output_*.txt

test: ## Run unit tests
	go test -v -race ./...

fmt: ## Format Go source files
	gofmt -s -w .

fmt-check: ## Check Go code formatting
	@diff=$$(gofmt -l .); if [ -n "$$diff" ]; then echo "Unformatted files found: $$diff"; exit 1; fi
	@if command -v docker >/dev/null 2>&1 && [ -n "$(GO_MOD_VERSION)" ]; then \
		docker_diff=$$(docker run --rm -v "$$(pwd):/src" -w /src "golang:$(GO_MOD_VERSION)" gofmt -l .); \
		if [ -n "$$docker_diff" ]; then \
			echo "Unformatted files found (Go $(GO_MOD_VERSION)): $$docker_diff"; \
			exit 1; \
		fi; \
	fi

tidy-check: ## Check that go.mod and go.sum are tidy
	go mod tidy
	git diff --exit-code go.mod go.sum

vulncheck: ## Run govulncheck vulnerability analysis
	@echo "Running govulncheck..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	elif [ -x "$$HOME/go/bin/govulncheck" ]; then \
		"$$HOME/go/bin/govulncheck" ./...; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v "$$(pwd):/src" -w /src "golang:$(GO_MOD_VERSION)" sh -c "go install golang.org/x/vuln/cmd/govulncheck@v1.1.4 && govulncheck ./..."; \
	else \
		echo "ERROR: govulncheck or docker is required!" >&2 && exit 1; \
	fi

hadolint: ## Lint Dockerfile with hadolint
	@echo "Running hadolint..."
	@if command -v hadolint >/dev/null 2>&1; then \
		hadolint Dockerfile --ignore DL3008; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v "$$(pwd):/work" -w /work ghcr.io/hadolint/hadolint:latest hadolint Dockerfile --ignore DL3008; \
	else \
		echo "ERROR: hadolint or docker is required!" >&2 && exit 1; \
	fi

format: fmt ## Alias for fmt

lint: tidy-check fmt-check ## Run linter and static analysis
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	elif [ -x "$$HOME/go/bin/golangci-lint" ]; then \
		"$$HOME/go/bin/golangci-lint" run; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v "$$(pwd):/app" -w /app golangci/golangci-lint:v2.15.0 golangci-lint run; \
	else \
		echo "ERROR: golangci-lint is required for make lint. Install via: go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.15.0" >&2; \
		exit 1; \
	fi

COVERAGE_MIN = 80

coverage: ## Generate test coverage report and enforce threshold
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@total=$$(go tool cover -func=coverage.out | grep total | awk '{print substr($$3, 1, length($$3)-1)}'); \
	echo "Total coverage: $$total%"; \
	awk -v cov="$$total" -v min="$(COVERAGE_MIN)" 'BEGIN {if (cov+0 < min+0) {printf "FAIL: coverage %.1f%% is below floor %.1f%%\n", cov, min; exit 1} else {printf "PASS: coverage %.1f%% meets floor %.1f%%\n", cov, min}}'

sbom: ## Generate SBOM in CycloneDX format
	@echo "Generating SBOM..."
	@if command -v syft >/dev/null 2>&1; then \
		syft dir:. -o cyclonedx-json=sbom.json; \
	elif command -v trivy >/dev/null 2>&1; then \
		trivy fs --format cyclonedx -o sbom.json .; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v $$(pwd):/src -w /src aquasec/trivy:0.60.0 fs --format cyclonedx -o sbom.json .; \
	else \
		echo "ERROR: trivy, syft, or docker is required!" >&2 && exit 1; \
	fi

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run: ## Run Docker container
	$(DOCKER) run --rm -it \
		--cap-drop=ALL \
		--cap-add=NET_RAW \
		--network host \
		$(IMAGE_NAME):$(IMAGE_TAG) $(ARGS)

docker-run-interactive: ## Run Docker container interactively with shell
	$(DOCKER) run --rm -it \
		--cap-drop=ALL \
		--cap-add=NET_RAW \
		--network host \
		--entrypoint /bin/sh \
		$(IMAGE_NAME):$(IMAGE_TAG)

docker-tag: ## Tag image for registry
ifdef REGISTRY
	$(DOCKER) tag $(IMAGE_NAME):$(IMAGE_TAG) $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
else
	@echo "Error: REGISTRY variable not set. Usage: make docker-tag REGISTRY=docker.io/username"
	@exit 1
endif

docker-push: docker-tag ## Push Docker image to registry
ifdef REGISTRY
	$(DOCKER) push $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
else
	@echo "Error: REGISTRY variable not set. Usage: make docker-push REGISTRY=docker.io/username"
	@exit 1
endif

docker-clean: ## Remove Docker images
	$(DOCKER) rmi $(IMAGE_NAME):$(IMAGE_TAG) || true
ifdef REGISTRY
	$(DOCKER) rmi $(REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG) || true
endif

all: clean build test docker-build ## Clean, build, test, and create Docker image

renovate: ## Run Renovate locally in dry-run mode
	@./bin/renovate/run.sh

renovate-summary: ## Show summary of Renovate updates
	@./bin/renovate/run.sh --summary

hooks: ## Install git pre-commit and pre-push hooks
	@chmod +x .githooks/pre-commit 2>/dev/null || true
	@chmod +x .githooks/pre-push 2>/dev/null || true
	@git config core.hooksPath .githooks
	@echo "Git hooks installed and core.hooksPath set to .githooks."

secrets: ## Run TruffleHog secret scanning
	@echo "Running TruffleHog secret scan..."
	@if command -v trufflehog >/dev/null 2>&1; then \
		trufflehog --no-update git file://$$(pwd) --only-verified --fail; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v $$(pwd):/src -w /src trufflesecurity/trufflehog:3.88.15 git file:///src --only-verified --fail; \
	else \
		echo "ERROR: trufflehog or docker is required!" >&2 && exit 1; \
	fi

trivy: ## Run Trivy vulnerability scanning
	@echo "Running Trivy vulnerability scan..."
	@if command -v trivy >/dev/null 2>&1; then \
		trivy fs --severity HIGH,CRITICAL --exit-code 1 .; \
	elif command -v docker >/dev/null 2>&1; then \
		docker run --rm -v $$(pwd):/src -v trivy-cache:/root/.cache -w /src aquasec/trivy:0.60.0 fs --severity HIGH,CRITICAL --exit-code 1 .; \
	else \
		echo "ERROR: trivy or docker is required!" >&2 && exit 1; \
	fi

