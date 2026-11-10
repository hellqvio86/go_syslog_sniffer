.PHONY: help build run clean test fmt fmt-check format lint coverage sbom docker-build docker-run docker-run-interactive docker-tag docker-push docker-clean all renovate renovate-summary hooks secrets trivy

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

format: fmt ## Alias for fmt

lint: fmt-check ## Run linter and static analysis
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	elif [ -x "$$HOME/go/bin/golangci-lint" ]; then \
		"$$HOME/go/bin/golangci-lint" run; \
	else \
		go vet ./...; \
	fi

coverage: ## Generate test coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

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

hooks: ## Install git pre-commit hook
	@chmod +x .githooks/pre-commit 2>/dev/null || true
	@git config core.hooksPath .githooks
	@echo "Git pre-commit hook installed and core.hooksPath set to .githooks."

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

