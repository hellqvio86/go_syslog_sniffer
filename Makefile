.PHONY: help build run clean test fmt format lint coverage docker-build docker-run docker-run-interactive docker-tag docker-push docker-clean all renovate renovate-summary

# Variables
BINARY_NAME = syslog_sniffer
LEGACY_NAME = sniffer
DOCKER = docker
IMAGE_NAME = syslog_sniffer
IMAGE_TAG = latest
REGISTRY ?= # e.g. docker.io/username

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the Go application
	go build -ldflags="-s -w" -o $(BINARY_NAME) main.go
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

format: fmt ## Alias for fmt

lint: ## Run linter and static analysis
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		go vet ./...; \
	fi

coverage: ## Generate test coverage report
	go test -coverprofile=coverage.out ./pkg/...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

docker-build: ## Build Docker image
	$(DOCKER) build -t $(IMAGE_NAME):$(IMAGE_TAG) .

docker-run: ## Run Docker container
	$(DOCKER) run --rm -it \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
		--network host \
		$(IMAGE_NAME):$(IMAGE_TAG) $(ARGS)

docker-run-interactive: ## Run Docker container interactively with shell
	$(DOCKER) run --rm -it \
		--cap-add=NET_RAW \
		--cap-add=NET_ADMIN \
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
