# Build stage
FROM golang:1.27-bookworm AS builder

ARG VERSION=dev

# Install build dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the application
RUN CGO_ENABLED=1 go build -ldflags="-s -w -X github.com/hellqvio86/go_syslog_sniffer/internal/config.Version=${VERSION}" -o syslog_sniffer main.go

# Artifacts export stage (for clean host extraction)
FROM scratch AS artifacts
COPY --from=builder /app/syslog_sniffer /syslog_sniffer

# Runtime stage (Debian-based for glibc and libpcap compatibility)
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libpcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy the binary from builder
COPY --from=builder /app/syslog_sniffer /usr/local/bin/syslog_sniffer
RUN chmod +x /usr/local/bin/syslog_sniffer \
    && ln -s /usr/local/bin/syslog_sniffer /usr/local/bin/sniffer

ENTRYPOINT ["/usr/local/bin/syslog_sniffer"]
CMD ["--help"]
