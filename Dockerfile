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

# Install runtime dependencies and capability tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    libcap2-bin \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g 10001 sniffer \
    && useradd -u 10001 -g sniffer -s /bin/sh -M sniffer

# Copy the binary from builder
COPY --from=builder /app/syslog_sniffer /usr/local/bin/syslog_sniffer
RUN chmod 755 /usr/local/bin/syslog_sniffer \
    && setcap cap_net_raw+ep /usr/local/bin/syslog_sniffer \
    && ln -s /usr/local/bin/syslog_sniffer /usr/local/bin/sniffer

USER sniffer:sniffer

ENTRYPOINT ["/usr/local/bin/syslog_sniffer"]
CMD ["--help"]
