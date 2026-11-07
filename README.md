# Go Syslog Sniffer

[![CI/CD](https://github.com/hellqvio86/go_syslog_sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/hellqvio86/go_syslog_sniffer/actions/workflows/ci.yml)
[![GitHub Release](https://img.shields.io/github/v/release/hellqvio86/go_syslog_sniffer)](https://github.com/hellqvio86/go_syslog_sniffer/releases)
[![GHCR Container](https://img.shields.io/badge/container-ghcr.io-blue?logo=docker)](https://github.com/hellqvio86/go_syslog_sniffer/pkgs/container/go_syslog_sniffer)
![Coverage](coverage.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/hellqvio86/go_syslog_sniffer)](https://goreportcard.com/report/github.com/hellqvio86/go_syslog_sniffer)
[![Go Reference](https://pkg.go.dev/badge/github.com/hellqvio86/go_syslog_sniffer.svg)](https://pkg.go.dev/github.com/hellqvio86/go_syslog_sniffer)
![Go Version](https://img.shields.io/github/go-mod/go-version/hellqvio86/go_syslog_sniffer)
![License](https://img.shields.io/github/license/hellqvio86/go_syslog_sniffer)
![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/hellqvio86/go_syslog_sniffer)
![amd64](https://img.shields.io/badge/arch-amd64-blue)
![arm64](https://img.shields.io/badge/arch-arm64-blue)

A high-performance syslog packet sniffer written in Go.
Captures syslog network traffic (UDP/TCP), parses RFC 5424 and RFC 3164 messages, counts events per host, takes a sample of the events, and outputs formatted JSON.

## Features

- **Live Capture**: Uses libpcap / gopacket to capture network traffic on physical or loopback interfaces.
- **Syslog Parsing**: Automatically identifies and parses RFC 5424 and RFC 3164 syslog formats to extract originating hostnames.
- **Payload Preservation**: Retains complete syslog payloads (including multi-line and newline-terminated messages) without truncation or regex drops.
- **Flexible Reporting**: Standard total summary mode or `--periodic` reporting mode.
- **Clean JSON Output**: Emits unescaped, formatted JSON summary reports.
- **Graceful Termination**: Intercepts `SIGINT`/`SIGTERM` to cleanly output stats captured up to the moment of termination.

## Building and Running

### Prerequisites

```console
# Debian / Ubuntu
sudo apt install -y golang libpcap-dev netcat-openbsd make
```

### Local Build

```bash
# Build the project
make build

# Run unit tests
make test

# Generate test coverage report
make coverage
```

### Usage

```bash
syslog_sniffer [OPTIONS]

Options:
  -i, --interface <INTERFACE>   Network interface to sniff (e.g., eth0, lo)
  -p, --port <PORT>             Syslog port to monitor (default: 514)
  -t, --interval <SECONDS>      Duration in seconds to capture (default: 10)
  -d, --debug                   Enable debug diagnostic logging
  -v, --version                 Print version and exit
      --periodic                Enable periodic summary output
      --frequency <SECONDS>     Frequency in seconds for periodic output (default: 5)
      --max-hosts <COUNT>       Maximum distinct hosts to track in memory (default: 10000)
      --sample-bytes <BYTES>    Maximum byte length of message sample retained per host (default: 2048)
  -h, --help                    Print usage instructions
```

### JSON Schema (v0.2.0+)

Entries in `hosts` are keyed by the originating source IP address to prevent sender-spoofed hostname collisions or unbounded map expansion. The claimed hostname extracted from RFC 5424 / RFC 3164 headers is preserved in the `hostname` field.

```json
{
  "interval_seconds": 10,
  "hosts": {
    "192.168.1.10": {
      "count": 42,
      "src_ip": "192.168.1.10",
      "hostname": "mymachine.example.com",
      "sample": "<165>1 2026-11-07T12:00:00.000Z mymachine.example.com appname[123] - ID47 [exampleSDID@32473] Sample log entry"
    }
  },
  "ignored": {
    "no_payload": 5,
    "not_syslog": 2
  }
}
```

## Protocol Considerations & Limitations

- **Multi-Message TCP Streams**: Newline-framed syslog messages arriving within a single TCP segment are split and counted individually.
- **TLS / Encrypted Syslog**: Encrypted TLS connections (e.g. port 6514) cannot be inspected. TLS handshakes (ClientHello) are identified automatically, reporting `"tls_suspected": true` for that host entry.
- **Ignored Packet Accounting**: Non-payload packets (e.g. TCP pure ACKs, empty UDP datagrams) and non-syslog payloads are tracked in the top-level `ignored` section.
- **UDP Fragmentation**: Large UDP syslog datagrams exceeding network MTU that undergo IP fragmentation only match port filters on the first fragment.

## Docker

### Published Image

Published multi-architecture image:
- **GitHub Container Registry (GHCR)**: [`ghcr.io/hellqvio86/go_syslog_sniffer`](https://github.com/hellqvio86/go_syslog_sniffer/pkgs/container/go_syslog_sniffer)

Supported architectures:
- `linux/amd64` (Standard 64-bit Intel/AMD)
- `linux/arm64` (Raspberry Pi 4/5, Apple Silicon, AWS Graviton)

Tags:
- `latest` (tracks the latest release)
- `<version>` (e.g., `0.1.0`)

#### Pull Image from GHCR

```bash
# Pull latest release
docker pull ghcr.io/hellqvio86/go_syslog_sniffer:latest

# Or pull a specific release tag
docker pull ghcr.io/hellqvio86/go_syslog_sniffer:0.1.0
```

#### Run Published Container

The container requires `NET_RAW` and `NET_ADMIN` capabilities for raw packet capture, and `--network host` to access network interfaces:

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  ghcr.io/hellqvio86/go_syslog_sniffer:latest --interface eth0 --port 514
```

Run with periodic reporting:

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  ghcr.io/hellqvio86/go_syslog_sniffer:latest \
  --interface eth0 \
  --port 514 \
  --periodic \
  --frequency 5
```

### Local Docker Build

To build and run the image locally from source:

```bash
# Build the Docker image locally
make docker-build

# Run the local container
make docker-run ARGS="--interface eth0 --port 514"
```

Or manually:

```bash
docker run --rm \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --network host \
  syslog_sniffer:latest --interface eth0 --port 514
```

## Available Make Targets

Run `make help` to see all available targets:

```text
make build              # Build the Go application
make test               # Run unit tests
make lint               # Run linter and static analysis
make fmt                # Format Go source files
make coverage           # Generate test coverage report
make docker-build       # Build Docker image
make docker-run         # Run Docker container
make clean              # Clean build artifacts
```

## CI/CD

Continuous integration runs via GitHub Actions on every push and pull request to `main`:
- Code formatting check (`gofmt`)
- Go static analysis (`go vet`)
- Unit tests with race detection (`go test -v -race`)
- Container image build and end-to-end integration tests (`tests/e2e_docker.sh`, `tests/e2e_periodic_docker.sh`)

## License

[MIT](LICENSE)

<p align="right">
  <a href="https://www.buymeacoffee.com/olofhellqvc">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" height="48">
  </a>
</p>
