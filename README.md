# Go Syslog Sniffer

[![CI/CD](https://github.com/hellqvio86/go_syslog_sniffer/actions/workflows/ci.yml/badge.svg)](https://github.com/hellqvio86/go_syslog_sniffer/actions/workflows/ci.yml)
[![Security Scan](https://github.com/hellqvio86/go_syslog_sniffer/actions/workflows/security.yml/badge.svg)](https://github.com/hellqvio86/go_syslog_sniffer/actions/workflows/security.yml)
[![GitHub Release](https://img.shields.io/github/v/release/hellqvio86/go_syslog_sniffer)](https://github.com/hellqvio86/go_syslog_sniffer/releases)
[![GHCR Container](https://img.shields.io/badge/container-ghcr.io-blue?logo=docker)](https://github.com/hellqvio86/go_syslog_sniffer/pkgs/container/go_syslog_sniffer)
[![Go Reference](https://pkg.go.dev/badge/github.com/hellqvio86/go_syslog_sniffer.svg)](https://pkg.go.dev/github.com/hellqvio86/go_syslog_sniffer)
![Go Version](https://img.shields.io/github/go-mod/go-version/hellqvio86/go_syslog_sniffer)
![License](https://img.shields.io/github/license/hellqvio86/go_syslog_sniffer)
![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/hellqvio86/go_syslog_sniffer)
![amd64](https://img.shields.io/badge/arch-amd64-blue)
![arm64](https://img.shields.io/badge/arch-arm64-blue)

A high-performance syslog packet sniffer written in Go.
Captures syslog network traffic (UDP/TCP), parses RFC 5424 and RFC 3164 messages, counts events per source IP, extracts claimed hostnames, takes a bounded sample of the events, and outputs formatted JSON or NDJSON.

## Features

- **Live & Offline Capture**: Uses libpcap / gopacket to capture live network traffic or replay from offline `.pcap` files (`-r / --read-file`).
- **Syslog Parsing & Stream Reassembly**: Automatically identifies and parses RFC 5424 and RFC 3164 (including ISO-8601 high-precision timestamps). TCP streams undergo bounded reassembly via `gopacket/tcpassembly` supporting RFC 6587 octet-counting and LF delimiters across split segments.
- **Source IP Keying**: Entries are strictly keyed by observed packet source IP (`netip.Addr`) with zero allocations on packet lookup, preventing sender-controlled map explosion.
- **Bounded Memory**: Memory footprint is bounded via `--max-hosts` (default 10,000) and `--sample-bytes` (default 2,048), reporting `overflow_events` when limits are reached. Max message size is bounded to 65,535 bytes.
- **Flexible Reporting**: Single summary mode or atomic `--periodic` interval reporting.
- **Machine-Friendly Output**: Formatted JSON or single-line NDJSON (`--format json|ndjson`).
- **Non-Root Docker Hardening**: Runs as unprivileged user `sniffer` (UID 10001) with Linux capabilities (`--cap-drop=ALL --cap-add=NET_RAW`).
- **Graceful Termination**: Intercepts `SIGINT`/`SIGTERM` to cleanly output stats captured up to the moment of termination.

## Building and Running

### Prerequisites

- **Go**: 1.26.0 or later (Ubuntu 24.04 `apt install golang` defaults to an older toolchain; install from [go.dev/dl](https://go.dev/dl/)).
- **libpcap**: `libpcap-dev` on Debian/Ubuntu for building.
- **Make & C Compiler**: `build-essential netcat-openbsd make curl`.

```console
# Debian / Ubuntu
sudo apt install -y build-essential libpcap-dev netcat-openbsd make curl
```

### Local Build

```bash
# Build the binary
make build

# Run unit tests
make test

# Generate test coverage report
make coverage

# Generate CycloneDX SBOM
make sbom
```

### Privileges (`sudo` vs `setcap`)

Capturing live packets via libpcap requires raw network capture access. You can either:

1. **Run with `sudo`**:
   ```bash
   sudo ./syslog_sniffer -i any -p 514
   ```
2. **Grant `CAP_NET_RAW` once** to run as a standard non-root user:
   ```bash
   sudo setcap cap_net_raw+ep ./syslog_sniffer
   ./syslog_sniffer -i any -p 514
   ```

### Usage

```bash
syslog_sniffer [OPTIONS]

Options:
  -i, --interface <INTERFACE>   Network interface to sniff (e.g., eth0, lo, or "any", default: "any")
  -p, --port <PORTS>            Syslog port(s) to monitor (comma-separated, 1-65535, default: 514)
      --direction <DIR>         Traffic direction to capture: dst, src, or both (default: dst)
  -t, --interval <SECONDS>      Duration in seconds to capture (0 = unlimited, default: 10)
  -d, --debug                   Enable debug diagnostic logging
  -v, --version                 Print version and exit
  -r, --read-file <FILE>        Read packets from a pcap file instead of a live interface
      --periodic                Enable periodic summary output
      --frequency <SECONDS>     Frequency in seconds for periodic output (default: 5)
      --format <FORMAT>         Output format: json or ndjson (default: json)
      --max-hosts <COUNT>       Maximum distinct hosts to track in memory (default: 10000)
      --sample-bytes <BYTES>    Maximum byte length of message sample retained per host (default: 2048)
      --no-sample               Do not include sample messages in output
      --redact-sample           Redact message samples in output
      --emit-empty              Emit empty summary reports when no traffic was seen
      --promisc                 Enable promiscuous mode on network interface (default: false)
      --list-interfaces         List available network interfaces and exit
  -h, --help                    Print usage instructions

Environment Variables:
  DEBUG=1                       Enable debug diagnostic logging (equivalent to -d / --debug)
```

### Exit Codes

- `0`: Successful execution, or requested `--help`, `--version`, or `--list-interfaces`.
- `1`: Configuration error (e.g. invalid port, unknown flag), network interface failure, closed capture stream, or unrecoverable capture failure.

### JSON Schema (v0.2.0+)

Entries in `hosts` are keyed by the originating source IP address to prevent sender-spoofed hostname collisions or unbounded map expansion. The claimed hostname extracted from RFC 5424 / RFC 3164 headers is preserved in the `hostname` field.

```json
{
  "start_time": "2026-11-07T12:00:00Z",
  "end_time": "2026-11-07T12:00:10Z",
  "interval_seconds": 10,
  "hosts": {
    "192.168.1.10": {
      "count": 42,
      "src_ip": "192.168.1.10",
      "hostname": "mymachine.example.com",
      "claimed_hostnames": [
        "mymachine.example.com"
      ],
      "claimed_hostnames_total": 1,
      "sample": "<165>1 2026-11-07T12:00:00.000Z mymachine.example.com appname[123] - ID47 [exampleSDID@32473] Sample log entry",
      "sample_truncated": false,
      "tls_suspected": false
    }
  },
  "overflow_events": 0,
  "ignored": {
    "no_payload": 5,
    "not_syslog": 2,
    "non_utf8_sanitized": 1,
    "decode_errors": 0
  },
  "capture_stats": {
    "received": 120,
    "dropped": 0,
    "if_dropped": 0
  }
}
```

## Protocol Considerations & Operational Limitations

- **Framing & Transports**: UDP datagrams are treated as exactly one syslog message without splitting on newlines (per RFC 5426). TCP streams undergo full stream reassembly using `gopacket/tcpassembly`, supporting RFC 6587 octet-counted framing (`<len> <msg>`) and traditional LF line delimiters across segment boundaries, out-of-order segments, connection close, and retransmissions.
- **Accounting & Counter Relationships**:
  - `capture_stats.received`: Total raw packets delivered by libpcap from the network socket.
  - `capture_stats.dropped` / `if_dropped`: Packets dropped by kernel buffer exhaustion or the network interface controller before application delivery.
  - `ignored.no_payload`: Packets captured with zero transport payload (e.g. TCP SYN, pure ACK, FIN without data, empty UDP datagrams).
  - `ignored.not_syslog`: Packets or frames that do not start with a valid `<PRI>` header (PRI <= 191), or carry invalid framing.
  - `ignored.decode_errors`: Malformed link-layer or IP packets that failed packet decoding.
  - `hosts[ip].count`: Successfully parsed syslog messages attributed to that observed source IP. (Note: for TCP streams with multiple messages per segment, `count` can exceed raw TCP packet count).
- **VLAN Tagging & BPF**: BPF filters automatically match both untagged and 802.1Q in-band VLAN tagged frames (`(dst port N) or (vlan and dst port N)`).
- **TLS / Encrypted Syslog**: Encrypted TLS connections (e.g. port 6514) cannot be payload-inspected without proxying. TLS handshakes (ClientHello) are identified automatically, reporting `"tls_suspected": true` for that host entry.
- **Relay Hostname Tracking**: Forwarders and relays (rsyslog, syslog-ng) that consolidate messages retain up to 8 unique claimed hostnames under `claimed_hostnames`. `claimed_hostnames_total` reports the total cumulative count of messages seen with a claimed hostname, including duplicates.
- **Kernel & Interface Drops**: On packet capture termination or periodic reporting, kernel and interface statistics (`received`, `dropped`, `if_dropped`) are retrieved via `pcap_stats` and reported in `capture_stats`. In periodic mode, deltas per window are reported.
- **UDP & IPv6 Fragmentation**: Large UDP datagrams that undergo IP fragmentation only match port filters on the first fragment. IPv6 extension headers are not reassembled.
- **Promiscuous Mode**: Promiscuous mode is disabled by default (`--promisc` to enable). Enabling promiscuous mode generally requires `CAP_NET_ADMIN`.
- **gopacket Fork Decision**: Evaluated `github.com/gopacket/gopacket`; the project retains `github.com/google/gopacket` v1.1.19 due to stability, pure Go layer decoders, standard CGO libpcap bindings, and broad distribution packaging.

## Security Considerations

- **Sensitive Data & Sample Suppression**: Syslog messages frequently contain secrets, tokens, or PII. Use `--no-sample` to completely omit message samples from JSON reports, or `--redact-sample` to output `"[REDACTED]"` in place of raw packet contents. Debug logging (`--debug`) strictly respects sample suppression and redaction.
- **Terminal Injection Prevention**: Debug messages logged to `stderr` are safely escaped using `%q` formatting to prevent ANSI escape sequence injection.
- **Resource Exhaustion Bounds**: The memory footprint is strictly bounded via `--max-hosts` (default 10,000), `--sample-bytes` (default 2,048), and max syslog message limits (65,535 bytes), preventing denial-of-service via spoofed source addresses or oversized payloads.
- **Least Privilege & Capabilities**: The Docker container runs as non-root user `sniffer` (UID 10001) and requires only `CAP_NET_RAW` with `--security-opt=no-new-privileges:true --cap-drop=ALL --cap-add=NET_RAW`. No setcap or file capabilities are installed in the container image.

## Performance & Benchmarks

The capture pipeline uses zero-allocation header parsing, zero-copy TCP assembly, and bounded memory tracking. Benchmarks can be reproduced with:

```bash
go test -bench=. -run=^$ -benchmem ./...
```

Measured on 12th Gen Intel Core i7-1260P (Linux 6.8, Go 1.26):

- **End-to-End Pipeline (Split + Parse + AddEntry)**: ~980,000 msgs/sec (1.04 µs/op, 86 MB/s, 9 allocs/op)
- **TCP Stream Reassembly (Contiguous)**: ~3,135,000 msgs/sec (377 ns/op, 191 MB/s, 5 allocs/op)
- **TCP Stream Reassembly (Split Segments)**: ~1,789,000 msgs/sec (673 ns/op, 107 MB/s, 7 allocs/op)
- **Syslog Parser (RFC 5424)**: ~1,000,000 msgs/sec (1.02 µs/op, 7 allocs/op)
- **Syslog Parser (RFC 3164)**: ~1,334,000 msgs/sec (917 ns/op, 7 allocs/op)
- **Offline Pcap Replay (100k packets)**: ~1,400,000 packets/sec (175 MB/s throughput)

## Docker

### Published Images

Published multi-architecture images on GitHub Container Registry (GHCR):
- [`ghcr.io/hellqvio86/go_syslog_sniffer`](https://github.com/hellqvio86/go_syslog_sniffer/pkgs/container/go_syslog_sniffer)

Supported architectures:
- `linux/amd64` (Standard 64-bit Intel/AMD)
- `linux/arm64` (Raspberry Pi 4/5, Apple Silicon, AWS Graviton)

Image Tags:
- `latest`: Latest tagged release
- `<version>`: Specific semantic version release (e.g. `0.2.0`)
- `edge`: Latest build from the `main` branch
- `sha-<short>`: Immutable commit-specific build

### Running the Container

The container drops all capabilities except `NET_RAW` and runs as non-root user `sniffer`:

```bash
docker run --rm \
  --network host \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  ghcr.io/hellqvio86/go_syslog_sniffer:latest --interface any --port 514
```

Run with periodic reporting:

```bash
docker run --rm \
  --network host \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  --cap-add=NET_RAW \
  ghcr.io/hellqvio86/go_syslog_sniffer:latest \
  --interface any \
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
make docker-run ARGS="--interface any --port 514"
```

## Available Make Targets

Run `make help` to see all available targets:

```text
make build              # Build the Go application
make test               # Run unit tests
make lint               # Run linter and static analysis
make fmt                # Format Go source files
make coverage           # Generate test coverage report
make sbom               # Generate CycloneDX SBOM
make docker-build       # Build Docker image
make docker-run         # Run Docker container
make clean              # Clean build artifacts
make hooks              # Install git pre-commit hook
make secrets            # Run TruffleHog secret scanning
make trivy              # Run Trivy vulnerability scanning
```

## License

[MIT](LICENSE)

<p align="right">
  <a href="https://www.buymeacoffee.com/olofhellqvc">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" height="48">
  </a>
</p>
