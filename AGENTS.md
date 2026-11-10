# AGENTS.md

Guidance and repository conventions for autonomous AI agents and coding assistants working on `go_syslog_sniffer`.

---

## 1. Project Overview & Architecture

`go_syslog_sniffer` is a high-performance, low-latency UDP and TCP syslog capture and aggregation tool written in pure safe Go. It captures network datagrams (live via libpcap raw sockets or replay via offline `.pcap` files), parses standard and network-gear syslog formats (RFC 5424, RFC 3164, RFC 6587), maintains bounded-memory aggregate statistics per verified source IP, and outputs structured JSON or NDJSON summaries.

### Core Modules

- [`main.go`](file:///home/hellqvio/git/go_syslog_sniffer/main.go): Binary entry point, CLI invocation orchestration, force-quit signal handling (`SIGINT`/`SIGTERM`), network interface listing, and exit code management.
- [`internal/app/app.go`](file:///home/hellqvio/git/go_syslog_sniffer/internal/app/app.go): Application capture loop (`RunSniffer`), periodic window intervals, capture statistics delta calculations, sample suppression/redaction in logs, and JSON/NDJSON emission.
- [`internal/capture/capture.go`](file:///home/hellqvio/git/go_syslog_sniffer/internal/capture/capture.go): Packet source abstraction (`PacketSource` interface) with live capture (`PcapPacketSource`) and offline pcap replay, BPF filter generation with in-band 802.1Q VLAN support (`(port N) or (vlan and port N)`), link-layer decoding into `PacketData`, and link type validation.
- [`internal/config/config.go`](file:///home/hellqvio/git/go_syslog_sniffer/internal/config/config.go): CLI argument parsing via `flag.FlagSet`, short and long flag aliases (`-i/-p/-t/-d/-v/-r`), multi-port comma separation, direction parsing, and validation rules.
- [`internal/stats/stats.go`](file:///home/hellqvio/git/go_syslog_sniffer/internal/stats/stats.go): Thread-safe bounded memory tracker (`Tracker`), atomic snapshot and reset (`SnapshotAndReset`), `netip.Addr` source IP map keying, rune-safe sample truncation, relay visibility (`claimed_hostnames`), and kernel drop delta tracking.
- [`internal/syslog/parser.go`](file:///home/hellqvio/git/go_syslog_sniffer/internal/syslog/parser.go): Transport-aware framing (`SplitMessages` for RFC 5426 UDP datagram preservation and RFC 6587 TCP octet-counting/LF-framing) and zero-allocation header parsing (RFC 5424 version 1, RFC 3164 with ISO timestamps, Cisco sequence numbers, and NTP markers).
- [`internal/testutil/`](file:///home/hellqvio/git/go_syslog_sniffer/internal/testutil/): Test harness utilities, in-memory `MockPacketSource`, and programmatic pcap fixture generation.
- [`testdata/`](file:///home/hellqvio/git/go_syslog_sniffer/testdata/): Standard offline pcap replay fixtures for end-to-end testing (UDP, TCP, VLAN, IPv6).

---

## 2. Invariants & Strict Guardrails

When modifying this repository, AI agents **MUST** respect the following non-negotiable invariants:

1. **No Root or Physical Interface in Automated Tests**:
   - Automated tests (`go test ./...`) must NEVER require `sudo`, root privileges, `CAP_NET_RAW`, or live network interfaces.
   - Use `testutil.MockPacketSource`, `gopacket.SerializeLayers`, or replay through `testdata/*.pcap` via `capture.NewOfflinePacketSource`.
2. **Race-Detector Cleanliness (`-race`)**:
   - All tests must pass with `-race` enabled (`go test -race ./...`).
   - Concurrently accessed structures (such as `bytes.Buffer` in async test goroutines) must use synchronized primitives (e.g., mutex wrappers).
3. **Strict Bounded Memory Constraints**:
   - Live packet capture must never cause unbounded heap growth or pin whole packet buffers.
   - All message samples must be truncated on UTF-8 rune boundaries (`utf8.RuneStart`) and cloned using `strings.Clone` before storing.
   - Host entries are strictly capped at `--max-hosts` (default 10,000), tracking `overflow_events` when limits are reached.
   - Forwarder/relay visibility is bounded to at most 8 unique `claimed_hostnames` per host entry.
4. **Transport-Aware Framing Integrity**:
   - UDP datagrams represent exactly one message (RFC 5426) and must NEVER be split on newlines.
   - TCP segments support RFC 6587 octet-counted framing (`<len> <msg>`) and LF line splitting. Truncated or overrunning octet frames must be rejected and attributed to `ignored.not_syslog`.
5. **Process Exit Code Contract**:
   - `0`: Clean completion (duration reached, SIGINT/SIGTERM received, clean offline pcap EOF, `--help`, `--version`, or `--list-interfaces`).
   - `1`: Fatal capture or runtime failure (interface missing, permission denied, invalid configuration arguments, corrupted pcap, or live stream closure).

---

## 3. Development, Build, & Verification Commands

All agents must verify code quality and test suites before committing or submitting changes.

### Build & Formatting
```bash
# Build binary
make build

# Check code formatting (must produce no diff)
make fmt-check

# Auto-format Go source files
make fmt
```

### Static Analysis & Security Scanning
```bash
# Run all code quality checks (golangci-lint and go vet)
make lint

# Run TruffleHog secrets scanner on git tree
make secrets

# Run Trivy vulnerability scan on Go modules
make trivy
```

### Test Suite & Fuzzing
```bash
# Run full unit and integration test suite with data race detection
go test -count=1 -race ./...

# Run individual package tests
go test -race ./internal/app
go test -race ./internal/capture
go test -race ./internal/config
go test -race ./internal/stats
go test -race ./internal/syslog

# Run framing and stats fuzz target
go test -v -fuzz=FuzzFramingAndStats -fuzztime=10s ./internal/stats

# Run end-to-end throughput and parsing benchmarks
go test -bench=. -benchmem ./...
```

### Docker & E2E Tests
```bash
# Build local docker image
make docker-build

# Run end-to-end smoke test container (--cap-drop=ALL --cap-add=NET_RAW)
./tests/e2e_docker.sh
./tests/e2e_periodic_docker.sh
```

---

## 4. Git, CI, & Release Conventions

### Conventional Commits
All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `fix(...)`: Bug fixes (e.g., `fix(parser): ...`, `fix(capture): ...`, `fix(config): ...`)
- `feat(...)`: New user-facing features, CLI flags, or schema extensions
- `chore(...)`: Maintenance, dependency updates, or tool pinning
- `refactor(...)`: Internal refactoring without functional changes
- `test(...)`: New unit tests, fixtures, or benchmarks
- `docs(...)`: Documentation updates

### Pre-commit Hooks
The repository includes `.githooks/pre-commit`, running:
1. `make fmt-check` & `make lint`
2. `go test -v -race ./...`
3. TruffleHog secrets scan (`make secrets`)
4. Trivy vulnerability scan (`make trivy`)

Ensure all checks succeed cleanly prior to committing.
