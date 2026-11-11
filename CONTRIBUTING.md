# Contributing to `go_syslog_sniffer`

Thank you for your interest in contributing to `go_syslog_sniffer`! This document provides guidelines, setup instructions, and development workflows for human contributors. Autonomous agents should also refer to [AGENTS.md](AGENTS.md).

---

## 1. Prerequisites & Toolchain

- **Go**: Go 1.26.0 or higher.
- **libpcap**: libpcap development headers and libraries (`libpcap-dev` on Debian/Ubuntu, `libpcap` on Arch/Fedora).
- **CGO**: CGO must be enabled (`CGO_ENABLED=1`) for building against `libpcap`.
- **Docker** (optional): For container builds, multi-architecture verification, and isolated tool runs (`hadolint`, `trivy`, `syft`).
- **Linters**: `golangci-lint` (v2.15.0+), `govulncheck` (v1.1.4+).

---

## 2. Building & Running Locally

```bash
# Build the application
make build

# Run unit and race tests (no root privileges required)
make test

# Format source files
make fmt

# Verify code formatting without modifying files
make fmt-check

# Run linter and static analysis
make lint

# Check dependencies for known vulnerabilities
make vulncheck
```

---

## 3. Testing Policy & Rootless Invariant

- **Zero Root Privileges in Tests**:
  All automated tests (`go test ./...` and `make test`) **must never** require `sudo`, root privileges, `CAP_NET_RAW`, or live network interfaces.
- **Race Detector**:
  All unit and integration tests must pass cleanly under the Go race detector (`go test -race ./...`).
- **Offline PCAP Replay**:
  Network packet processing is tested deterministically using in-memory synthetic packets (`testutil.MockPacketSource`), serialized `gopacket` frames, or offline `.pcap` files (`capture.NewOfflinePacketSource`).

---

## 4. Git Hooks & Continuous Integration

- **Optional Local Hooks**:
  Pre-commit and pre-push hooks are provided as convenience checks to help catch formatting, linting, and secret scanning issues locally before pushing:
  ```bash
  make hooks
  ```
  Note that local hooks are optional convenience tools. **GitHub Actions CI is the authoritative quality gate** for all PRs and pushes to `main`.
- **Conventional Commits**:
  Please format commit messages using [Conventional Commits](https://www.conventionalcommits.org/):
  - `fix(...)`: Bug fixes (e.g. `fix(parser): ...`, `fix(capture): ...`)
  - `feat(...)`: New features or CLI flags
  - `chore(...)`: Maintenance, dependency updates, or toolchain alignment
  - `test(...)`: Adding or improving tests
  - `docs(...)`: Documentation updates

---

## 5. Security & Vulnerability Scanning

Before submitting changes, ensure no secrets or vulnerabilities are introduced:
```bash
# Run secrets detection scan
make secrets

# Run container and filesystem vulnerability scan
make trivy
```

---

## 6. Pull Request Process

1. Fork and create a branch from `main`.
2. Ensure `make fmt-check`, `make lint`, and `make test` pass cleanly.
3. Open a Pull Request describing your changes, motivation, and test coverage.
