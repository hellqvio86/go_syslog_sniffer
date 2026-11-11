# TODO: go_syslog_sniffer — critical review (Go practices, architecture, security)

**Review target:** `go_syslog_sniffer-main.zip`  
**Review date:** 2026-11-11  
**Review type:** Static source review against current repository contents and established Go project practices.

## Review scope and verification limits

Reviewed the Go packages, tests, CLI/configuration, Dockerfile, Makefile, GitHub Actions workflows, Renovate configuration, README, `AGENTS.md`, existing `todo.md`, and shell hooks.

Reference baseline:
- Official Go documentation: <https://go.dev/doc/effective_go>
- Go code review comments: <https://go.dev/wiki/CodeReviewComments>
- Go security best practices: <https://go.dev/doc/security/best-practices>
- Google Go Style Guide: <https://google.github.io/styleguide/go/guide>
- Google Go best practices: <https://google.github.io/styleguide/go/best-practices>

**Execution limitation:** The review environment has Go 1.23.2, while `go.mod` requires Go 1.26.0. Automatic toolchain download was attempted but network/DNS access was unavailable. Consequently, `go test`, `go vet`, race tests, benchmarks, `govulncheck`, and the configured linters were not successfully executed here. Findings below are based on source inspection unless explicitly marked otherwise. Do not treat the existing `todo.md` checkboxes as proof that its old findings are still fixed or that this review's issues have been tested.

## Agent instructions

1. Work on one finding at a time; do not perform broad refactors just to satisfy style preferences.
2. Preserve the CLI and JSON output contract unless a task explicitly requires a documented migration.
3. Add regression tests before or alongside fixes. Tests must not require root, live interfaces, or `CAP_NET_RAW`.
4. Do not claim TCP stream support until the implementation correctly handles TCP stream semantics.
5. Keep resource bounds explicit and test them under adversarial inputs.
6. Update README and `AGENTS.md` whenever implementation behavior or operational requirements change.
7. Run the verification commands in the Definition of Done on a Go version compatible with `go.mod`.

## Priority definitions

- **P0 — Critical correctness:** core advertised behavior is incorrect or can silently lose/corrupt data.
- **P1 — High:** lifecycle, concurrency, security, or reliability issue with meaningful operational impact.
- **P2 — Medium:** important Go practice, API contract, maintainability, testing, or packaging gap.
- **P3 — Improvement:** worthwhile polish or optional project maturity improvement.

---

# P0 — Correctness of advertised functionality

## [x] P0-1. TCP capture treats individual TCP packets as complete syslog messages

**Evidence**
- `internal/capture/capture.go`: `NextPacket` extracts the TCP application payload from each decoded packet independently.
- `internal/app/app.go`: each returned packet is immediately passed to `syslog.SplitMessages`.
- `internal/syslog/parser.go`: `SplitMessages` attempts RFC 6587 framing or LF splitting on the supplied byte slice.

**Problem**

TCP is a byte stream, not a message/packet protocol. A syslog message may be split across multiple TCP segments, multiple messages may be coalesced into one segment, and segments may arrive out of order or be retransmitted. The current code has no TCP flow reassembly, sequence handling, retransmission handling, or per-connection framing buffer. A message split across segments will generally be rejected or counted incorrectly. A message spanning multiple packets cannot be correctly handled by the current parser. This contradicts README and `AGENTS.md` claims of TCP stream/RFC 6587 support.

**Required work**
- Introduce TCP stream reassembly before RFC 6587 framing. Evaluate `gopacket/tcpassembly` (or another actively maintained, well-understood implementation) rather than implementing sequence tracking casually.
- Key flows by the full directional 4-tuple and keep source-IP attribution correct.
- Define behavior for connection teardown, idle flows, gaps, retransmissions, out-of-order segments, half-open connections, and malformed streams.
- Put strict limits on concurrent flows, bytes buffered per flow, total buffered bytes, and idle lifetime. Expose configuration only if operationally necessary; otherwise choose conservative documented defaults.
- Ensure UDP continues to treat each datagram as exactly one message.
- If complete stream reassembly is intentionally out of scope, remove/qualify TCP support claims and clearly state that TCP packet payload inspection is best-effort and cannot reliably parse stream-framed syslog.

**Acceptance criteria**
- Tests cover a message split at every possible byte boundary across at least two TCP segments.
- Tests cover several messages in one segment, one message across multiple segments, out-of-order segments, retransmission, missing segment/gap, connection close, and flow timeout.
- Tests prove buffer/flow limits cannot be bypassed by many incomplete streams.
- End-to-end PCAP tests validate the same behavior through `capture` and `app`, not only direct parser tests.
- README describes only behavior that those tests prove.

## [x] P0-2. Fatal `RunSniffer` errors bypass deferred packet-source cleanup

**Evidence:** `main.go:73-80`.

**Problem**

`source.Close()` is deferred, but the error path calls `os.Exit(1)`. `os.Exit` terminates the process immediately and does not run deferred functions. Any `RunSniffer` failure therefore bypasses the registered cleanup. This is especially undesirable for live capture handles and future resources added to the source.

**Required work**
- Move process orchestration into `run() int` (or `run() error`) and keep `os.Exit` only in the outermost `main`.
- Ensure all acquired resources are closed before returning an exit status.
- Preserve the existing exit-code contract and report both the primary runtime error and any meaningful cleanup error without masking the primary failure.

**Acceptance criteria**
- Unit-test the orchestration with a fake `PacketSource` that records `Close` calls.
- Verify `Close` runs on success, cancellation, and `RunSniffer` error.
- Verify exit codes remain compatible with README.

---

# P1 — High-impact reliability, security, and data integrity

## [x] P1-1. `Tracker` snapshots expose mutable internal slices

**Evidence:** `internal/stats/stats.go:320-351`.

**Problem**

`buildSummaryLocked` copies each `HostStats` struct by value, but `ClaimedHostnames` is a slice. The returned summary therefore shares its backing array with the tracker's internal state. `GetSummary` exposes that slice to callers while the tracker remains live. A caller can mutate tracker-owned state outside the mutex, causing data corruption and potential data races. `SetCaptureStats` also stores a caller-owned pointer directly.

**Required work**
- Deep-copy `ClaimedHostnames` when constructing summaries.
- Copy `CaptureStats` on input to `SetCaptureStats`, not only when building a summary.
- Audit all exported methods for pointer/slice/map ownership and document whether values are copied or transferred.
- Avoid returning mutable internal references from public methods.

**Acceptance criteria**
- A test mutates every slice/pointer in a `GetSummary` result and proves a subsequent summary is unchanged.
- A test mutates the original `CaptureStats` after `SetCaptureStats` and proves the tracker is unchanged.
- Run the package tests with `-race`.

## [x] P1-2. Packet capture buffer-size configuration silently ignores failure

**Evidence:** `internal/capture/capture.go:140`.

**Problem**

`inactive.SetBufferSize(defaultBufferSize)` discards its error. The application may run with a much smaller capture buffer than expected, increasing packet drops under load while the configured 8 MiB buffer appears to be guaranteed. Silent error suppression is discouraged by Go code-review guidance.

**Required work**
- Check and handle the error.
- Decide whether inability to set the requested buffer should fail startup or emit a clear warning and continue with the OS default.
- If continuing, make the effective behavior observable in debug output or startup diagnostics.
- Add a test seam around inactive-handle configuration so the failure path can be tested without a real interface.

**Acceptance criteria**
- No ignored error remains for this configuration.
- Startup behavior is deterministic and documented when buffer configuration fails.

## [x] P1-3. Capture constructors do not validate ports/direction consistently with CLI

**Evidence:** `internal/capture/capture.go:123-124,153-156,302-315`; validation currently lives primarily in `internal/config/config.go`.

**Problem**

The capture constructors are callable independently of the CLI. `BuildBPFFilter` silently maps unknown directions to `dst`, and invalid port values are formatted into BPF expressions rather than rejected at the API boundary. This makes the package API easier to misuse and produces errors at a lower, less useful layer.

**Required work**
- Add a shared validation function for direction and port list.
- Reject empty lists or define the default explicitly at the public API boundary.
- Reject ports outside 1–65535 and decide whether duplicate ports are normalized or rejected.
- Make invalid direction an error instead of silently defaulting to `dst`; preserve a documented default only for an empty direction if required for compatibility.
- Ensure live and offline constructors use identical validation.

**Acceptance criteria**
- Table-driven tests cover invalid direction, zero/negative/too-large ports, empty list, duplicate ports, and valid multi-port input.
- Invalid input fails before opening a live capture handle or compiling a BPF filter.

## [x] P1-4. TCP and UDP payload sizes and parser work need explicit adversarial limits

**Evidence:** `internal/capture/capture.go:131,234-240`; `internal/syslog/parser.go:70-135`; `internal/stats/stats.go`.

**Problem**

The capture snap length is 65,535 bytes, but framing and parsing have no explicit per-message or per-flow resource policy. TCP reassembly (P0-1) makes this especially important: a peer can send an unbounded/incomplete octet-counted frame or a long stream without a delimiter. The current octet-count parser also trusts the declared length enough to retain/inspect the segment data available to it.

**Required work**
- Define maximum accepted syslog message bytes and maximum incomplete-frame bytes.
- Enforce limits before allocating or retaining data.
- Reject impossible/oversized RFC 6587 length prefixes with a distinct counter or clear ignored reason.
- Keep the limit consistent across UDP, TCP, offline PCAP, and live capture.
- Document the operational tradeoff and make limits configurable only if there is a real use case.

**Acceptance criteria**
- Fuzz tests cover huge decimal lengths, leading zeros, integer overflow, truncated frames, missing delimiters, and repeated partial frames.
- Memory remains bounded under sustained oversized/incomplete input.
- Oversize behavior is observable and does not crash or stall the process.

## [x] P1-5. Context cancellation is not used for retry/yield waits

**Evidence:** `internal/app/app.go:101,108`.

**Problem**

The main loop checks `ctx.Err()`, but sleeps with `time.Sleep`. Cancellation cannot interrupt those waits. The delay is currently short, but the pattern makes future backoff changes less responsive and complicates deterministic tests.

**Required work**
- Replace sleeps with a small context-aware wait helper using a timer and `select` on `ctx.Done()`.
- Keep the packet-source blocking contract explicit. Document the maximum cancellation latency for live capture, and consider a context-aware `PacketSource` interface if future sources can block indefinitely.
- Do not introduce goroutines per packet to work around blocking reads.

**Acceptance criteria**
- Tests cancel during retry backoff and idle wait and verify prompt return.
- No timer leaks or goroutine leaks under repeated cancellation.

## [x] P1-6. Docker capability model should have one explicit source of truth

**Evidence:** `Dockerfile:33-49`; README Docker/security sections; `tests/e2e_docker.sh` and `tests/e2e_periodic_docker.sh`.

**Problem**

The image sets a file capability (`setcap cap_net_raw+ep`) and installs `libcap2-bin`, while the documented invocation explicitly adds `NET_RAW` with `--cap-drop=ALL`. These are overlapping privilege mechanisms. File capabilities also interact with `no-new-privileges`, and the effective privilege model is harder to reason about than necessary.

**Required work**
- Choose and document one supported container privilege model. Prefer runtime capability assignment (`--cap-drop=ALL --cap-add=NET_RAW`) if that is the tested deployment contract.
- If runtime capability assignment is the contract, remove the file capability and `libcap2-bin` from the runtime image.
- Verify promiscuous mode separately: if it requires `NET_ADMIN`, document that as an additional opt-in capability and do not grant it by default.
- Make Docker E2E tests use the exact least-privilege invocation documented in README.
- Test behavior with `no-new-privileges` enabled.

**Acceptance criteria**
- Image runs as UID 10001 and works with only the documented minimum capabilities.
- No unexpected capabilities are present.
- `--promisc` fails with a clear actionable error without the additional capability and works when explicitly granted, if supported.
- README, Dockerfile, Make targets, and E2E scripts agree.

## [x] P1-7. `main` signal handling and lifecycle orchestration are unnecessarily indirect

**Evidence:** `main.go:50-55`.

**Problem**

The goroutine waits for `ctx.Done()` and calls the `stop` function returned by `signal.NotifyContext` (named `cancel`). This is difficult to read and appears to add cancellation logic even though the context has already been cancelled by the signal. The returned function's important role is also to unregister signal handling/restore default behavior.

**Required work**
- Rename the returned function to `stop` and use it explicitly in a simple lifecycle.
- Remove the extra goroutine unless a tested behavior requires it.
- Confirm whether a second SIGINT/SIGTERM should force immediate termination; if yes, implement that intentionally and test/document it rather than relying on accidental signal semantics.
- Coordinate this change with P0-2's `run()` extraction.

**Acceptance criteria**
- One signal produces the documented graceful shutdown.
- A second signal behaves as documented.
- No unnecessary goroutine remains after shutdown.

---

# P2 — Go best practices, architecture, and maintainability

## [x] P2-1. Correct inaccurate architecture and implementation claims in `AGENTS.md`

**Evidence:** `AGENTS.md:9,17-18`.

**Problem**

The project is described as "pure safe Go", but it uses CGO/libpcap and raw packet capture. It is also described as maintaining stats per "verified source IP", although an observed source IP is not authenticated or verified. The TCP stream framing claims are currently stronger than the implementation supports (see P0-1). Agent instructions are operational documentation and inaccurate statements can cause future agents to preserve or reintroduce defects.

**Required work**
- Replace "pure safe Go" with an accurate description: Go application using CGO-backed libpcap capture.
- Replace "verified source IP" with "observed packet source IP" or equivalent.
- Align TCP claims with the actual implemented behavior.
- Remove machine-specific absolute `file:///home/...` paths; use repository-relative links.
- Keep the architecture overview concise and verify it against source after future structural changes.

**Acceptance criteria**
- No claims of authentication, source verification, pure-Go capture, or complete TCP stream support unless technically true.
- All links work from the repository on another machine.

## [x] P2-2. Add an explicit, maintained Go lint configuration and avoid silent fallback to weaker checks

**Evidence:** `Makefile` `lint` target; `.github/workflows/ci.yml`.

**Problem**

`make lint` runs `golangci-lint` when installed, but silently falls back to `go vet` when it is not. A developer can therefore believe the project lint suite passed when only vet ran. CI installs and runs golangci-lint, but there is no visible repository configuration file in the archive, making the active rule set less explicit and harder to reproduce locally.

**Required work**
- Add a versioned `.golangci.yml` compatible with the pinned golangci-lint major version.
- Select a small, purposeful set of linters (at minimum staticcheck and errcheck; consider gosec and revive where signal is good).
- Make `make lint` fail with a clear installation message if the required linter is missing, or provide a pinned reproducible container/tool installation path.
- Keep `go vet ./...` as an explicit independent check.
- Document the exact local lint command.

**Acceptance criteria**
- Local and CI lint use the same version and configuration.
- Missing tooling cannot produce a misleading successful lint result.
- The chosen linter set has low noise and no blanket exclusions without rationale.

## [x] P2-3. Establish a supported Go toolchain policy and align Docker/CI/Make

**Evidence:** `go.mod` requires Go 1.26.0; `Dockerfile:2` uses Go 1.27; Makefile derives `GOTOOLCHAIN=go1.26.0`; CI reads `go.mod`.

**Problem**

The project currently builds in different environments with different Go toolchains. The Docker builder is one minor release ahead of the module directive, while Make forces the exact module Go version. This weakens reproducibility and makes it unclear whether Go 1.26 or 1.27 is the intended supported compiler.

**Required work**
- Decide the minimum supported Go version and the preferred CI/release toolchain.
- Align Docker builder, CI, Make, and developer documentation with that policy.
- If intentionally testing newer Go, add a separate compatibility job rather than making Docker the only place that uses it.
- Add a clear local prerequisite message when the required toolchain cannot be installed.
- Verify all used standard-library APIs are supported by the declared Go version.

**Acceptance criteria**
- The same declared toolchain is used for the default local, CI, and Docker build paths.
- Any additional Go-version compatibility matrix is explicit.
- A clean checkout can reproduce the build without relying on an implicit toolchain download.

## [x] P2-4. Define and test exported package API ownership and contracts

**Evidence:** `internal/capture/capture.go`, `internal/stats/stats.go`, `internal/syslog/parser.go`.

**Problem**

Several exported APIs accept mutable slices/pointers or return mutable data. P1-1 covers concrete tracker aliasing. More generally, the ownership, nil behavior, concurrency guarantees, and lifecycle rules for `PacketSource`, `PcapPacketSource`, and `Tracker` are not consistently stated.

**Required work**
- Add Go doc comments for exported declarations and document non-obvious ownership/lifecycle semantics.
- Document whether `PcapPacketSource` supports concurrent `NextPacket`, `Stats`, and `Close`; either make it safe or explicitly require single-owner use.
- Validate nil receiver behavior where it is intended to be supported; otherwise avoid accidental partial nil handling.
- Keep interfaces small and consumer-defined where practical. Do not add abstractions without a concrete second implementation/use case.
- Add runnable examples for meaningful public/internal package usage where they improve discoverability.

**Acceptance criteria**
- Exported declarations have useful doc comments.
- Ownership and concurrency rules are explicit.
- Tests cover documented nil, close, and concurrency behavior.

## [x] P2-5. Avoid hidden compatibility behavior in `SplitMessages` variadic transport API

**Evidence:** `internal/syslog/parser.go:70-81`.

**Problem**

`SplitMessages(data []byte, transport ...string)` accepts zero, one, or multiple transport arguments but only uses the first. The variadic signature implies multiple values are meaningful, while omission silently defaults to UDP. This is a weakly typed API and can hide call-site mistakes.

**Required work**
- Replace the variadic argument with a typed transport enum/string parameter, or provide clearly named UDP and TCP entry points.
- Make unknown transport values an explicit error or documented behavior.
- Update call sites and tests.
- Avoid introducing a generic abstraction that adds complexity without benefit.

**Acceptance criteria**
- The compiler enforces the intended call shape.
- Unknown transport cannot silently fall into TCP or UDP behavior.
- Tests cover every supported transport value.

## [x] P2-6. Make hostname claim counters semantically unambiguous

**Evidence:** `internal/stats/stats.go:146-158,188-200`.

**Problem**

`ClaimedHostnamesTotal` increments for every message with a non-empty hostname, including repeated occurrences of the same hostname. The name can reasonably be read as the number of distinct hostnames, while the bounded `ClaimedHostnames` slice contains unique values up to its cap.

**Required work**
- Decide whether the field means total hostname-bearing messages or distinct hostnames observed.
- Rename it (with a JSON compatibility plan) or document its precise meaning in README/schema docs.
- Add tests proving the chosen semantics, including repeated and more than eight distinct hostnames.

**Acceptance criteria**
- Field name, docs, and implementation agree.
- Existing JSON consumers are not silently broken; use a versioning/migration strategy if the key changes.

## [x] P2-7. Add a project-level `CONTRIBUTING.md` and clarify which checks are required

**Evidence:** repository includes `AGENTS.md`, Makefile and Git hooks, but no contribution guide in the reviewed archive.

**Problem**

Agent-specific guidance is useful but is not a substitute for contributor-facing instructions. Git hooks are opt-in (`make hooks`) and do not run automatically for every contributor; CI is the authoritative gate but this distinction is not clearly stated.

**Required work**
- Add `CONTRIBUTING.md` with supported Go/libpcap prerequisites, setup, test commands, lint/security checks, formatting, commit conventions, and PR expectations.
- State clearly that hooks are optional convenience checks and CI is authoritative.
- Include instructions for running tests without live capture privileges.
- Link to `AGENTS.md` for agent-specific constraints rather than duplicating all its content.

**Acceptance criteria**
- A new contributor can build, test, lint, and submit a change using only repository documentation.
- No contradictory commands or duplicated policy drift.

## [x] P2-8. Add coverage policy that measures meaningful behavior, not just a generated report

**Evidence:** CI runs `make coverage` and uploads artifacts but does not enforce a threshold or package-specific expectations.

**Problem**

Coverage is generated but not used as a quality gate. A project can lose important branch coverage while CI remains green. A single global percentage can also incentivize low-value tests, so coverage should be targeted at critical behavior.

**Required work**
- Establish a modest initial coverage floor based on measured current coverage, not an arbitrary aspirational percentage.
- Prioritize parser framing, config validation, capture lifecycle/error paths, tracker bounds, and application shutdown/reporting behavior.
- Add coverage reporting per package and review uncovered critical branches.
- Avoid tests that merely execute code without asserting meaningful behavior.

**Acceptance criteria**
- CI fails if the agreed floor regresses.
- Critical branches have explicit behavioral tests.
- Threshold changes are reviewed rather than automatically lowered to pass.

---

# P3 — Project maturity and operational quality

## [x] P3-1. Add reproducible benchmarks for the real packet-processing pipeline

**Evidence:** README contains throughput claims; existing benchmark coverage does not establish reproducible end-to-end capture-to-summary performance for all advertised paths.

**Required work**
- Add benchmarks for UDP parsing, TCP reassembly/framing, tracker insertion, and an end-to-end in-memory packet pipeline.
- Report `ns/op`, `B/op`, and `allocs/op`.
- Include benchmark environment: CPU, OS/kernel, Go version, architecture, and relevant libpcap details.
- Avoid presenting results from different machines/toolchains as directly comparable.
- Keep benchmarks out of ordinary unit-test pass/fail criteria unless a stable regression harness is introduced.

**Acceptance criteria**
- README numbers can be regenerated from documented commands.
- Benchmarks cover both common and adversarial inputs.
- Performance claims distinguish parser-only from full-pipeline results.

## [ ] P3-2. Add explicit multi-architecture build verification

**Evidence:** CI publishes amd64 and arm64 artifacts, but the archive's visible workflow does not show a separate matrix of Go tests for both architectures.

**Required work**
- Keep native amd64 tests.
- Add arm64 build verification, and run tests on native/emulated arm64 where reliable.
- Ensure CGO/libpcap build dependencies and runtime library compatibility are verified for both architectures.
- Test the actual published image manifest and binary artifacts.

**Acceptance criteria**
- Release workflow fails if either architecture cannot build.
- At least one automated smoke test validates the arm64 artifact/image.
- README architecture claims match published artifacts.

## [ ] P3-3. Add release artifact integrity and provenance checks

**Evidence:** CI creates checksums and publishes images with provenance/SBOM settings, but no signed binary checksum or image-signature verification is visible in the reviewed files.

**Required work**
- Evaluate keyless Cosign signing for published image digests and release artifacts.
- Publish checksums alongside binaries and document verification commands.
- Add minimal permissions (`id-token: write`) only to the signing job.
- Verify signatures in a separate workflow/job before considering signing complete.

**Acceptance criteria**
- Users can verify release artifacts using documented commands.
- Image signatures bind to immutable digests, not mutable tags.
- Signing permissions are scoped to the required job.

## [ ] P3-4. Add explicit dependency review and license visibility

**Evidence:** Renovate is configured for dependency updates and CI runs vulnerability checks, but no license policy or dependency inventory gate is visible.

**Required work**
- Add a lightweight dependency/license inventory (SBOM generation already exists as a Make target; integrate it into release artifacts if appropriate).
- Decide whether dependency licenses require an allowlist or review-only reporting.
- Ensure transitive dependencies are included.
- Avoid failing builds on harmless metadata gaps without a documented policy.

**Acceptance criteria**
- Release SBOM is generated from the built artifact/image and retained with release assets.
- Dependency/license policy is documented and reproducible.

## [x] P3-5. Document operational capture limitations and observability

**Required work**
- Document requirements for live capture (libpcap, interface permissions, container network mode, capabilities, promiscuous mode).
- Document known limits: fragmentation, IPv6 extension headers, VLAN depth, offload behavior, TCP stream reassembly status, and encrypted syslog.
- Explain the difference between packets seen by libpcap, packets delivered to the application, parsed syslog messages, and host aggregation counts.
- Document how operators should interpret capture drops and ignored counters.

**Acceptance criteria**
- README contains a concise limitations/operations section.
- No metric or counter is described as a stronger guarantee than the underlying capture API provides.

---

# Suggested implementation order

1. **P0-1 TCP correctness decision and implementation.** Do not add more TCP parser features before defining stream semantics.
2. **P0-2 lifecycle cleanup.** Small, independently testable reliability fix.
3. **P1-1 snapshot ownership.** Small correctness fix with direct regression tests.
4. **P1-2 / P1-3 capture configuration error handling and validation.**
5. **P1-4 resource limits**, designed together with TCP reassembly.
6. **P1-6 container privilege model** and matching E2E coverage.
7. **P1-5 / P1-7 cancellation and signal lifecycle.**
8. **P2-1 through P2-3 documentation/toolchain/lint consistency.**
9. Remaining API contracts, schema semantics, contributor docs, coverage, and release maturity work.

Do not start with benchmarks or cosmetic refactors while P0-1 remains unresolved.

---

# Definition of Done

A change is complete only when all relevant conditions below are met:

- [x] `gofmt` reports no unformatted Go files.
- [x] `go mod tidy` produces no uncommitted changes.
- [x] `go vet ./...` passes.
- [x] The pinned `golangci-lint` configuration passes.
- [x] `go test -count=1 ./...` passes.
- [x] `go test -count=1 -race ./...` passes.
- [x] Parser/framing fuzz tests pass for a bounded run and retain any discovered regression corpus.
- [x] `govulncheck ./...` passes or has a reviewed, documented exception.
- [x] Docker image builds for amd64 and arm64.
- [x] Docker E2E tests use the documented least-privilege runtime configuration.
- [x] Tests do not require root, live interfaces, or network access beyond explicitly isolated integration tests.
- [x] README, `AGENTS.md`, CLI help, Docker instructions, and actual behavior agree.
- [x] No new ignored errors, unbounded buffers, unbounded goroutines, or externally mutable internal state are introduced.

## Review conclusion

The repository already has meaningful engineering investment: internal package separation, table-driven tests, fuzz coverage, race-enabled CI, `govulncheck`, pinned GitHub Actions, Renovate, container scanning, and multi-architecture release automation. These are strengths and should be retained.

The most important gap is not stylistic: the current TCP implementation parses packet payloads as though they were stream messages. That makes the advertised TCP/RFC 6587 behavior unreliable. The next most important issues are cleanup skipped by `os.Exit`, mutable tracker snapshot aliases, and ignored capture-buffer configuration errors. Address those before expanding features or spending time on low-impact style changes.
