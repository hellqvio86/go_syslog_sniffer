# TODO: go_syslog_sniffer — critical review (v2, against current code)

Repo: hellqvio86/go_syslog_sniffer, reviewed from the uploaded zip at commit `38f7b1a` (module `go 1.25.0`, packages `pkg/{app,capture,config,stats,syslog}`, Dockerfile, CI, Renovate + Dependabot).
This replaces my earlier review, which was written against the old single-file `sniffer.go` (commit `884d292`). Most of that review no longer applies; see "Status of the previous review" at the bottom.

## How this was verified

- `go vet ./...` clean; `go test -race ./...` passes. (Run in a scratch copy with the `go` directive lowered to 1.22 because the sandbox only had Go 1.22.)
- Coverage: app 72.4%, capture 60.0%, config 92.3%, stats 100%, syslog 100%, main 0%.
- Behavioural claims below marked **[probed]** were confirmed with synthetic Ethernet/IP/TCP/UDP frames built with `gopacket.SerializeLayers` and fed through `PcapPacketSource.NextPacket` + `syslog.ParseSyslogPacket` (probe code in the appendix).
- NOT verified: live pcap capture, the Docker build, whether CI is currently green, GitHub-side settings (branch protection, GHCR visibility), and whether the pinned action versions exist.

## Instructions for the agent

- Work top-down by priority. One commit per task ID, message prefixed with the ID.
- Every behavioural fix needs a test. Use the synthetic-frame helper from the appendix so tests need neither root nor a live interface.
- Run `gofmt -s`, `go vet ./...`, `go test -race ./...` before finishing each task.
- Keep `-i/-p/-t/-d/-v` and the long flags backward compatible. Changes to the JSON schema must be called out in the README and bump `VERSION`.
- Locate code by function name; line numbers drift.

## Behaviour summary (context)

`NewPcapPacketSource` opens a live pcap handle (promiscuous, snaplen 262144, 250 ms read timeout) with BPF `port N`. `NextPacket` returns the UDP/TCP application payload (falling back to the whole raw frame) plus the source IP. `ParseSyslogPacket` accepts the payload if it is valid UTF-8, optionally extracts a hostname (RFC 5424 or 3164 regex). `RunSniffer` keys a `StatsTracker` by that **hostname from the message** (fallback: source IP, then `"Unknown"`), keeping a count and the first message as sample. Output is pretty JSON `{interval_seconds, hosts{host:{count,sample}}}`, once at the end or every `--frequency` seconds with `--periodic`.

---

## P0 — correctness

### [x] B1. Anything that is valid UTF-8 is counted as syslog **[probed]**
- **Where:** `syslog.ParseSyslogPacket`; `capture.PcapPacketSource.NextPacket` (raw-frame fallback).
- **Problem:** The only gate is `utf8.Valid`. The old code at least required `<digits>`. Now:
  - A UDP datagram `GET / HTTP/1.1\r\n` on port 514 is counted as a syslog event (host = source IP, sample = that text). Probe result: `COUNTED as syslog`.
  - The "first `<` anywhere" heuristic discards leading bytes, so a payload merely containing `<` is treated as syslog starting there.
  - PRI is never range-checked: `<999>Oct 11 22:14:15 evil x: y` is accepted, host `evil`.
  - `NextPacket` falls back to `pkt.Data()` (the **entire Ethernet frame**) when `ApplicationLayer()` is nil, i.e. for pure TCP ACK/SYN-ACK segments and empty UDP datagrams. Because `port N` also matches the collector's replies (B3), these frames arrive constantly. They are rejected only when the frame bytes happen to be invalid UTF-8. Probe: 13 of 2000 loopback-style pure-ACK frames (0.65%) were counted as syslog events with a binary-garbage sample. On a real network the rate depends on MAC/checksum bytes, but it is nonzero and the sample is junk.
- **Fix:**
  1. In `NextPacket`, if there is no application layer return "no payload" (skip), never `pkt.Data()`.
  2. In the parser, require the message to start with `<PRI>` where PRI is 1–3 digits and ≤ 191, optionally preceded by an RFC 6587 octet-count prefix (`^\d+ `). Drop the "first `<` anywhere" heuristic.
  3. Return a typed reason for rejection (`ErrNotSyslog`, `ErrEmpty`) so the app can count ignored packets (see S5).
- **Acceptance:** table-driven tests for: valid 5424, valid 3164, octet-counted, `GET / HTTP/1.1`, `<999>`, text with `<` in the middle, empty payload, pure TCP ACK frame, SYN-ACK frame, empty UDP frame. Only the valid ones are counted.

### [x] B2. Valid syslog that is not valid UTF-8 is silently dropped **[probed]**
- **Where:** `ParseSyslogPacket` (`if !utf8.Valid(...) { return nil }`).
- **Problem:** `<13>Oct 11 22:14:15 h app: caf\xc3` (a message truncated mid-multibyte-character, which senders that truncate at a size limit produce routinely) is rejected and **not counted at all**. The same applies to Latin-1 hostnames or message bodies. A tool whose job is to discover who is sending syslog should not make senders disappear.
- **Fix:** Count the packet, and sanitize only the sample: `strings.ToValidUTF8(msg, "\uFFFD")`, or add `"sample_encoding":"base64"` when the payload is not valid UTF-8. Never drop.
- **Acceptance:** the probe case above yields a host entry with count 1 and a valid-JSON sample.

### [x] B3. BPF `port N` matches both directions
- **Where:** `NewPcapPacketSource` (`filter := fmt.Sprintf("port %d", port)`).
- **Problem:** Replies from the collector (TCP ACKs, SYN-ACKs with source port 514) are captured too. Together with B1 they pollute counts and produce false hosts keyed by the collector's own IP.
- **Fix:** default to `dst port N`; optionally `--direction dst|src|both`. Multiple ports: `--port 514,601` → `(dst port 514 or dst port 601)`.
- **Acceptance:** test with a synthetic TCP handshake plus data plus ACKs: only the sender is counted with the default. Unit-test the generated filter string.

### [x] B4. Host key is sender-controlled and the real source address is lost **[probed]**
- **Where:** `app.RunSniffer` (hostname selection), `stats.StatsTracker`.
- **Problem:** Entries are keyed by the *hostname claimed inside the message*. Consequences:
  - One IP can create unlimited keys by varying the hostname field (see S1), and many machines claiming the same name merge into one entry.
  - Output never shows the sending IP when a hostname was parsed, which defeats the main use case ("who is sending syslog to this box?").
  - RFC 5424 NILVALUE `-` is used as a real hostname. Probe: `<165>1 2026-11-07T12:00:00Z - app 1 - - msg` → key `"-"`.
  - The 5424 regex requires `\d` + whitespace after PRI, so rsyslog's default high-precision 3164 variant (`<13>2026-11-07T12:00:00+01:00 myhost app: msg`) gets no hostname (probe: `host=""`) and silently falls back to the IP.
- **Fix:** Key by source IP (`netip.Addr`); keep `hostname` (claimed) as a field, plus `src_ip`. Treat `-` as empty. Validate claimed hostnames (≤255 bytes, printable, no whitespace). Support the ISO-timestamp 3164 variant. Optionally keep `--group-by ip|hostname`.
- **Acceptance:** two IPs claiming the same hostname produce two entries; one IP varying hostnames produces one entry; `-` never appears as a hostname.

### [x] B5. Capture failure is swallowed; persistent errors would spin
- **Where:** `PcapPacketSource.NextPacket`, `app.RunSniffer`.
- **Problem:** When the packet channel closes (interface down, pcap error) `NextPacket` returns `(nil, nil)` forever; the loop sleeps 10 ms per iteration until the interval ends, prints an empty `{"hosts":{}}` and exits 0. Separately, the `err != nil → continue` path has no backoff or limit; if a source ever returns persistent errors this spins at 100% CPU for the whole interval.
- **Fix:** Return `io.EOF` (or a typed `ErrCaptureClosed`) from `NextPacket` when the channel is closed; `RunSniffer` returns an error (exit 1, message on stderr, partial results still printed). Add a consecutive-error limit with small backoff.
- **Acceptance:** test with a source that returns EOF early → non-nil error and exit code 1; test with a source that returns errors forever → returns after N errors.

---

## P1 — robustness and security

### [x] S1. Unbounded memory from untrusted input
- **Where:** `stats.StatsTracker`, `syslog.rfc*Regex` (`\S+` has no length bound), `PacketData.Data`.
- **Problem:** The host map is keyed by a sender-controlled string of unbounded length, and each entry stores the whole first message (up to ~64 KB for UDP, more for TCP). A single sender can grow memory without limit; `GetSummary` then copies everything again.
- **Fix:** `--max-hosts` (default 10000) with an `overflow_events` counter in the output when the cap is hit; truncate hostname to 255 bytes and the sample to a configurable `--sample-bytes` (default 2048) with a `sample_truncated` boolean.
- **Acceptance:** test feeding > max-hosts distinct keys and a 64 KB message: map size and sample length stay capped, overflow counter is reported.

### [x] S2. `--periodic` stops after `-t`; there is no "run until signalled"
- **Where:** `config.ParseArgs`, `app.RunSniffer`.
- **Problem:** Periodic mode is bounded by `Interval` (default 10 s), so `--periodic --frequency 5` produces two reports and exits unless the user also passes a large `-t`. `-t 0` is indistinguishable from "unset" (the code uses 0 as sentinel for both port and interval), so infinite capture can't be requested. Huge values of `Interval`/`Frequency` overflow `time.Duration` (uint64 → int64) and make the loop exit immediately.
- **Fix:** Detect explicitly-set flags with `fs.Visit`; define `-t 0` = unlimited; make periodic default to unlimited; validate upper bounds (`≤ 1<<31` seconds or use `time.Duration` with overflow check).
- **Acceptance:** config tests for explicit 0, unset, huge values; app test showing periodic mode emits ≥ 3 reports with a mock source and a fake clock.

### [x] S3. Config validation and the `eth0` default
- **Where:** `config.ParseArgs`.
- **Problem:** `-p 70000` or `-p -5` fail later as an opaque BPF error. The default interface `eth0` doesn't exist on most modern Linux hosts (predictable names like `enp3s0`) and in many containers, so the zero-argument run fails with `failed to open interface eth0`.
- **Fix:** Validate port 1–65535 in `ParseArgs`. Default to `any` on Linux (supported by libpcap) or, on failure to open, list candidates via `pcap.FindAllDevs()` in the error message. Add `--list-interfaces`.
- **Acceptance:** tests for out-of-range ports; error message for an unknown interface contains the available device names.

### [x] S4. Kernel/interface drops are invisible, so counts are only lower bounds
- **Where:** `capture` (no use of `handle.Stats()`); README says "high-performance".
- **Fix:** On `Close()`/end of run read `handle.Stats()` and report `capture_stats {received, dropped, if_dropped}` (stderr in debug mode, and as an optional JSON object). For busy collectors use `pcap.NewInactiveHandle` + `SetBufferSize` before `Activate`.
- **Acceptance:** stats appear in debug output; documented in README as "counts are lower bounds when drops > 0".

### [x] S5. Silent ignoring and protocol limitations
- **Problem:**
  - TCP is handled per segment (no reassembly): several newline-framed messages in one segment count as 1; a message split across segments yields junk samples.
  - TLS syslog (usually 6514) is encrypted; after B1 it will be rejected with no hint to the user.
  - UDP fragments: later fragments carry no ports and are not matched by `port N`; the first fragment is a truncated message.
  - There's no counter for packets that were seen and ignored.
- **Fix:** Add `ignored` counters to the output (`no_payload`, `not_syslog`, `non_utf8_sanitized`), detect a TLS ClientHello (`0x16 0x03`) and report `"tls_suspected": true` for that source, split newline-framed TCP payloads into separate events, and document the remaining limitations in the README. Optional later: `gopacket/tcpassembly`.
- **Acceptance:** tests for a multi-message TCP segment (count = number of messages) and a TLS-looking payload.

### [x] S6. Sample content handling
- **Problem:** Samples are raw log lines (possibly secrets/PII) printed to stdout; `--debug` prints every full message to stderr with control characters unescaped (terminal escape injection). JSON output itself is escaped correctly (`SetEscapeHTML(false)`; control chars stay `\uXXXX`).
- **Fix:** Add `--no-sample` and `--redact-sample` options; print debug messages with `%q`; add a "Security considerations" section to the README.
- **Acceptance:** test that a sample containing ESC is escaped in debug output; `--no-sample` output has no `sample` field.

---

## P2 — design and code quality

### [x] R1. Capture performance and the "high-performance" claim
- `gopacket.NewPacketSource` is used with default `DecodeOptions` (copies each packet, decodes all layers eagerly); `NextPacket` allocates a `time.After` timer on every call. No benchmark exists.
- **Fix:** set `DecodeOptions{Lazy: true, NoCopy: true}` (copy the payload before storing), reuse one `time.Timer` or restructure around the channel/ctx, add `BenchmarkParseSyslogPacket` and a replay benchmark over a synthetic 100k-packet pcap; either keep the README claim with numbers or drop it.

### [x] R2. Test double in production package; add offline source
- `MockPacketSource` is defined in `capture.go` (non-test file), so it is exported API and compiled into the binary. Move it to a `_test.go` file or `internal/testutil`.
- Add `OfflinePacketSource` (`pcap.OpenOffline`) and a `-r file.pcap` flag. It enables fixtures, regression tests and analysing captures from other machines.

### [ ] R3. Layout and naming
- App-private code lives in `pkg/` (importable by anyone); move to `internal/`.
- Stutter: `stats.StatsTracker`, `syslog.SyslogPacket`, `syslog.ParseSyslogPacket`, `stats.JsonSummary` → `stats.Tracker`, `syslog.Message`, `syslog.Parse`, `JSONSummary`.
- `interface{}` → `any`; `err == flag.ErrHelp` in `main` → `errors.Is`; `PacketData.SrcIP string` → `netip.Addr` (avoids a string allocation per packet).

### [ ] R4. `StatsTracker` snapshot is not atomic
- Periodic mode calls `GetSummary` then `Clear` as two lock acquisitions. Safe today (single goroutine), a trap once a ticker goroutine or HTTP endpoint exists. Add `SnapshotAndReset(interval)` that swaps the map under one lock.

### [ ] R5. Periodic output is not machine-friendly
- It emits concatenated pretty-printed JSON documents, which are awkward for log shippers. Add `--format json|ndjson` (compact, one object per line). Intermediate reports put the nominal `--frequency` in `interval_seconds`, not the measured elapsed time; report `start`/`end` timestamps instead.

### [ ] R6. CLI ergonomics
- Short/long flag pairs are defined twice with "long wins" precedence and 0-as-unset (see S2). The `DEBUG=1` environment variable is undocumented. Consider a single definition per option with an alias helper. Generated `-h` output lists short and long variants as separate flags with duplicated defaults.

---

## P3 — tests

### [ ] T1. Parser
- Add table-driven cases from B1/B2/B4 plus `FuzzParseSyslogPacket` asserting: no panic, returned message is valid UTF-8, `json.Marshal` of the result round-trips.
- Existing `TestParseNoHostname` asserts that plain text without PRI is accepted as syslog; it encodes the B1 bug and must be changed.

### [ ] T2. Capture conversion
- `NextPacket`'s packet-to-`PacketData` logic (the part that matters) has no tests; capture coverage is 60% from the mock and the invalid-interface test only. Build frames with `gopacket.SerializeLayers` (appendix) for: TCP pure ACK, SYN-ACK, empty UDP, UDP with payload, IPv6, 802.1Q VLAN.

### [ ] T3. App
- Add tests for: source returns EOF (B5), overflow cap (S1), periodic emits multiple reports (S2), golden JSON for the schema, `--no-sample` (S6). Add a test for `main` exit codes via `exec` of the built binary (version, bad flag, unknown interface).

---

## P4 — CI, packaging, supply chain

### [ ] C1. Image tags are mutable and published on every push to `main`
- **Where:** `.github/workflows/ci.yml`, job `publish-docker` (`if: github.ref == 'refs/heads/main' || github.event_name == 'release'`).
- **Problem:** Each push to `main` pushes `latest` **and** the `VERSION` tag (and semver tags derived from it). A version tag like `0.1.0` is overwritten until someone bumps `VERSION`. The README says `latest` "tracks the latest release", which is not true.
- **Fix:** Push `<version>`/semver/`latest` only on release events or when `VERSION` changed; on plain pushes publish `edge` and `sha-<short>`. The `draft-release` job compares `VERSION` with `HEAD~1` only; use `github.event.before` so multi-commit pushes don't miss a bump. Expose the "changed" output and reuse it.

### [ ] C2. Two dependency bots on the same repo
- Both `.github/dependabot.yml` (gomod, weekly) and `renovate.json` (+ `bin/renovate/run.sh`) are active; git history shows PRs from both (for example the `golang.org/x/net` bump). Pick one (Renovate also covers Actions and Docker). In `run.sh` stop using `ghcr.io/renovatebot/renovate:latest`; pin it. Enable `pinDigests` for Actions and Docker base images.

### [ ] C3. Workflow hardening
- Top-level `permissions: contents: write, packages: write` is the default for every job; set top-level `contents: read` and grant per job (several jobs already override).
- Actions are pinned by major tag, not commit SHA. For a security tool, pin by SHA (Renovate can maintain them).
- `build-and-test` commits `coverage.svg` back to `main` via `git-auto-commit-action`, creating bot commits and requiring write access to the default branch (breaks with branch protection). Prefer Codecov, a gist badge, or generating the badge at release time.

### [ ] C4. Missing checks
- Add to CI: `golangci-lint` (or `staticcheck`), `govulncheck ./...`, `go mod tidy` + `git diff --exit-code`, `hadolint Dockerfile`, a container scan (Trivy/Grype), SBOM and provenance (`sbom: true`, `provenance: mode=max` on `docker/build-push-action`) and image signing (cosign keyless). The README positions this as parity with `rust_syslog_sniffer`, which has SBOM generation; this repo has no `make sbom`.

### [ ] C5. Dockerfile
- Runtime stage installs `libpcap-dev` (headers and toolchain dependencies); the runtime library package (`libpcap0.8` on bookworm) is enough.
- Runs as root; there is no `USER`. Try `setcap cap_net_raw+ep` on the binary and a non-root user; document `--cap-drop=ALL --cap-add=NET_RAW`.
- `--cap-add=NET_ADMIN` is recommended everywhere, but the code only needs raw capture; NET_ADMIN is probably unnecessary once promiscuous mode is optional (N1). **[verify]** by running with only `NET_RAW`.
- No `.dockerignore` (`COPY . .` sends `.git`, binaries, coverage files); base images referenced by tag only; the sibling Rust image uses Debian Trixie while this one uses Bookworm.

### [ ] C6. README accuracy
- Options list omits `-v/--version` and the `DEBUG=1` env var.
- Prerequisites say `apt install golang`; on Ubuntu 24.04 that installs Go 1.22 while `go.mod` requires 1.25.0 (works only via toolchain auto-download). State the required version.
- "Retains complete syslog payloads … without truncation" conflicts with S1; "high-performance" is unmeasured (R1); Docker tag table is wrong (C1).
- Missing sections: privileges (`sudo` vs `setcap`), limitations (S5), security considerations (S6), JSON schema, exit codes.

### [ ] C7. Dependency health **[verify]**
- `github.com/google/gopacket v1.1.19` is pinned. Check whether the upstream is still maintained and whether the `github.com/gopacket/gopacket` fork is the better dependency; run `govulncheck`. `golang.org/x/net` is only an indirect requirement (bumped by Dependabot).

### [ ] N1. Promiscuous mode is hard-coded
- `pcap.OpenLive(intf, defaultSnapLen, true, readTimeout)`. Add `--promisc` (default off: the typical use is a collector sniffing its own traffic, and promisc widens what's captured). Lower `snaplen` to e.g. 65535 to match UDP's maximum payload.

---

## Suggested order

1. B1, B2, B3, B5 (each small, independently testable)
2. T1/T2 alongside, then B4 + S1 (schema change; bump `VERSION`)
3. S2, S3, S5, S6, S4
4. R2 (offline source), R1, R3–R6
5. C1, C2, C3, C4, C5, C6, C7, N1

## Definition of done

- A non-syslog UDP/TCP payload, a bare TCP ACK, or an empty UDP datagram never appears in output.
- Valid syslog with invalid UTF-8 is counted.
- Memory use is bounded by `max-hosts × (hostname + sample-bytes)` regardless of input.
- Capture failure yields a non-zero exit and a clear error.
- Output is always valid JSON (fuzz-tested); schema documented with a golden test.
- `go test -race ./...` and the new CI checks pass; version tags are immutable.

## Status of the previous review (old commit `884d292`)

| Old item | Now |
|---|---|
| JSON "un-escape" hack corrupting output | **Fixed** (`SetEscapeHTML(false)` encoder) |
| Closed channel → nil-pointer panic | **Fixed**, but see B5 (now silent) |
| Regex compiled per packet | **Fixed** (package-level), but detection regressed (B1) |
| `OpenLive` timeout of 1000 ns | **Fixed** (250 ms) |
| No signal handling | **Fixed** (`signal.NotifyContext`) |
| `panic` on setup errors | **Fixed** (errors, exit 1) |
| Silent empty output | **Fixed** for non-periodic (prints empty `hosts`) |
| Global mutable state, single file | **Fixed** (packages, mutex-guarded tracker) |
| Missing tests/CI/Docker/multi-arch | **Fixed** (unit tests, e2e scripts, multi-arch image, release flow) |
| BPF `port N` both directions | **Still open** (B3) |
| Unbounded memory | **Still open, worse** (S1: key is now sender-controlled) |
| TCP per-segment / TLS | **Still open** (S5) |
| Promiscuous hard-coded | **Still open** (N1) |
| JSON schema naming | **Changed** (new schema; see B4 for what's lost) |

---

## Appendix: synthetic-frame probe (reuse for T2)

```go
package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/syslog"
)

func frame(t *testing.T, l4 gopacket.SerializableLayer, payload []byte, proto layers.IPProtocol) gopacket.Packet {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstMAC: net.HardwareAddr{0, 0, 0, 0, 0, 0}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: proto, SrcIP: net.IP{127, 0, 0, 1}, DstIP: net.IP{127, 0, 0, 1}}
	switch v := l4.(type) {
	case *layers.TCP:
		v.SetNetworkLayerForChecksum(ip)
	case *layers.UDP:
		v.SetNetworkLayerForChecksum(ip)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, l4, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// Feed a packet through the same conversion the live source uses.
func run(t *testing.T, name string, pkt gopacket.Packet) {
	ch := make(chan gopacket.Packet, 1)
	ch <- pkt
	p := &PcapPacketSource{packets: ch} // in-package test: handle is nil
	pd, _ := p.NextPacket()
	if pd == nil {
		t.Logf("%-28s -> nil", name)
		return
	}
	if sp := syslog.ParseSyslogPacket(pd.Data); sp == nil {
		t.Logf("%-28s -> rejected", name)
	} else {
		t.Logf("%-28s -> COUNTED host=%q msg=%q", name, sp.Hostname, sp.Message)
	}
}
```

Probe results at `38f7b1a` (expected-after-fix in the right column):

| Input | Today | Should be |
|---|---|---|
| UDP `GET / HTTP/1.1\r\n` | counted | ignored (`not_syslog`) |
| UDP `<999>Oct 11 22:14:15 evil x: y` | counted, host `evil` | ignored (PRI > 191) |
| UDP `<165>1 … - app …` (NILVALUE host) | counted, host `-` | counted, host from source IP |
| UDP `<13>2026-11-07T12:00:00+01:00 myhost app: msg` | counted, host `""` → IP | counted, host `myhost` |
| UDP `<13>Oct 11 22:14:15 h app: caf\xc3` | **dropped** | counted, sample sanitized |
| UDP with ESC (`\x1b[2J`) in body | counted, JSON-escaped | same, plus escaped in debug output |
| TCP pure ACK (no payload) | rejected by luck (0.65% counted) | skipped (no payload) |
| Empty UDP datagram | rejected by luck | skipped (no payload) |
