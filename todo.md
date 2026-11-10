# TODO: go_syslog_sniffer — critical review (v3, against current code)

Repo: hellqvio86/go_syslog_sniffer, `VERSION` 0.2.2, zip commit `445443de20dc1d190fc5100cba2cdad20c8d6306`, module `go 1.26.0`, layout `main.go` + `internal/{app,capture,config,stats,syslog,testutil}`.

This **replaces** the `todo.md` currently in the repo (v2). Every v2 item is ticked and, with the exceptions listed in "Status of v2" at the bottom, really is fixed. The IDs below are new; do not map them to v2 IDs.

## How this was verified (read first)

- **Static review only.** The sandbox had no Go toolchain and no module access, so nothing was compiled, run or probed. Coverage numbers, benchmark numbers and CI status are NOT re-checked.
- **[static]** = follows directly from the code as written; the first step of the task is still to write a failing test that proves it.
- **[verify]** = depends on environment (libpcap version, distro, GitHub settings). Confirm with the given command before changing code.
- Files read: all non-test `.go`, `go.mod`, `Dockerfile`, `Makefile`, `README.md`, `renovate.json`, `.github/workflows/*`, `.githooks/pre-commit`, test file names/greps. Test bodies were only grepped, not audited.

## Instructions for the agent

- Work top-down. One commit per task ID, message prefixed with the ID (e.g. `B1: treat pcap EOF as clean end`).
- Write the failing test first, then fix. Tests must not need root or a live interface: build frames with `gopacket.SerializeLayers`, write fixtures with `pcapgo` into `testdata/`, replay with `NewOfflinePacketSource`.
- Before finishing each task: `gofmt -s -l .` (empty), `go vet ./...`, `go test -race ./...`.
- Keep `-i/-p/-t/-d/-v` and the long flags backward compatible. A JSON schema change must update the README schema block, add/refresh a golden test, and bump `VERSION` **and** `config.Version` together.
- Locate code by function name; line numbers drift.

## Behaviour summary (context)

`main` builds a `PacketSource` (live pcap on `any`/`-i`, or `-r file`), BPF `dst port N`, and calls `app.RunSniffer`. The loop pulls `PacketData{Data, SrcIP, NoPayload}`, drops TLS-looking payloads, splits payloads on `\n`, parses each line with `syslog.Parse` (PRI ≤ 191, optional octet-count prefix, claimed hostname via three regexes) and records into `stats.Tracker`, keyed by source IP, with first-message sample. Output is one JSON document at the end, or one per `--frequency` seconds with `--periodic`.

---

## P0 — correctness

### [x] B1. `-r file.pcap` always exits 1 at end of file **[static]**
- **Where:** `capture.PcapPacketSource.NextPacket` (returns `io.EOF` when the channel closes, for live *and* offline), `app.RunSniffer` (EOF → `captureErr` → returned), `main` (exit 1).
- **Problem:** Reaching the end of a pcap is the normal way a replay finishes, but it is reported as `Error: capture stream closed: EOF` with exit code 1 (the README lists "closed capture stream" under exit 1). All app tests use `ReturnEOFOnExhaust` to simulate a *failure*, so the offline success path has no test; `main_test.go` only covers `-r` with a missing file.
- **Related defects in offline mode:**
  - Interval defaults to 10 s of wall-clock even for `-r`, so a large pcap is silently cut off after 10 s while the report looks complete.
  - `start_time`/`end_time` are wall-clock "now", not packet timestamps, so a replay of yesterday's capture reports today's time and a 1–2 s window.
- **Fix:**
  1. Distinguish the two cases: offline end-of-file → `io.EOF` (clean finish, exit 0); live channel closed → `capture.ErrCaptureClosed` (error, exit 1). Update `testutil.MockPacketSource` so the "failure" tests return `ErrCaptureClosed` and add an "offline-style EOF = success" test.
  2. When `-r` is given and `-t` was not explicitly set, default to unlimited (`0`).
  3. Add `Timestamp time.Time` to `PacketData` (from `pkt.Metadata().Timestamp`); in offline mode derive `start_time`/`end_time`/`interval_seconds` from first/last packet timestamp.
- **Acceptance:** `go test` that replays a fixture pcap (>10 s of packet timestamps, a few hundred packets) through the real `NewOfflinePacketSource` + `RunSniffer` and asserts: nil error, all expected hosts/counts present, report window equals the pcap's time span. CLI test in `main_test.go` asserting exit code 0 for `-r testdata/x.pcap`. A live-closed-channel test still exits 1.

### [x] B2. `interval_seconds` is the nominal value, not the measured one **[static]**
- **Where:** `app.RunSniffer` final-report block (`interval = cfg.Interval` when not periodic).
- **Problem:** Ctrl-C after 3 s of a `-t 10` run still reports `interval_seconds: 10`; `-t 0` (unlimited) reports `interval_seconds: 0`. Anyone computing msgs/s from `count / interval_seconds` gets wrong or divide-by-zero results. `start_time`/`end_time` are right, so the output contradicts itself.
- **Fix:** Always report measured elapsed (`ceil(end-start)`, min 1) in every mode; keep the field name. (Offline mode: packet-timestamp span, see B1.)
- **Acceptance:** test with a cancelled context after ~100 ms and `Interval=10` → `interval_seconds` ≤ 1; test `Interval=0` → ≥ 1; periodic windows already use measured values, keep them tested.

### [x] B3. Periodic mode: counters leak across windows and are lost at shutdown **[static]**
- **Where:** `app.RunSniffer` periodic block and final-report condition (`!cfg.Periodic || !statsTracker.IsEmpty()`); `stats.Tracker.IsEmpty` (looks at hosts only).
- **Problem:**
  - A window with only ignored traffic (non-syslog, no-payload, TLS-less garbage) has no hosts, so `IsEmpty()` is true: no report, no `SnapshotAndReset`, but `lastReportTime = now` still advances. The `ignored` counters (and `overflow_events`) from that window are then added to the *next* non-empty report whose `start_time` is later. Wrong attribution.
  - The final report is skipped in periodic mode if the last window has ignored-only traffic, so those counts vanish.
  - Quiet windows produce no output at all, so a consumer cannot tell "no syslog arrived" from "sniffer died".
- **Fix:** Always `SnapshotAndReset` at each window boundary. Emit if hosts non-empty **or** any ignored/overflow counter non-zero; add `--emit-empty` (default false) to emit heartbeat reports. Define `IsEmpty` as "nothing at all to report" or replace it with `HasData()`.
- **Acceptance:** tests with a fake clock/mock source: (a) ignored-only window then a host window → second report's `ignored` contains only its own counts; (b) ignored-only final window is still emitted; (c) `--emit-empty` emits `hosts: {}` every window.

### [x] B4. The "strictly bounded memory" claim is false: samples and hostnames pin whole messages **[static]**
- **Where:** `stats.Tracker.formatSample` (`message[:st.sampleBytes]`), `syslog.cleanHostname` (returns a substring of the regex match), `syslog.Parse` (`strings.ToValidUTF8(string(payloadBytes), …)` returns the same string when already valid).
- **Problem:** In Go a substring shares the backing array of its parent. Each host's stored `Sample` (≤ 2048 bytes) and `Hostname` (≤ 255) keep the **entire original message** alive (up to ~64 KB for UDP, more for TCP). Worst case is `max-hosts × message size` (10 000 × 64 KB ≈ 640 MB), not `max-hosts × sample-bytes` (≈ 20 MB). The README "Resource Exhaustion Bounds" paragraph and v2's definition of done both assert the smaller bound.
- **Fix:** `strings.Clone` the sample and hostname before storing. Better: let `Parse` work on `[]byte`, and only materialise strings for (a) the 255-byte hostname and (b) the sample when a **new** host entry is created, instead of converting the whole payload to a string for every packet (that is also the main per-packet allocation; see D3).
- **Acceptance:** a test that inserts N=2000 distinct IPs, each with a 64 KB message, calls `runtime.GC()`, and asserts `HeapAlloc` growth is under ~`N × (sampleBytes + 1 KB)`. It must fail before the fix. Update README wording only after the test passes.

### [x] B5. `--debug` bypasses `--no-sample` / `--redact-sample` **[static]**
- **Where:** `app.RunSniffer` debug line `Captured from %s (claimed=%s): %q`.
- **Problem:** The README's "Sensitive Data & Sample Suppression" promises that samples can be omitted or redacted, but debug mode prints every full message to stderr regardless, and `DEBUG=1` in the environment enables it silently. For a security tool this is the one place secrets and PII leak.
- **Fix:** Debug logging honours the same options: with `--no-sample` or `--redact-sample` print only length, source IP and claimed hostname; otherwise truncate to `--sample-bytes`. Mention in README that `--debug` is not for production.
- **Acceptance:** test that a message containing a token string never appears in stderr when `RedactSample`/`NoSample` is set with `Debug` on.

---

## P1 — protocol handling and silent undercounting

### [x] F1. Message framing ignores the transport; octet-counting is only half-implemented **[static]**
- **Where:** `syslog.SplitMessages` (newline split for everything), `syslog.Parse` (`headerPrefixRegex` accepts `(\d+)\s+` but never uses the number), `capture.PacketData` (no transport info).
- **Problem:**
  - **UDP:** RFC 5426 says one datagram is one message. Splitting on `\n` turns every multi-line message (stack traces, some appliance logs) into one valid message plus N `not_syslog` ignores. `count` is right by accident, `ignored.not_syslog` is inflated.
  - **TCP, octet-counted (RFC 6587):** frames like `59 <34>…62 <13>…` in one segment are not newline-separated, so they count as **one** message; the length is never validated or used to find the boundary.
  - **TCP, newline-framed:** works, but retransmitted segments and messages split across segments are counted/ignored per segment (no reassembly).
  - Inconsistency: the no-newline path returns the payload untouched, the multi-line path `TrimSpace`s each line (trailing `\r`, `\0` handling differs).
- **Fix:** Add `Transport` (`udp|tcp`) to `PacketData` from the decoded layers. UDP: no splitting, trim only trailing `\r\n\x00`. TCP: if payload matches `^\d+ <`, parse octet-counted frames using the length (reject frames whose length overruns the segment and count them as `not_syslog`); else split on LF. Keep the documented "no TCP reassembly" limitation; optionally add `gopacket/tcpassembly` later behind a flag.
- **Acceptance:** table tests for: UDP multi-line datagram (1 message, 0 ignored), TCP two octet-counted frames in one segment (2 messages), octet length longer than payload (ignored), TCP LF-framed three messages (3), UDP with trailing `\x00`.

### [x] F2. Decode failures and unsupported link types look like `no_payload` **[static]** / default `any` on newer libpcap **[verify]**
- **Where:** `capture.PcapPacketSource.NextPacket` (never looks at `pkt.ErrorLayer()`), constructors (never validate `handle.LinkType()`), `go.mod` (`github.com/google/gopacket v1.1.19`).
- **Problem:** A packet that fails to decode, or a link type gopacket cannot decode, ends up with no IP layer and is counted as `ignored.no_payload`. The tool then prints a "successful" report with zero hosts. The default interface is `any`; on Linux that is a cooked capture, and newer libpcap versions can hand out `DLT_LINUX_SLL2`. v1.1.19 of the original gopacket has no SLL2 decoder as far as I know.
- **Verify:** on each target distro run `tcpdump --list-data-link-types -i any` and check which type the default is, and whether `go run . -i any -t 5` sees traffic you generate with `logger -n 127.0.0.1 -P 514 test`.
- **Fix:**
  1. Add `ignored.decode_errors`; count when `pkt.ErrorLayer() != nil`.
  2. After `Activate`/`OpenOffline`, check `handle.LinkType()` against the supported set; if unsupported, either `SetDatalink` to a supported one or fail with a message naming the link type and suggesting `-i <real interface>`.
  3. v2 item C7 ("evaluate the `github.com/gopacket/gopacket` fork") is ticked but `go.mod` is unchanged and no decision is recorded. Either migrate or record why not in the README.
- **Acceptance:** unit test feeding a truncated IPv4 frame → `decode_errors == 1`, `no_payload == 0`; test that an unsupported link type produces a clear error (use a pcap fixture with that link type).

### [x] F3. `capture_stats` is cumulative but the host counts are per window **[verify]**
- **Where:** `app.RunSniffer` (`source.Stats()` → `SetCaptureStats` at each periodic report).
- **Problem:** `pcap_stats` counters are totals since the handle was opened. In periodic mode each report shows the running total of `received/dropped` next to host counts that were reset, so the two cannot be compared and drops cannot be attributed to a window.
- **Verify:** run `--periodic --frequency 2` against steady traffic and watch `received` grow monotonically while `count` stays flat.
- **Fix:** keep the previous snapshot in `RunSniffer` and report deltas per window (clamp at 0), plus a documented `capture_stats_total` only in the final report if wanted.
- **Acceptance:** mock source whose `Stats()` returns increasing totals → each periodic report contains the delta.

### [x] F4. BPF filter may miss VLAN-tagged and extension-header IPv6 traffic **[verify]**
- **Where:** `capture.BuildBPFFilter`.
- **Problem:** libpcap's `dst port N` does not match 802.1Q-tagged frames when the tag is in-band (typical on SPAN/mirror ports and trunk captures), and does not follow IPv6 extension headers. A discovery tool then silently reports nothing for those senders.
- **Verify:** build a pcap with a tagged UDP/514 frame and check `NewOfflinePacketSource` returns it.
- **Fix:** emit `(dst port N) or (vlan and dst port N)`; document IPv6 extension-header and fragment limitations next to the existing UDP-fragment note. Keep the generated filter covered by a unit test and compile-check it with `pcap.CompileBPFFilter` for Ethernet.

### [x] F5. Multi-port and direction exist in the code but not in the CLI
- **Where:** `main.go` hardcodes `"dst"` and `cfg.Port` is a single `int`; `BuildBPFFilter` already supports `src`/`both` and several ports.
- **Problem:** Real deployments use 514 (UDP+TCP), 601, 6514. Currently they need separate runs, and the multi-port/direction code is untested through the CLI.
- **Fix:** accept `-p 514,6514` (comma list, each 1–65535) and `--direction dst|src|both` (default `dst`); thread through `Config`, both constructors, README.
- **Acceptance:** config tests for lists/invalid entries; filter-string tests; an offline test where only the second port's traffic is present.

---

## P2 — security hardening and robustness

### [x] S1. Stats: sender-controlled fallback key, silent TLS drop, zero-count hosts
- `Tracker.AddEntry` keeps a second map `namedStats` keyed by the *claimed hostname* when `srcIP` is invalid. That reintroduces the sender-controlled key the schema change was meant to remove. It should be unreachable for IP packets: remove `namedStats` and the `AddEntryString` fallback, or key the fallback by a fixed `"unknown"` only.
- `RecordTLS` silently does nothing when `max-hosts` is reached (no `overflow_events`), and creates hosts with `count: 0` and no sample; those hosts make `IsEmpty()` false. Count the overflow and decide/document whether zero-count TLS hosts belong in `hosts`.
- `formatSample` truncates at a byte offset and can split a UTF-8 rune; the JSON encoder then silently substitutes U+FFFD. Truncate at a rune boundary (`utf8.RuneStart`).
- `cleanHostname` truncates >255-byte tokens to a bogus 255-byte hostname; reject instead.
- **Acceptance:** tests for each bullet (overflow counted for TLS at cap; sample never ends mid-rune; 300-byte hostname → empty hostname).

### [x] S2. Relays hide the real senders
- One entry per source IP stores only the first non-empty claimed hostname. Behind an rsyslog/syslog-ng forwarder, a hundred hosts collapse into one entry with one hostname.
- **Fix (optional feature):** add a bounded `claimed_hostnames` list (max N, default 8) plus `claimed_hostnames_total` per entry, so relays are visible without unbounded memory.

### [x] S3. Parser coverage gaps affect common network gear
- RFC 3164 regex only accepts `Mmm dd hh:mm:ss`. It misses `Oct 11 2026 22:14:15`, fractional seconds, Cisco `*`/`.` NTP markers and sequence-number prefixes (`<189>1234: …`); hostname is then silently empty and the host shows only by IP.
- RFC 5424 regex accepts any single digit as VERSION; PRI accepts leading zeros (`<007>`).
- **Fix:** extend regexes (or hand-write a small header scanner on bytes, which also helps D3); only treat the 5424 path as valid when VERSION is `1`.
- **Acceptance:** table-driven cases for each variant; keep both existing fuzz targets green and add a seed corpus entry for each.

### [x] S4. Config silently rewrites bad input
- `--max-hosts <= 0` becomes 10000 and `--sample-bytes <= 0` becomes 2048 with no message (a user passing `0` probably meant "none", which is `--no-sample`). Return an error instead.
- `--no-sample` + `--redact-sample` together: one silently wins. Error or document precedence in `-h`.
- `-r` combined with `-i`/`--promisc` ignores them silently; warn or error.
- `--periodic` with the default `json` format emits concatenated pretty-printed documents. Default to `ndjson` when `--periodic` is set and `--format` was not given.
- **Acceptance:** config tests for each case.

### [x] S5. Signal handling: second Ctrl-C does nothing
- `signal.NotifyContext` keeps swallowing SIGINT until `cancel` runs at exit. If `handle.Close()` blocks (it can wait for the 250 ms read timeout, longer on a stuck interface), the user cannot force-quit.
- **Fix:** after the context is done, call the stop function in a goroutine (`go func(){ <-ctx.Done(); cancel() }()`) so a second signal uses the default action.

---

## P3 — design and code quality

### [x] D1. Remove the "backwards compatibility" aliases from `internal/`
Nothing outside this module can import `internal/`, so these exist only to keep old tests compiling.

| Symbol | non-test uses | test uses |
|---|---|---|
| `syslog.SyslogPacket` | 0 | 0 |
| `syslog.ParseSyslogPacket` | 0 | 6 |
| `stats.JsonSummary` | 0 | 8 |
| `stats.StatsTracker` | 0 | 0 |
| `stats.NewStatsTracker` | 0 | 6 |
| `stats.NewStatsTrackerWithLimits` / `WithOptions` | 0 | 2 / 2 |
| `stats.NewTrackerWithLimits` | only via the alias above | 0 |
| `stats.Tracker.RecordTLSString` | 0 | 0 |
| `capture.NewPcapPacketSourceWithDirection` | 0 | 0 |
| `capture.NewPcapPacketSource` | 0 | 1 |

Migrate the tests to the real names (`Parse`, `JSONSummary`, `NewTracker…`), delete the aliases and wrappers. (Counts are from a grep, re-check after F5, which may change constructor signatures.)

### [x] D2. Deduplicate
- `stats.GetSummary` and `SnapshotAndReset` copy the same maps with the same loops; extract `buildSummaryLocked`. `SnapshotAndReset` does not need to copy at all, since it replaces the maps; hand the old maps over.
- `capture.Stats` → `stats.CaptureStats` conversion is written out three times in `app.go`; add a helper or reuse one type.
- Live and offline constructors repeat the `DecodeOptions`/`PacketSource` setup; extract `newSource(handle, filter)`.

### [x] D3. Performance claims vs reality
- README says "zero-copy packet slicing" and quotes ~1.1–1.4 M packets/s. In the code the payload is copied in `NextPacket`, then converted to a `string` (second copy) in `Parse`, then regex-matched on the full string. The parser benchmark covers only `Parse`, not the stats path.
- **Fix:** do B4's byte-based parse, drop the README wording that no longer matches, add an end-to-end benchmark (`NextPacket` → `Parse` → `AddEntry`), record CPU/Go/libpcap in the README next to the numbers or remove them.
- **[verify]** whether the explicit payload copy is still needed: `gopacket.PacketSource` reads via `ReadPacketData`, which returns a fresh buffer, so `NoCopy` should already be safe. Only drop the copy if a test with aggressive GC and buffer reuse stays green.

### [x] D4. Version in two places
`VERSION` and `config.Version` both say `0.2.2` and nothing checks they agree (`go run`/`go build` without ldflags uses the constant). Add a test that reads `../../VERSION` and compares, or derive from `debug.ReadBuildInfo()`.

---

## P4 — tests

### [x] T1. Offline end-to-end tests
There is no CLI-level test that a valid pcap succeeds (only the missing-file case) and the e2e scripts only run live. Add `testdata/*.pcap` fixtures (UDP 514 5424 + 3164, TCP LF-framed, TCP octet-counted, VLAN-tagged, IPv6, TLS ClientHello on 6514, pure ACK, truncated frame) generated by a small `go run ./internal/testutil/gen` or `go test -run TestGenerateFixtures -update`, plus golden JSON outputs. This also gives B1, B3, F1, F2, F4 their test inputs.

### [x] T2. Fuzz the framing and the stats path
`FuzzParse*` exist for the parser only. Add a fuzz target over `SplitMessages` + `Parse` + `Tracker.AddEntry` + `json.Marshal` asserting: no panic, output valid JSON, sample ≤ `sampleBytes`, hosts ≤ `maxHosts`.

---

## P5 — CI, packaging, supply chain

### [x] C1. Docker e2e does not test the documented privilege model
`tests/e2e_docker.sh` and `e2e_periodic_docker.sh` run with `--cap-add=NET_ADMIN`; the README and Dockerfile say only `NET_RAW` (with `--cap-drop=ALL`). Run the e2e with exactly the README flags (`--cap-drop=ALL --cap-add=NET_RAW`, default non-root user). Add a test that `--promisc` without `NET_ADMIN` fails with a clear message **[verify]** that promiscuous mode really needs `NET_ADMIN`; if so, document it. Also check `setcap` file capabilities still work under `--security-opt no-new-privileges` (they do not); note it in the README if you recommend that option.

### [x] C2. Unpinned tooling in a security pipeline
Actions are SHA-pinned, but `ci.yml` installs `govulncheck@latest`, uses `golangci-lint` `version: latest`, and the Makefile `sbom` target runs `aquasec/trivy:latest`. Pin versions (Renovate custom regex manager can keep them current).

### [x] C3. Docker base image digests **[verify]**
`renovate.json` sets `pinDigests: true` for the `dockerfile` manager, but both `FROM` lines in the Dockerfile are tag-only. Check whether the Renovate PR is open or the manager is not running; pin `golang` and `debian` by digest.

### [x] C4. Orphaned artifact
`coverage.svg` (74.5%) is committed but nothing references it (not in the README, no workflow writes it). Delete it, or wire up a real badge. Also add `coverage.svg` to `.gitignore` if it is ever generated locally again.

### [x] C5. Image signing (optional)
SBOM and `provenance: mode=max` are already enabled on the publish step. Keyless `cosign sign` on the pushed digest is the remaining gap (needs `id-token: write` on that job only).

---

## Suggested order

1. B1, B2, B3 (small, independent, all in `app`/`capture`); T1 fixtures alongside.
2. B4 (+ D3 byte-based parse), B5.
3. F1, F2, F3, F4, F5.
4. S1–S5, then D1, D2, D4.
5. T2, C1–C5.

## Definition of done

- `-r file.pcap` exits 0, reports the capture's own time window, and is not cut by the default interval.
- `interval_seconds` equals the measured window in every mode.
- Periodic reports never carry counters from a previous window, and no counters are dropped at shutdown.
- A regression test proves heap usage is bounded by `max-hosts × (sample-bytes + hostname + overhead)` regardless of message size.
- `--debug` never prints a message that `--no-sample`/`--redact-sample` would suppress.
- UDP datagrams are one message each; TCP octet-counted and LF-framed segments split correctly.
- Decode errors and unsupported link types are reported, never counted as `no_payload`.
- `go test -race ./...`, fuzz seeds, and the updated CI checks pass.

## Status of v2 (verified by reading the code)

| v2 item | State |
|---|---|
| B1 parser accepts non-syslog | Fixed (PRI ≤ 191, no raw-frame fallback) |
| B2 invalid UTF-8 dropped | Fixed (sanitised + counted) |
| B3 BPF both directions | Fixed (`dst`), but see F4/F5 |
| B4 host key | Mostly fixed (IP key); `namedStats` fallback remains, see S1 |
| B5 swallowed capture failure | Fixed for live, **broke offline**, see B1 |
| S1 unbounded memory | **Not actually fixed**, see B4 |
| S2 periodic/interval | Fixed, but see B2/B3 |
| S3 config validation | Fixed (see S4 for silent coercions) |
| S4 capture stats | Present, semantics wrong in periodic mode, see F3 |
| S5 ignored counters/TLS | Present; framing still wrong, see F1 |
| S6 samples | `--no-sample`/`--redact-sample` fixed; debug path leaks, see B5 |
| R1–R6 | Done; "zero-copy" claim inaccurate, see D3; aliases left behind, see D1 |
| T1–T3 | Done for unit level; no offline/CLI success test, see T1 |
| C1 tags, C2 one bot, C3 hardening, C5 Dockerfile, C6 README | Done (see C1–C4 above for leftovers) |
| C4 missing checks | Mostly done; unpinned tools (C2), no signing (C5) |
| C7 gopacket fork evaluation | Ticked, `go.mod` unchanged, no recorded decision; see F2 |
| N1 promisc | Done |
