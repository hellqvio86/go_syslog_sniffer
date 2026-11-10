package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
	"github.com/hellqvio86/go_syslog_sniffer/internal/config"
	"github.com/hellqvio86/go_syslog_sniffer/internal/stats"
	"github.com/hellqvio86/go_syslog_sniffer/internal/syslog"
	"github.com/hellqvio86/go_syslog_sniffer/internal/testutil"
)

func TestRunSniffer_Basic(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		Debug:     false,
	}

	packets := []*capture.PacketData{
		{
			Data:  []byte("<165>1 2026-11-07T12:00:00Z hostA app 1 - - Test message 1"),
			SrcIP: netip.MustParseAddr("10.0.0.1"),
		},
		{
			Data:  []byte("<165>1 2026-11-07T12:00:01Z hostA app 1 - - Test message 2"),
			SrcIP: netip.MustParseAddr("10.0.0.1"),
		},
		{
			Data:  []byte("<13>Oct 11 22:14:15 hostB login: ok"),
			SrcIP: netip.MustParseAddr("10.0.0.2"),
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	ctx := context.Background()
	err := RunSniffer(ctx, cfg, mockSource, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stderr.Len() > 0 {
		t.Errorf("expected no stderr output, got: %s", stderr.String())
	}

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to parse stdout json: %v\nOutput: %s", err, stdout.String())
	}

	if summary.IntervalSeconds < 1 || summary.IntervalSeconds > 2 {
		t.Errorf("expected interval 1 or 2, got %d", summary.IntervalSeconds)
	}
	if len(summary.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(summary.Hosts))
	}

	hostA := summary.Hosts["10.0.0.1"]
	if hostA.Count != 2 {
		t.Errorf("expected hostA count 2, got %d", hostA.Count)
	}
	if hostA.Hostname != "hostA" {
		t.Errorf("expected hostA Hostname 'hostA', got %q", hostA.Hostname)
	}
	if hostA.SrcIP != "10.0.0.1" {
		t.Errorf("expected hostA SrcIP '10.0.0.1', got %q", hostA.SrcIP)
	}
	if !strings.Contains(hostA.Sample, "Test message 1") {
		t.Errorf("expected hostA sample to be first message, got %q", hostA.Sample)
	}

	hostB := summary.Hosts["10.0.0.2"]
	if hostB.Count != 1 {
		t.Errorf("expected hostB count 1, got %d", hostB.Count)
	}
	if hostB.Hostname != "hostB" {
		t.Errorf("expected hostB Hostname 'hostB', got %q", hostB.Hostname)
	}
	if hostB.SrcIP != "10.0.0.2" {
		t.Errorf("expected hostB SrcIP '10.0.0.2', got %q", hostB.SrcIP)
	}
	if !strings.Contains(hostB.Sample, "login: ok") {
		t.Errorf("expected hostB sample, got %q", hostB.Sample)
	}
}

func TestRunSniffer_Debug(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		Debug:     true,
	}

	packets := []*capture.PacketData{
		{
			Data:  []byte("<13>msg"),
			SrcIP: netip.MustParseAddr("192.168.1.10"),
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(stderr.String(), "DEBUG: Port to sniff") {
		t.Errorf("expected debug output in stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "DEBUG: Captured from 192.168.1.10") {
		t.Errorf("expected capture log in stderr, got: %s", stderr.String())
	}
}

func TestRunSniffer_ContextCancel(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  60, // large interval
	}

	packets := []*capture.PacketData{
		{
			Data:  []byte("<13>early exit msg"),
			SrcIP: netip.MustParseAddr("127.0.0.1"),
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after brief delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := RunSniffer(ctx, cfg, mockSource, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to parse stdout json: %v", err)
	}

	if len(summary.Hosts) != 1 {
		t.Errorf("expected 1 host on early exit, got %d", len(summary.Hosts))
	}
}

func TestRunSniffer_ClosedCaptureSource(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  10,
	}

	packets := []*capture.PacketData{
		{
			Data:  []byte("<13>Oct 11 22:14:15 host1 login: ok"),
			SrcIP: netip.MustParseAddr("10.0.0.1"),
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	mockSource.ReturnCaptureClosedOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected non-nil error when live capture stream is closed, got nil")
	}

	if !strings.Contains(stderr.String(), "capture stream closed") {
		t.Errorf("expected capture closed error message on stderr, got: %q", stderr.String())
	}

	// Partial results must still be printed
	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("expected valid JSON partial results, got err: %v\nOutput: %s", err, stdout.String())
	}
	if len(summary.Hosts) != 1 {
		t.Errorf("expected 1 host in partial results, got %d", len(summary.Hosts))
	}
}

func TestRunSniffer_RealOfflinePcapReplay(t *testing.T) {
	pcapPath := filepath.Join("..", "..", "testdata", "valid_syslog.pcap")
	source, err := capture.NewOfflinePacketSource(pcapPath, 514, "dst")
	if err != nil {
		t.Fatalf("failed to open test pcap: %v", err)
	}
	defer source.Close()

	cfg := &config.Config{
		PcapFile: pcapPath,
		Port:     514,
		Interval: 0,
	}

	var stdout, stderr bytes.Buffer
	err = RunSniffer(context.Background(), cfg, source, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected nil error replaying pcap, got: %v", err)
	}

	if stderr.Len() > 0 {
		t.Errorf("expected no error output on stderr, got: %s", stderr.String())
	}

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to parse summary: %v\nOutput: %s", err, stdout.String())
	}

	if len(summary.Hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(summary.Hosts))
	}
	for _, ip := range []string{"192.168.1.10", "192.168.1.11", "192.168.1.12"} {
		host, ok := summary.Hosts[ip]
		if !ok {
			t.Errorf("missing expected host %s", ip)
			continue
		}
		if host.Count != 5 {
			t.Errorf("host %s expected count 5, got %d", ip, host.Count)
		}
	}
	if summary.IntervalSeconds != 14 {
		t.Errorf("expected interval 14s, got %d", summary.IntervalSeconds)
	}
	if summary.StartTime != "2026-11-10T12:00:00Z" {
		t.Errorf("expected start time 2026-11-10T12:00:00Z, got %s", summary.StartTime)
	}
	if summary.EndTime != "2026-11-10T12:00:14Z" {
		t.Errorf("expected end time 2026-11-10T12:00:14Z, got %s", summary.EndTime)
	}
}

func TestRunSniffer_B2_MeasuredInterval(t *testing.T) {
	// 1. Cancelled context after ~100ms with Interval=10 nominal
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  10, // nominal 10s
	}
	mock := testutil.NewMockPacketSource(nil)
	var stdout, stderr bytes.Buffer

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	err := RunSniffer(ctx, cfg, mock, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to parse summary: %v", err)
	}
	if summary.IntervalSeconds > 1 {
		t.Errorf("expected measured interval <= 1s for 100ms run, got %d", summary.IntervalSeconds)
	}

	// 2. Interval=0 (unlimited)
	ctx2, cancel2 := context.WithCancel(context.Background())
	cfg2 := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  0,
	}
	mock2 := testutil.NewMockPacketSource(nil)
	var stdout2, stderr2 bytes.Buffer

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel2()
	}()

	err = RunSniffer(ctx2, cfg2, mock2, &stdout2, &stderr2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var summary2 stats.JSONSummary
	if err := json.Unmarshal(stdout2.Bytes(), &summary2); err != nil {
		t.Fatalf("failed to parse summary: %v", err)
	}
	if summary2.IntervalSeconds < 1 {
		t.Errorf("expected measured interval >= 1s for Interval=0, got %d", summary2.IntervalSeconds)
	}
}

func TestRunSniffer_B3_PeriodicIgnoredCountersAndEmitEmpty(t *testing.T) {
	// (a) and (b): ignored-only window, then valid host window, then ignored-only final window
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Periodic:  true,
		Frequency: 1,
		Format:    "ndjson",
	}

	mock := &steppedMockSource{}
	var stdout safeBuffer
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	go func() {
		// Wait for 3 reports to be emitted
		for {
			time.Sleep(50 * time.Millisecond)
			lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
			if len(lines) >= 3 && lines[0] != "" {
				cancel()
				return
			}
		}
	}()

	err := RunSniffer(ctx, cfg, mock, &stdout, &stderr)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 reports, got %d. Output:\n%s", len(lines), stdout.String())
	}

	var rep1, rep2, rep3 stats.JSONSummary
	_ = json.Unmarshal([]byte(lines[0]), &rep1)
	_ = json.Unmarshal([]byte(lines[1]), &rep2)
	_ = json.Unmarshal([]byte(lines[2]), &rep3)

	// Window 1 should have ignored.no_payload == 1 and 0 hosts
	if rep1.Ignored.NoPayload != 1 || len(rep1.Hosts) != 0 {
		t.Errorf("rep1: expected 1 ignored no_payload and 0 hosts, got %+v", rep1)
	}

	// Window 2 should have 1 host and ignored.no_payload == 0 (no counter leak from Window 1)
	if len(rep2.Hosts) != 1 || rep2.Ignored.NoPayload != 0 {
		t.Errorf("rep2: expected 1 host and 0 ignored no_payload (no leak), got hosts=%d ignored=%+v", len(rep2.Hosts), rep2.Ignored)
	}

	// Window 3 should have 1 ignored no_payload
	if rep3.Ignored.NoPayload != 1 {
		t.Errorf("rep3: expected 1 ignored no_payload, got %+v", rep3)
	}

	// (c) --emit-empty emits empty reports
	cfgEmpty := &config.Config{
		Interface: "lo",
		Port:      514,
		Periodic:  true,
		Frequency: 1,
		EmitEmpty: true,
		Format:    "ndjson",
	}
	var stdoutEmpty, stderrEmpty bytes.Buffer
	ctxEmpty, cancelEmpty := context.WithTimeout(context.Background(), 1100*time.Millisecond)
	defer cancelEmpty()

	mockEmpty := testutil.NewMockPacketSource(nil)
	_ = RunSniffer(ctxEmpty, cfgEmpty, mockEmpty, &stdoutEmpty, &stderrEmpty)

	emptyLines := strings.Split(strings.TrimSpace(stdoutEmpty.String()), "\n")
	if len(emptyLines) == 0 || emptyLines[0] == "" {
		t.Fatalf("expected at least one heartbeat report with --emit-empty, got none")
	}
	var emptyRep stats.JSONSummary
	if err := json.Unmarshal([]byte(emptyLines[0]), &emptyRep); err != nil {
		t.Fatalf("failed to parse empty report: %v", err)
	}
	if len(emptyRep.Hosts) != 0 {
		t.Errorf("expected 0 hosts in empty report, got %d", len(emptyRep.Hosts))
	}
}

type steppedMockSource struct {
	startTime time.Time
	sent1     bool
	sent2     bool
	sent3     bool
}

func (s *steppedMockSource) NextPacket() (*capture.PacketData, error) {
	if s.startTime.IsZero() {
		s.startTime = time.Now()
	}
	elapsed := time.Since(s.startTime)
	if !s.sent1 {
		s.sent1 = true
		return &capture.PacketData{NoPayload: true}, nil
	}
	if elapsed >= 1100*time.Millisecond && !s.sent2 {
		s.sent2 = true
		return &capture.PacketData{
			Data:  []byte("<165>1 2026-11-10T12:00:00Z hostA app 1 - - Test"),
			SrcIP: netip.MustParseAddr("10.0.0.1"),
		}, nil
	}
	if elapsed >= 2100*time.Millisecond && !s.sent3 {
		s.sent3 = true
		return &capture.PacketData{NoPayload: true}, nil
	}
	return nil, nil
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *steppedMockSource) Close() error                   { return nil }
func (s *steppedMockSource) Stats() (*capture.Stats, error) { return nil, nil }

func TestRunSniffer_OfflineEOFSource(t *testing.T) {
	cfg := &config.Config{
		PcapFile: "testdata/valid_syslog.pcap",
		Port:     514,
		Interval: 0,
	}

	packets := []*capture.PacketData{
		{
			Data:      []byte("<13>Oct 11 22:14:15 host1 login: ok"),
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			Timestamp: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
		},
		{
			Data:      []byte("<13>Oct 11 22:14:25 host1 login: ok"),
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			Timestamp: time.Date(2026, 11, 10, 12, 0, 10, 0, time.UTC),
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)
	if err != nil {
		t.Fatalf("expected nil error on offline EOF, got: %v", err)
	}

	if stderr.Len() > 0 {
		t.Errorf("expected no error output on stderr, got: %s", stderr.String())
	}

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("expected valid JSON output, got err: %v\nOutput: %s", err, stdout.String())
	}
	if summary.IntervalSeconds != 10 {
		t.Errorf("expected measured packet timestamp interval 10, got %d", summary.IntervalSeconds)
	}
	if summary.StartTime != "2026-11-10T12:00:00Z" {
		t.Errorf("expected start time 2026-11-10T12:00:00Z, got %s", summary.StartTime)
	}
	if summary.EndTime != "2026-11-10T12:00:10Z" {
		t.Errorf("expected end time 2026-11-10T12:00:10Z, got %s", summary.EndTime)
	}
}

type faultyPacketSource struct {
	callCount int
	err       error
}

func (f *faultyPacketSource) NextPacket() (*capture.PacketData, error) {
	f.callCount++
	return nil, f.err
}

func (f *faultyPacketSource) Close() error {
	return nil
}

func (f *faultyPacketSource) Stats() (*capture.Stats, error) {
	return nil, nil
}

func TestRunSniffer_PersistentErrors(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  10,
	}

	faulty := &faultyPacketSource{
		err: fmt.Errorf("simulated network read failure"),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := RunSniffer(context.Background(), cfg, faulty, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected non-nil error when source returns persistent errors, got nil")
	}

	if !strings.Contains(err.Error(), "exceeded max consecutive capture errors") {
		t.Errorf("expected max consecutive capture errors in err, got: %v", err)
	}

	if faulty.callCount < 10 {
		t.Errorf("expected at least 10 calls before stopping, got %d", faulty.callCount)
	}
}

type pacedPacketSource struct {
	pktCount int
}

func (p *pacedPacketSource) NextPacket() (*capture.PacketData, error) {
	p.pktCount++
	time.Sleep(200 * time.Millisecond)
	return &capture.PacketData{
		Data:  []byte(fmt.Sprintf("<13>Oct 11 22:14:15 host%d app: msg", p.pktCount)),
		SrcIP: netip.MustParseAddr(fmt.Sprintf("192.168.1.%d", p.pktCount%5+1)),
	}, nil
}

func (p *pacedPacketSource) Close() error {
	return nil
}

func (p *pacedPacketSource) Stats() (*capture.Stats, error) {
	return nil, nil
}

func TestRunSniffer_PeriodicMultipleReports(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Periodic:  true,
		Frequency: 1, // 1 second frequency
		Interval:  0, // Unlimited duration
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3300*time.Millisecond)
	defer cancel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	source := &pacedPacketSource{}
	err := RunSniffer(ctx, cfg, source, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that at least 3 reports were emitted
	reportCount := strings.Count(stdout.String(), `"interval_seconds"`)
	if reportCount < 3 {
		t.Errorf("expected at least 3 periodic reports, got %d. Output:\n%s", reportCount, stdout.String())
	}
}

func TestRunSniffer_MultiMessageTCPSegment(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
	}

	// Single TCP segment containing 3 newline-separated syslog messages
	multiPayload := []byte("<13>Oct 11 22:14:15 host1 msg1\n<13>Oct 11 22:14:16 host1 msg2\n<13>Oct 11 22:14:17 host1 msg3\n")
	packets := []*capture.PacketData{
		{
			Data:      multiPayload,
			SrcIP:     netip.MustParseAddr("10.0.0.1"),
			Transport: "tcp",
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_ = RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to unmarshal stdout: %v", err)
	}

	entry, ok := summary.Hosts["10.0.0.1"]
	if !ok {
		t.Fatalf("expected host 10.0.0.1, got: %+v", summary.Hosts)
	}
	if entry.Count != 3 {
		t.Errorf("expected count 3 for multi-message segment, got %d", entry.Count)
	}
}

func TestRunSniffer_F2_DecodeErrors(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
	}

	packets := []*capture.PacketData{
		{
			DecodeError: true,
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout, stderr bytes.Buffer
	err := RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to unmarshal output: %v", err)
	}

	if summary.Ignored.DecodeErrors != 1 {
		t.Errorf("expected decode_errors == 1, got %d", summary.Ignored.DecodeErrors)
	}
	if summary.Ignored.NoPayload != 0 {
		t.Errorf("expected no_payload == 0, got %d", summary.Ignored.NoPayload)
	}
}

func TestRunSniffer_TLSDetected(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      6514,
		Interval:  1,
	}

	// Simulated TLS ClientHello: 0x16 0x03 0x01 ...
	tlsPayload := []byte{0x16, 0x03, 0x01, 0x00, 0x50, 0x01, 0x00, 0x00}
	packets := []*capture.PacketData{
		{
			Data:  tlsPayload,
			SrcIP: netip.MustParseAddr("10.0.0.2"),
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_ = RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to unmarshal stdout: %v", err)
	}

	entry, ok := summary.Hosts["10.0.0.2"]
	if !ok {
		t.Fatalf("expected host 10.0.0.2 in summary, got: %+v", summary.Hosts)
	}
	if !entry.TLSSuspected {
		t.Errorf("expected tls_suspected=true for TLS traffic")
	}
	if summary.Ignored.NotSyslog != 1 {
		t.Errorf("expected ignored.not_syslog=1, got %d", summary.Ignored.NotSyslog)
	}
}

func TestRunSniffer_S6DebugEscaping(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		Debug:     true,
	}

	rawMsgWithESC := "<13>Oct 11 22:14:15 host evil: \x1b[2Jcleared"
	packets := []*capture.PacketData{
		{
			Data:  []byte(rawMsgWithESC),
			SrcIP: netip.MustParseAddr("10.0.0.9"),
		},
	}

	mockSource := testutil.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_ = RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)

	stderrStr := stderr.String()
	// Must contain the %q escaped sequence "\x1b[2Jcleared"
	if !strings.Contains(stderrStr, `\x1b[2Jcleared`) {
		t.Errorf("expected stderr to contain escaped control codes, got: %q", stderrStr)
	}
	// Must not contain the raw unescaped escape byte 0x1b in the debug log
	capturedLine := ""
	for _, line := range strings.Split(stderrStr, "\n") {
		if strings.Contains(line, "Captured from 10.0.0.9") {
			capturedLine = line
			break
		}
	}
	if strings.Contains(capturedLine, "\x1b[2J") {
		t.Errorf("expected captured line to NOT have unescaped ESC byte, got: %q", capturedLine)
	}
}

func TestRunSniffer_S6NoSampleAndRedact(t *testing.T) {
	packets := []*capture.PacketData{
		{
			Data:  []byte("<13>Oct 11 22:14:15 host secret_app: sensitive-token-12345"),
			SrcIP: netip.MustParseAddr("10.0.0.8"),
		},
	}

	// 1. Test NoSample
	cfgNoSample := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		NoSample:  true,
	}
	mock1 := testutil.NewMockPacketSource(packets)
	mock1.ReturnEOFOnExhaust = true
	var stdout1, stderr1 bytes.Buffer
	_ = RunSniffer(context.Background(), cfgNoSample, mock1, &stdout1, &stderr1)

	if strings.Contains(stdout1.String(), "sensitive-token-12345") {
		t.Errorf("expected sensitive sample to be omitted with --no-sample, got: %s", stdout1.String())
	}
	if strings.Contains(stdout1.String(), `"sample"`) {
		t.Errorf("expected sample field to be omitted entirely, got: %s", stdout1.String())
	}

	// 2. Test RedactSample
	cfgRedact := &config.Config{
		Interface:    "lo",
		Port:         514,
		Interval:     1,
		RedactSample: true,
	}
	mock2 := testutil.NewMockPacketSource(packets)
	mock2.ReturnEOFOnExhaust = true
	var stdout2, stderr2 bytes.Buffer
	_ = RunSniffer(context.Background(), cfgRedact, mock2, &stdout2, &stderr2)

	if strings.Contains(stdout2.String(), "sensitive-token-12345") {
		t.Errorf("expected sensitive sample to be redacted with --redact-sample, got: %s", stdout2.String())
	}
	if !strings.Contains(stdout2.String(), `"[REDACTED]"`) {
		t.Errorf("expected '[REDACTED]' in JSON output, got: %s", stdout2.String())
	}
}

func TestRunSniffer_S4CaptureStats(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		Debug:     true,
	}

	packets := []*capture.PacketData{
		{
			Data:  []byte("<13>Oct 11 22:14:15 host app: test message"),
			SrcIP: netip.MustParseAddr("10.0.0.7"),
		},
	}

	mock := testutil.NewMockPacketSource(packets)
	mock.ReturnEOFOnExhaust = true
	mock.MockStats = &capture.Stats{
		PacketsReceived:  250,
		PacketsDropped:   12,
		PacketsIfDropped: 3,
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_ = RunSniffer(context.Background(), cfg, mock, &stdout, &stderr)

	// Check debug stderr output
	stderrStr := stderr.String()
	if !strings.Contains(stderrStr, "DEBUG: Capture stats: received=250 dropped=12 if_dropped=3") {
		t.Errorf("expected capture stats in debug stderr, got: %s", stderrStr)
	}

	// Check JSON stdout output
	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if summary.CaptureStats == nil {
		t.Fatalf("expected capture_stats in JSON output, got nil")
	}
	if summary.CaptureStats.PacketsReceived != 250 || summary.CaptureStats.PacketsDropped != 12 || summary.CaptureStats.PacketsIfDropped != 3 {
		t.Errorf("unexpected capture stats in JSON: %+v", summary.CaptureStats)
	}
}

func TestRunSniffer_F3_PeriodicCaptureStatsDelta(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Periodic:  true,
		Frequency: 1,
		Interval:  2,
		Format:    "ndjson",
		EmitEmpty: true,
	}

	callCount := 0
	mock := &testutil.MockPacketSource{
		StatsFunc: func() (*capture.Stats, error) {
			callCount++
			return &capture.Stats{
				PacketsReceived:  callCount * 100,
				PacketsDropped:   callCount * 10,
				PacketsIfDropped: 0,
			}, nil
		},
	}

	var stdout safeBuffer
	var stderr bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()

	_ = RunSniffer(ctx, cfg, mock, &stdout, &stderr)

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 periodic reports, got %d. Output: %s", len(lines), stdout.String())
	}

	for i, line := range lines {
		var s stats.JSONSummary
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			t.Fatalf("failed to unmarshal line %d: %v", i, err)
		}
		if s.CaptureStats == nil {
			t.Fatalf("line %d: expected capture_stats, got nil", i)
		}
		if s.CaptureStats.PacketsReceived != 100 {
			t.Errorf("line %d: expected delta PacketsReceived 100, got %d", i, s.CaptureStats.PacketsReceived)
		}
		if s.CaptureStats.PacketsDropped != 10 {
			t.Errorf("line %d: expected delta PacketsDropped 10, got %d", i, s.CaptureStats.PacketsDropped)
		}
	}
}

func TestRunSniffer_R5FormatAndTimestamps(t *testing.T) {
	packets := []*capture.PacketData{
		{
			Data:  []byte("<13>Oct 11 22:14:15 host app: msg"),
			SrcIP: netip.MustParseAddr("10.0.0.5"),
		},
	}

	// 1. Test NDJSON format (compact single line)
	cfgNDJSON := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		Format:    "ndjson",
	}
	mock1 := testutil.NewMockPacketSource(packets)
	mock1.ReturnEOFOnExhaust = true
	var stdout1, stderr1 bytes.Buffer
	_ = RunSniffer(context.Background(), cfgNDJSON, mock1, &stdout1, &stderr1)

	outLines := strings.Split(strings.TrimSpace(stdout1.String()), "\n")
	if len(outLines) != 1 {
		t.Errorf("expected exactly 1 line for ndjson output, got %d lines: %s", len(outLines), stdout1.String())
	}

	var sum1 stats.JSONSummary
	if err := json.Unmarshal([]byte(outLines[0]), &sum1); err != nil {
		t.Fatalf("failed to unmarshal ndjson line: %v", err)
	}
	if sum1.StartTime == "" || sum1.EndTime == "" {
		t.Errorf("expected start_time and end_time to be populated, got start=%q end=%q", sum1.StartTime, sum1.EndTime)
	}
	// Verify RFC 3339 timestamp format
	if _, err := time.Parse(time.RFC3339, sum1.StartTime); err != nil {
		t.Errorf("invalid start_time RFC3339 format: %v", err)
	}
	if _, err := time.Parse(time.RFC3339, sum1.EndTime); err != nil {
		t.Errorf("invalid end_time RFC3339 format: %v", err)
	}

	// 2. Test pretty JSON format (multiline)
	cfgJSON := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		Format:    "json",
	}
	mock2 := testutil.NewMockPacketSource(packets)
	mock2.ReturnEOFOnExhaust = true
	var stdout2, stderr2 bytes.Buffer
	_ = RunSniffer(context.Background(), cfgJSON, mock2, &stdout2, &stderr2)

	jsonLines := strings.Split(strings.TrimSpace(stdout2.String()), "\n")
	if len(jsonLines) <= 1 {
		t.Errorf("expected pretty multiline json output, got %d lines: %s", len(jsonLines), stdout2.String())
	}
}

func TestJSONSummary_GoldenSchema(t *testing.T) {
	summary := &stats.JSONSummary{
		StartTime:       "2026-11-07T12:00:00Z",
		EndTime:         "2026-11-07T12:00:10Z",
		IntervalSeconds: 10,
		Hosts: map[string]stats.HostStats{
			"192.168.1.10": {
				Count:           42,
				Sample:          "<165>1 2026-11-07T12:00:00Z web-01 app 1 - - Hello syslog",
				SampleTruncated: false,
				TLSSuspected:    false,
				Hostname:        "web-01",
				SrcIP:           "192.168.1.10",
			},
		},
		OverflowEvents: 5,
		Ignored: stats.IgnoredCounters{
			NoPayload:        3,
			NotSyslog:        2,
			NonUTF8Sanitized: 1,
		},
		CaptureStats: &stats.CaptureStats{
			PacketsReceived:  100,
			PacketsDropped:   2,
			PacketsIfDropped: 1,
		},
	}

	b, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}

	// Verify against golden JSON structure
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("failed to unmarshal JSON into map: %v", err)
	}

	expectedKeys := []string{
		"start_time", "end_time", "interval_seconds", "hosts",
		"overflow_events", "ignored", "capture_stats",
	}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing expected top-level key %q in JSON schema", key)
		}
	}

	hostsMap, ok := raw["hosts"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'hosts' to be a map")
	}
	h1, ok := hostsMap["192.168.1.10"].(map[string]any)
	if !ok {
		t.Fatalf("expected host entry '192.168.1.10' in hosts map")
	}
	expectedHostKeys := []string{"count", "sample", "hostname", "src_ip"}
	for _, k := range expectedHostKeys {
		if _, ok := h1[k]; !ok {
			t.Errorf("missing expected host key %q in host stats", k)
		}
	}

	ignoredMap, ok := raw["ignored"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'ignored' to be a map")
	}
	for _, k := range []string{"no_payload", "not_syslog", "non_utf8_sanitized"} {
		if _, ok := ignoredMap[k]; !ok {
			t.Errorf("missing expected ignored key %q", k)
		}
	}

	capMap, ok := raw["capture_stats"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'capture_stats' to be a map")
	}
	for _, k := range []string{"received", "dropped", "if_dropped"} {
		if _, ok := capMap[k]; !ok {
			t.Errorf("missing expected capture_stats key %q", k)
		}
	}
}

func TestRunSniffer_OverflowCap(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		MaxHosts:  3,
	}

	var packets []*capture.PacketData
	for i := 1; i <= 10; i++ {
		packets = append(packets, &capture.PacketData{
			Data:  []byte(fmt.Sprintf("<13>Oct 11 22:14:15 host%d app: msg", i)),
			SrcIP: netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", i)),
		})
	}

	mock := testutil.NewMockPacketSource(packets)
	mock.ReturnEOFOnExhaust = true

	var stdout, stderr bytes.Buffer
	_ = RunSniffer(context.Background(), cfg, mock, &stdout, &stderr)

	var summary stats.JSONSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(summary.Hosts) != 3 {
		t.Errorf("expected exactly 3 hosts capped by MaxHosts=3, got %d", len(summary.Hosts))
	}
	if summary.OverflowEvents != 7 {
		t.Errorf("expected 7 overflow events, got %d", summary.OverflowEvents)
	}
}

func TestRunSniffer_B5_DebugSampleSuppression(t *testing.T) {
	secretToken := "SUPER_SECRET_PII_PASSWORD_9999"
	packet := &capture.PacketData{
		Data:  []byte(fmt.Sprintf("<13>Oct 11 22:14:15 host1 login: %s", secretToken)),
		SrcIP: netip.MustParseAddr("10.0.0.1"),
	}

	// 1. NoSample with Debug=true
	cfgNoSample := &config.Config{
		Interface: "lo",
		Port:      514,
		Debug:     true,
		NoSample:  true,
		Interval:  1,
	}
	mock1 := testutil.NewMockPacketSource([]*capture.PacketData{packet})
	mock1.ReturnEOFOnExhaust = true
	var stdout1, stderr1 bytes.Buffer
	_ = RunSniffer(context.Background(), cfgNoSample, mock1, &stdout1, &stderr1)

	if strings.Contains(stderr1.String(), secretToken) {
		t.Errorf("stderr leaked secret sample under --no-sample + --debug:\n%s", stderr1.String())
	}
	if strings.Contains(stdout1.String(), secretToken) {
		t.Errorf("stdout leaked secret sample under --no-sample:\n%s", stdout1.String())
	}

	// 2. RedactSample with Debug=true
	cfgRedact := &config.Config{
		Interface:    "lo",
		Port:         514,
		Debug:        true,
		RedactSample: true,
		Interval:     1,
	}
	mock2 := testutil.NewMockPacketSource([]*capture.PacketData{packet})
	mock2.ReturnEOFOnExhaust = true
	var stdout2, stderr2 bytes.Buffer
	_ = RunSniffer(context.Background(), cfgRedact, mock2, &stdout2, &stderr2)

	if strings.Contains(stderr2.String(), secretToken) {
		t.Errorf("stderr leaked secret sample under --redact-sample + --debug:\n%s", stderr2.String())
	}
	if !strings.Contains(stderr2.String(), "[REDACTED]") {
		t.Errorf("expected [REDACTED] in stderr under --redact-sample + --debug, got:\n%s", stderr2.String())
	}
}

func BenchmarkPipeline_NextPacketParseAddEntry(b *testing.B) {
	rawPacket := []byte("<165>1 2026-11-10T12:00:00Z mymachine.example.com app 1234 ID47 - An application log entry")
	srcIP := netip.MustParseAddr("192.168.1.100")
	tracker := stats.NewTrackerWithOptions(10000, 2048, false, false)

	b.ReportAllocs()
	b.SetBytes(int64(len(rawPacket)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		msgs := syslog.SplitMessages(rawPacket, "udp")
		for _, m := range msgs {
			msg, err := syslog.Parse(m)
			if err == nil {
				tracker.AddEntry(srcIP, msg.Hostname, msg.Message)
			}
		}
	}
}
