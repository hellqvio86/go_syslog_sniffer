package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hellqvio86/go_syslog_sniffer/pkg/capture"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/config"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/stats"
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
			SrcIP: "10.0.0.1",
		},
		{
			Data:  []byte("<165>1 2026-11-07T12:00:01Z hostA app 1 - - Test message 2"),
			SrcIP: "10.0.0.1",
		},
		{
			Data:  []byte("<13>Oct 11 22:14:15 hostB login: ok"),
			SrcIP: "10.0.0.2",
		},
	}

	mockSource := capture.NewMockPacketSource(packets)
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

	var summary stats.JsonSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to parse stdout json: %v\nOutput: %s", err, stdout.String())
	}

	if summary.IntervalSeconds != 1 {
		t.Errorf("expected interval 1, got %d", summary.IntervalSeconds)
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
			SrcIP: "192.168.1.10",
		},
	}

	mockSource := capture.NewMockPacketSource(packets)
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
			SrcIP: "127.0.0.1",
		},
	}

	mockSource := capture.NewMockPacketSource(packets)
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

	var summary stats.JsonSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("failed to parse stdout json: %v", err)
	}

	if len(summary.Hosts) != 1 {
		t.Errorf("expected 1 host on early exit, got %d", len(summary.Hosts))
	}
}

func TestRunSniffer_EOFSource(t *testing.T) {
	cfg := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  10,
	}

	packets := []*capture.PacketData{
		{
			Data:  []byte("<13>Oct 11 22:14:15 host1 login: ok"),
			SrcIP: "10.0.0.1",
		},
	}

	mockSource := capture.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected non-nil error when capture stream returns EOF early, got nil")
	}

	if !strings.Contains(stderr.String(), "capture stream closed") {
		t.Errorf("expected capture closed error message on stderr, got: %q", stderr.String())
	}

	// Partial results must still be printed
	var summary stats.JsonSummary
	if err := json.Unmarshal(stdout.Bytes(), &summary); err != nil {
		t.Fatalf("expected valid JSON partial results, got err: %v\nOutput: %s", err, stdout.String())
	}
	if len(summary.Hosts) != 1 {
		t.Errorf("expected 1 host in partial results, got %d", len(summary.Hosts))
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
		SrcIP: fmt.Sprintf("192.168.1.%d", p.pktCount%5+1),
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
			Data:  multiPayload,
			SrcIP: "10.0.0.1",
		},
	}

	mockSource := capture.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_ = RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)

	var summary stats.JsonSummary
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
			SrcIP: "10.0.0.2",
		},
	}

	mockSource := capture.NewMockPacketSource(packets)
	mockSource.ReturnEOFOnExhaust = true

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	_ = RunSniffer(context.Background(), cfg, mockSource, &stdout, &stderr)

	var summary stats.JsonSummary
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
			SrcIP: "10.0.0.9",
		},
	}

	mockSource := capture.NewMockPacketSource(packets)
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
			SrcIP: "10.0.0.8",
		},
	}

	// 1. Test NoSample
	cfgNoSample := &config.Config{
		Interface: "lo",
		Port:      514,
		Interval:  1,
		NoSample:  true,
	}
	mock1 := capture.NewMockPacketSource(packets)
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
	mock2 := capture.NewMockPacketSource(packets)
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
			SrcIP: "10.0.0.7",
		},
	}

	mock := capture.NewMockPacketSource(packets)
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
	var summary stats.JsonSummary
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
