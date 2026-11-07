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
