package config

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg, err := ParseArgs([]string{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Interface != "any" {
		t.Errorf("expected interface 'any', got %q", cfg.Interface)
	}
	if cfg.Port != 514 {
		t.Errorf("expected port 514, got %d", cfg.Port)
	}
	if cfg.Interval != 10 {
		t.Errorf("expected interval 10, got %d", cfg.Interval)
	}
	if cfg.Debug {
		t.Errorf("expected debug false, got true")
	}
	if cfg.Periodic {
		t.Errorf("expected periodic false, got true")
	}
	if cfg.Frequency != 5 {
		t.Errorf("expected frequency 5, got %d", cfg.Frequency)
	}
	if cfg.MaxHosts != 10000 {
		t.Errorf("expected MaxHosts 10000, got %d", cfg.MaxHosts)
	}
	if cfg.SampleBytes != 2048 {
		t.Errorf("expected SampleBytes 2048, got %d", cfg.SampleBytes)
	}
}

func TestParseLongArgs(t *testing.T) {
	args := []string{
		"--interface", "lo",
		"--port", "1514",
		"--interval", "25",
		"--debug",
		"--periodic",
		"--frequency", "3",
	}

	cfg, err := ParseArgs(args, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Interface != "lo" {
		t.Errorf("expected interface 'lo', got %q", cfg.Interface)
	}
	if cfg.Port != 1514 {
		t.Errorf("expected port 1514, got %d", cfg.Port)
	}
	if cfg.Interval != 25 {
		t.Errorf("expected interval 25, got %d", cfg.Interval)
	}
	if !cfg.Debug {
		t.Errorf("expected debug true, got false")
	}
	if !cfg.Periodic {
		t.Errorf("expected periodic true, got false")
	}
	if cfg.Frequency != 3 {
		t.Errorf("expected frequency 3, got %d", cfg.Frequency)
	}
}

func TestParseShortArgs(t *testing.T) {
	args := []string{
		"-i", "eth1",
		"-p", "5514",
		"-t", "45",
		"-d",
	}

	cfg, err := ParseArgs(args, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Interface != "eth1" {
		t.Errorf("expected interface 'eth1', got %q", cfg.Interface)
	}
	if cfg.Port != 5514 {
		t.Errorf("expected port 5514, got %d", cfg.Port)
	}
	if cfg.Interval != 45 {
		t.Errorf("expected interval 45, got %d", cfg.Interval)
	}
	if !cfg.Debug {
		t.Errorf("expected debug true, got false")
	}
}

func TestInvalidFrequency(t *testing.T) {
	args := []string{"--frequency", "0"}
	_, err := ParseArgs(args, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for frequency 0, got nil")
	}
}

func TestVersionFlag(t *testing.T) {
	cfg, err := ParseArgs([]string{"--version"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.ShowVersion {
		t.Errorf("expected ShowVersion true, got false")
	}

	cfgShort, err := ParseArgs([]string{"-v"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfgShort.ShowVersion {
		t.Errorf("expected ShowVersion true, got false")
	}
}

func TestS3_PortValidationAndListInterfaces(t *testing.T) {
	// Invalid port < 1
	_, err := ParseArgs([]string{"-p", "0"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for port 0, got nil")
	}

	// Negative port
	_, err = ParseArgs([]string{"-p", "-5"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for negative port -5, got nil")
	}

	// Port > 65535
	_, err = ParseArgs([]string{"--port", "70000"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for port 70000, got nil")
	}

	// Valid port 65535
	cfg, err := ParseArgs([]string{"-p", "65535"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for valid port 65535: %v", err)
	}
	if cfg.Port != 65535 {
		t.Errorf("expected port 65535, got %d", cfg.Port)
	}

	// --list-interfaces flag
	cfgList, err := ParseArgs([]string{"--list-interfaces"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfgList.ListInterfaces {
		t.Errorf("expected ListInterfaces true, got false")
	}
}

func TestS2_IntervalAndPeriodicSemantics(t *testing.T) {
	// 1. Explicit 0 via -t
	cfg, err := ParseArgs([]string{"-t", "0"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interval != 0 {
		t.Errorf("expected interval 0 for -t 0, got %d", cfg.Interval)
	}

	// 2. Explicit 0 via --interval
	cfgLong, err := ParseArgs([]string{"--interval", "0"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgLong.Interval != 0 {
		t.Errorf("expected interval 0 for --interval 0, got %d", cfgLong.Interval)
	}

	// 3. Periodic mode without explicit interval defaults to 0 (unlimited)
	cfgPeriodic, err := ParseArgs([]string{"--periodic"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgPeriodic.Interval != 0 {
		t.Errorf("expected interval 0 (unlimited) for periodic mode without -t, got %d", cfgPeriodic.Interval)
	}

	// 4. Standard mode without explicit interval defaults to 10
	cfgDefault, err := ParseArgs([]string{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgDefault.Interval != 10 {
		t.Errorf("expected default interval 10 for standard mode, got %d", cfgDefault.Interval)
	}

	// 5. Periodic mode with explicit interval preserves requested interval
	cfgPeriodicExplicit, err := ParseArgs([]string{"--periodic", "-t", "30"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgPeriodicExplicit.Interval != 30 {
		t.Errorf("expected interval 30, got %d", cfgPeriodicExplicit.Interval)
	}

	// 6. Huge interval overflowing 1<<31 rejects cleanly
	_, err = ParseArgs([]string{"--interval", "3000000000"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for interval > 1<<31, got nil")
	}

	// 7. Huge frequency overflowing 1<<31 rejects cleanly
	_, err = ParseArgs([]string{"--frequency", "3000000000"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for frequency > 1<<31, got nil")
	}
}

func TestParseSampleFlags(t *testing.T) {
	cfg, err := ParseArgs([]string{"--no-sample", "--redact-sample"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.NoSample {
		t.Errorf("expected NoSample true, got false")
	}
	if !cfg.RedactSample {
		t.Errorf("expected RedactSample true, got false")
	}
}

func TestParseReadFileFlag(t *testing.T) {
	// 1. Short flag -r
	cfgShort, err := ParseArgs([]string{"-r", "capture.pcap"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgShort.PcapFile != "capture.pcap" {
		t.Errorf("expected PcapFile 'capture.pcap', got %q", cfgShort.PcapFile)
	}

	// 2. Long flag --read-file
	cfgLong, err := ParseArgs([]string{"--read-file", "traffic.pcap"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgLong.PcapFile != "traffic.pcap" {
		t.Errorf("expected PcapFile 'traffic.pcap', got %q", cfgLong.PcapFile)
	}
}

func TestParseFormatFlag(t *testing.T) {
	// 1. Default format is json
	cfgDef, err := ParseArgs([]string{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgDef.Format != "json" {
		t.Errorf("expected default format 'json', got %q", cfgDef.Format)
	}

	// 2. Explicit ndjson format
	cfgNd, err := ParseArgs([]string{"--format", "ndjson"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgNd.Format != "ndjson" {
		t.Errorf("expected format 'ndjson', got %q", cfgNd.Format)
	}

	// 3. Invalid format returns error
	_, err = ParseArgs([]string{"--format", "xml"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for invalid format 'xml', got nil")
	}
}

func TestCLIErgonomics_R6(t *testing.T) {
	// 1. Grouped help output from -h
	var helpBuf bytes.Buffer
	_, err := ParseArgs([]string{"-h"}, &helpBuf)
	if !errors.Is(err, flag.ErrHelp) {
		t.Errorf("expected flag.ErrHelp, got %v", err)
	}
	helpStr := helpBuf.String()
	if !strings.Contains(helpStr, "-i, --interface <INTERFACE>") {
		t.Errorf("expected grouped interface flag in help, got:\n%s", helpStr)
	}
	if !strings.Contains(helpStr, "-p, --port <PORT>") {
		t.Errorf("expected grouped port flag in help, got:\n%s", helpStr)
	}
	if !strings.Contains(helpStr, "DEBUG=1") {
		t.Errorf("expected DEBUG=1 environment variable in help, got:\n%s", helpStr)
	}

	// 2. DEBUG=1 environment variable
	t.Setenv("DEBUG", "1")
	cfgEnv, err := ParseArgs([]string{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfgEnv.Debug {
		t.Errorf("expected Debug true from DEBUG=1 env var, got false")
	}

	// 3. Flag overrides default port and interface via short or long
	cfgShort, err := ParseArgs([]string{"-p", "601", "-i", "enp1s0"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfgShort.Port != 601 || cfgShort.Interface != "enp1s0" {
		t.Errorf("unexpected short flag values: port=%d intf=%s", cfgShort.Port, cfgShort.Interface)
	}
}
