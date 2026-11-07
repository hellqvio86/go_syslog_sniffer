package config

import (
	"bytes"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg, err := ParseArgs([]string{}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Interface != "eth0" {
		t.Errorf("expected interface 'eth0', got %q", cfg.Interface)
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

func TestCustomLimitsArgs(t *testing.T) {
	args := []string{"--max-hosts", "500", "--sample-bytes", "1024"}
	cfg, err := ParseArgs(args, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MaxHosts != 500 {
		t.Errorf("expected MaxHosts 500, got %d", cfg.MaxHosts)
	}
	if cfg.SampleBytes != 1024 {
		t.Errorf("expected SampleBytes 1024, got %d", cfg.SampleBytes)
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
