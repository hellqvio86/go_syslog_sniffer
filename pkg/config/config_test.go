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
