package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hellqvio86/go_syslog_sniffer/internal/config"
)

var testBinaryPath string

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "sniffer-test-*")
	if err != nil {
		panic(err)
	}

	testBinaryPath = filepath.Join(tmpDir, "syslog_sniffer")
	cmd := exec.Command("go", "build", "-o", testBinaryPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(tmpDir)
		panic("failed to build test binary: " + string(out))
	}

	code := m.Run()
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

func runBinary(args ...string) (int, string, string, error) {
	cmd := exec.Command(testBinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return exitCode, stdout.String(), stderr.String(), err
}

func TestCLI_Version(t *testing.T) {
	for _, flag := range []string{"-v", "--version"} {
		t.Run(flag, func(t *testing.T) {
			exitCode, stdout, stderr, _ := runBinary(flag)
			if exitCode != 0 {
				t.Fatalf("expected exit code 0 for %s, got %d (stderr: %s)", flag, exitCode, stderr)
			}
			expected := "syslog_sniffer " + config.Version
			if !strings.Contains(stdout, expected) {
				t.Errorf("expected stdout to contain %q, got: %q", expected, stdout)
			}
		})
	}
}

func TestCLI_Help(t *testing.T) {
	for _, flag := range []string{"-h", "--help"} {
		t.Run(flag, func(t *testing.T) {
			exitCode, stdout, stderr, _ := runBinary(flag)
			if exitCode != 0 {
				t.Fatalf("expected exit code 0 for %s, got %d (stderr: %s)", flag, exitCode, stderr)
			}
			combined := stdout + stderr
			if !strings.Contains(combined, "Usage of syslog_sniffer") && !strings.Contains(combined, "-i") {
				t.Errorf("expected usage info in output, got: %q", combined)
			}
		})
	}
}

func TestCLI_ListInterfaces(t *testing.T) {
	exitCode, stdout, stderr, _ := runBinary("--list-interfaces")
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for --list-interfaces, got %d (stderr: %s)", exitCode, stderr)
	}
	if !strings.Contains(stdout, "Available network interfaces:") {
		t.Errorf("expected stdout to contain 'Available network interfaces:', got: %q", stdout)
	}
}

func TestCLI_InvalidFlag(t *testing.T) {
	exitCode, _, stderr, _ := runBinary("--non-existent-flag-xyz")
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code for invalid flag, got 0")
	}
	if !strings.Contains(stderr, "flag provided but not defined") {
		t.Errorf("expected unknown flag error in stderr, got: %q", stderr)
	}
}

func TestCLI_InvalidPort(t *testing.T) {
	exitCode, _, stderr, _ := runBinary("-p", "99999")
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code for invalid port, got 0")
	}
	if !strings.Contains(stderr, "port must be between 1 and 65535") {
		t.Errorf("expected port range error in stderr, got: %q", stderr)
	}
}

func TestCLI_InvalidInterface(t *testing.T) {
	exitCode, _, stderr, _ := runBinary("-i", "non_existent_device_xyz123")
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code for invalid interface, got 0")
	}
	if !strings.Contains(stderr, "failed to open interface non_existent_device_xyz123") {
		t.Errorf("expected open interface error in stderr, got: %q", stderr)
	}
}

func TestCLI_InvalidPcapFile(t *testing.T) {
	exitCode, _, stderr, _ := runBinary("-r", "non_existent_file_xyz.pcap")
	if exitCode == 0 {
		t.Fatalf("expected non-zero exit code for invalid pcap file, got 0")
	}
	if !strings.Contains(stderr, "Failed to open pcap file") {
		t.Errorf("expected pcap error in stderr, got: %q", stderr)
	}
}
