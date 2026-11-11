package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
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

func TestCLI_ValidPcapFile(t *testing.T) {
	pcapPath := filepath.Join("testdata", "valid_syslog.pcap")
	exitCode, stdout, stderr, err := runBinary("-r", pcapPath)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for valid pcap replay, got %d (err: %v, stderr: %s)", exitCode, err, stderr)
	}
	if !strings.Contains(stdout, `"hosts"`) || !strings.Contains(stdout, "192.168.1.10") {
		t.Errorf("expected valid JSON output with hosts, got: %s", stdout)
	}
}

func TestCLI_VlanPcapFile(t *testing.T) {
	pcapPath := filepath.Join("testdata", "vlan_syslog.pcap")
	exitCode, stdout, stderr, err := runBinary("-r", pcapPath)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for vlan pcap, got %d (err: %v, stderr: %s)", exitCode, err, stderr)
	}
	if !strings.Contains(stdout, "192.168.1.50") {
		t.Errorf("expected host 192.168.1.50 in output, got: %s", stdout)
	}
}

func TestCLI_TcpPcapFile(t *testing.T) {
	pcapPath := filepath.Join("testdata", "tcp_syslog.pcap")
	exitCode, stdout, stderr, err := runBinary("-r", pcapPath)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for tcp pcap, got %d (err: %v, stderr: %s)", exitCode, err, stderr)
	}
	if !strings.Contains(stdout, "10.0.0.1") || !strings.Contains(stdout, "10.0.0.2") {
		t.Errorf("expected hosts 10.0.0.1 and 10.0.0.2 in output, got: %s", stdout)
	}
}

func TestCLI_IPv6PcapFile(t *testing.T) {
	pcapPath := filepath.Join("testdata", "ipv6_syslog.pcap")
	exitCode, stdout, stderr, err := runBinary("-r", pcapPath)
	if exitCode != 0 {
		t.Fatalf("expected exit code 0 for ipv6 pcap, got %d (err: %v, stderr: %s)", exitCode, err, stderr)
	}
	if !strings.Contains(stdout, "2001:db8::1") {
		t.Errorf("expected host 2001:db8::1 in output, got: %s", stdout)
	}
}

// recordingSource records whether Close was executed.
type recordingSource struct {
	closed        bool
	nextErr       error
	statsErr      error
	closeErr      error
	returnPackets []*capture.PacketData
}

func (r *recordingSource) NextPacket() (*capture.PacketData, error) {
	if r.nextErr != nil {
		return nil, r.nextErr
	}
	if len(r.returnPackets) > 0 {
		p := r.returnPackets[0]
		r.returnPackets = r.returnPackets[1:]
		return p, nil
	}
	return nil, io.EOF
}

func (r *recordingSource) Stats() (*capture.Stats, error) {
	if r.statsErr != nil {
		return nil, r.statsErr
	}
	return &capture.Stats{}, nil
}

func (r *recordingSource) Close() error {
	r.closed = true
	return r.closeErr
}

func TestRun_LifecycleAndCleanup(t *testing.T) {
	origFactory := packetSourceFactory
	defer func() { packetSourceFactory = origFactory }()

	t.Run("successful run closes packet source and returns 0", func(t *testing.T) {
		rec := &recordingSource{}
		packetSourceFactory = func(cfg *config.Config) (capture.PacketSource, error) {
			return rec, nil
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"-i", "lo", "-t", "1"}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("expected exit code 0, got %d (stderr: %s)", code, stderr.String())
		}
		if !rec.closed {
			t.Errorf("expected Close to have been called on source")
		}
	})

	t.Run("runtime error closes packet source and returns 1", func(t *testing.T) {
		rec := &recordingSource{
			nextErr: capture.ErrCaptureClosed, // triggers RunSniffer fatal error
		}
		packetSourceFactory = func(cfg *config.Config) (capture.PacketSource, error) {
			return rec, nil
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"-i", "lo", "-t", "1"}, &stdout, &stderr)
		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
		if !rec.closed {
			t.Errorf("expected Close to have been called even on fatal runtime error")
		}
		if !strings.Contains(stderr.String(), "Error: capture stream closed") {
			t.Errorf("expected error message on stderr, got: %q", stderr.String())
		}
	})

	t.Run("invalid arguments returns 1 without opening packet source", func(t *testing.T) {
		called := false
		packetSourceFactory = func(cfg *config.Config) (capture.PacketSource, error) {
			called = true
			return &recordingSource{}, nil
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"--invalid-flag-123"}, &stdout, &stderr)
		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
		if called {
			t.Errorf("packet source should not be created for invalid CLI arguments")
		}
	})

	t.Run("source creation failure returns 1", func(t *testing.T) {
		packetSourceFactory = func(cfg *config.Config) (capture.PacketSource, error) {
			return nil, errors.New("simulated setup failure")
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"-i", "lo"}, &stdout, &stderr)
		if code != 1 {
			t.Errorf("expected exit code 1, got %d", code)
		}
		if !strings.Contains(stderr.String(), "Error: Failed to setup capture") {
			t.Errorf("expected error message on stderr, got: %q", stderr.String())
		}
	})
}
