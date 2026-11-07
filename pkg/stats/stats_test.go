package stats

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestStatsTracker_Basic(t *testing.T) {
	st := NewStatsTracker()
	if !st.IsEmpty() {
		t.Fatal("expected new tracker to be empty")
	}

	st.AddEntry("192.168.1.10", "web-01", "<13>msg1")
	if st.IsEmpty() {
		t.Fatal("expected tracker to not be empty")
	}

	st.AddEntry("192.168.1.10", "web-01", "<13>msg2")

	summary := st.GetSummary(10)
	if summary.IntervalSeconds != 10 {
		t.Errorf("expected interval 10, got %d", summary.IntervalSeconds)
	}
	if len(summary.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(summary.Hosts))
	}

	h1 := summary.Hosts["192.168.1.10"]
	if h1.Count != 2 {
		t.Errorf("expected count 2, got %d", h1.Count)
	}
	if h1.SrcIP != "192.168.1.10" {
		t.Errorf("expected SrcIP '192.168.1.10', got %q", h1.SrcIP)
	}
	if h1.Hostname != "web-01" {
		t.Errorf("expected Hostname 'web-01', got %q", h1.Hostname)
	}
	if h1.Sample != "<13>msg1" {
		t.Errorf("expected sample '<13>msg1', got %q", h1.Sample)
	}

	// Verify JSON serialization round-trip
	b, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}
	var unmarshaled JsonSummary
	if err := json.Unmarshal(b, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal summary: %v", err)
	}
	if unmarshaled.IntervalSeconds != 10 || unmarshaled.Hosts["192.168.1.10"].Count != 2 {
		t.Errorf("unmarshaled mismatch: %+v", unmarshaled)
	}
}

func TestStatsTracker_B4Acceptance(t *testing.T) {
	st := NewStatsTracker()

	// 1. Two IPs claiming the same hostname produce two entries
	st.AddEntry("10.0.0.1", "shared-host", "<13>msg from 10.0.0.1")
	st.AddEntry("10.0.0.2", "shared-host", "<13>msg from 10.0.0.2")

	summary := st.GetSummary(10)
	if len(summary.Hosts) != 2 {
		t.Fatalf("expected 2 entries for two IPs sharing same hostname, got %d", len(summary.Hosts))
	}
	if summary.Hosts["10.0.0.1"].Count != 1 || summary.Hosts["10.0.0.2"].Count != 1 {
		t.Errorf("unexpected counts: %+v", summary.Hosts)
	}

	// 2. One IP varying hostnames produces one entry
	st.AddEntry("10.0.0.1", "different-host", "<13>another msg from 10.0.0.1")
	summary = st.GetSummary(10)
	if len(summary.Hosts) != 2 {
		t.Fatalf("expected still 2 entries after IP varied hostname, got %d", len(summary.Hosts))
	}
	if summary.Hosts["10.0.0.1"].Count != 2 {
		t.Errorf("expected IP 10.0.0.1 count to be 2, got %d", summary.Hosts["10.0.0.1"].Count)
	}
}

func TestStatsTracker_S1Limits(t *testing.T) {
	maxHosts := 5
	sampleBytes := 64
	st := NewStatsTrackerWithLimits(maxHosts, sampleBytes)

	// Feed more than maxHosts distinct IPs
	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		st.AddEntry(ip, "myhost", fmt.Sprintf("message %d", i))
	}

	summary := st.GetSummary(10)
	if len(summary.Hosts) != maxHosts {
		t.Errorf("expected capped hosts count %d, got %d", maxHosts, len(summary.Hosts))
	}
	if summary.OverflowEvents != 5 {
		t.Errorf("expected 5 overflow events, got %d", summary.OverflowEvents)
	}

	// Test sample truncation with large 64KB message
	stBig := NewStatsTrackerWithLimits(10, sampleBytes)
	largeMessage := strings.Repeat("A", 65536)
	stBig.AddEntry("10.1.1.1", "bighost", largeMessage)

	summaryBig := stBig.GetSummary(10)
	hostEntry := summaryBig.Hosts["10.1.1.1"]
	if len(hostEntry.Sample) != sampleBytes {
		t.Errorf("expected sample truncated to %d bytes, got %d", sampleBytes, len(hostEntry.Sample))
	}
	if !hostEntry.SampleTruncated {
		t.Errorf("expected SampleTruncated to be true")
	}
}

func TestStatsTracker_Clear(t *testing.T) {
	st := NewStatsTracker()
	st.AddEntry("10.0.0.1", "host1", "msg1")
	st.Clear()
	if !st.IsEmpty() {
		t.Fatal("expected tracker to be empty after Clear")
	}
	summary := st.GetSummary(5)
	if len(summary.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(summary.Hosts))
	}
	if summary.OverflowEvents != 0 {
		t.Errorf("expected 0 overflow events after clear, got %d", summary.OverflowEvents)
	}
}

func TestStatsTracker_Concurrent(t *testing.T) {
	st := NewStatsTracker()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				st.AddEntry("10.0.0.1", "hostA", "msgA")
				st.AddEntry("10.0.0.2", "hostB", "msgB")
			}
		}()
	}

	wg.Wait()

	summary := st.GetSummary(10)
	if summary.Hosts["10.0.0.1"].Count != 5000 {
		t.Errorf("expected hostA count 5000, got %d", summary.Hosts["10.0.0.1"].Count)
	}
	if summary.Hosts["10.0.0.2"].Count != 5000 {
		t.Errorf("expected hostB count 5000, got %d", summary.Hosts["10.0.0.2"].Count)
	}
}

func TestStatsTracker_S6SampleOptions(t *testing.T) {
	// 1. Test NoSample
	stNoSample := NewStatsTrackerWithOptions(100, 2048, true, false)
	stNoSample.AddEntry("192.168.1.50", "host1", "<13>secret message")
	sumNoSample := stNoSample.GetSummary(10)
	hNoSample := sumNoSample.Hosts["192.168.1.50"]
	if hNoSample.Sample != "" {
		t.Errorf("expected empty sample with noSample=true, got %q", hNoSample.Sample)
	}
	if hNoSample.SampleTruncated {
		t.Errorf("expected sample_truncated to be false with noSample=true")
	}

	bytesNoSample, err := json.Marshal(sumNoSample)
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}
	if strings.Contains(string(bytesNoSample), `"sample"`) {
		t.Errorf("expected JSON to omit 'sample' key, but got: %s", string(bytesNoSample))
	}

	// 2. Test RedactSample
	stRedact := NewStatsTrackerWithOptions(100, 2048, false, true)
	stRedact.AddEntry("192.168.1.50", "host1", "<13>secret message")
	sumRedact := stRedact.GetSummary(10)
	hRedact := sumRedact.Hosts["192.168.1.50"]
	if hRedact.Sample != "[REDACTED]" {
		t.Errorf("expected sample to be '[REDACTED]', got %q", hRedact.Sample)
	}
	if hRedact.SampleTruncated {
		t.Errorf("expected sample_truncated to be false with redactSample=true")
	}

	bytesRedact, err := json.Marshal(sumRedact)
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}
	if !strings.Contains(string(bytesRedact), `"sample":"[REDACTED]"`) {
		t.Errorf("expected JSON to contain redacted sample, got: %s", string(bytesRedact))
	}
}
