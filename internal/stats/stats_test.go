package stats

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestStatsTracker_Basic(t *testing.T) {
	st := NewTracker()
	if !st.IsEmpty() {
		t.Fatal("expected new tracker to be empty")
	}

	st.AddEntryString("192.168.1.10", "web-01", "<13>msg1")
	if st.IsEmpty() {
		t.Fatal("expected tracker to not be empty")
	}

	st.AddEntryString("192.168.1.10", "web-01", "<13>msg2")

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
	var unmarshaled JSONSummary
	if err := json.Unmarshal(b, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal summary: %v", err)
	}
	if unmarshaled.IntervalSeconds != 10 || unmarshaled.Hosts["192.168.1.10"].Count != 2 {
		t.Errorf("unmarshaled mismatch: %+v", unmarshaled)
	}
}

func TestStatsTracker_B4Acceptance(t *testing.T) {
	st := NewTracker()

	// 1. Two IPs claiming the same hostname produce two entries
	st.AddEntryString("10.0.0.1", "shared-host", "<13>msg from 10.0.0.1")
	st.AddEntryString("10.0.0.2", "shared-host", "<13>msg from 10.0.0.2")

	summary := st.GetSummary(10)
	if len(summary.Hosts) != 2 {
		t.Fatalf("expected 2 entries for two IPs sharing same hostname, got %d", len(summary.Hosts))
	}
	if summary.Hosts["10.0.0.1"].Count != 1 || summary.Hosts["10.0.0.2"].Count != 1 {
		t.Errorf("unexpected counts: %+v", summary.Hosts)
	}

	// 2. One IP varying hostnames produces one entry
	st.AddEntryString("10.0.0.1", "different-host", "<13>another msg from 10.0.0.1")
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
	st := NewTrackerWithOptions(maxHosts, sampleBytes, false, false)

	// Feed more than maxHosts distinct IPs
	for i := 1; i <= 10; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		st.AddEntryString(ip, "myhost", fmt.Sprintf("message %d", i))
	}

	summary := st.GetSummary(10)
	if len(summary.Hosts) != maxHosts {
		t.Errorf("expected capped hosts count %d, got %d", maxHosts, len(summary.Hosts))
	}
	if summary.OverflowEvents != 5 {
		t.Errorf("expected 5 overflow events, got %d", summary.OverflowEvents)
	}

	// Test sample truncation with large 64KB message
	stBig := NewTrackerWithOptions(10, sampleBytes, false, false)
	largeMessage := strings.Repeat("A", 65536)
	stBig.AddEntryString("10.1.1.1", "bighost", largeMessage)

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
	st := NewTracker()
	st.AddEntryString("10.0.0.1", "host1", "msg1")
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
	st := NewTracker()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				st.AddEntryString("10.0.0.1", "hostA", "msgA")
				st.AddEntryString("10.0.0.2", "hostB", "msgB")
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
	stNoSample := NewTrackerWithOptions(100, 2048, true, false)
	stNoSample.AddEntryString("192.168.1.50", "host1", "<13>secret message")
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
	stRedact := NewTrackerWithOptions(100, 2048, false, true)
	stRedact.AddEntryString("192.168.1.50", "host1", "<13>secret message")
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

func TestStatsTracker_S4CaptureStats(t *testing.T) {
	st := NewTracker()
	st.AddEntryString("10.0.0.1", "host1", "<13>test message")

	// Initially no capture stats
	sum1 := st.GetSummary(10)
	if sum1.CaptureStats != nil {
		t.Errorf("expected nil CaptureStats initially, got %+v", sum1.CaptureStats)
	}

	// Set capture stats
	st.SetCaptureStats(&CaptureStats{
		PacketsReceived:  100,
		PacketsDropped:   5,
		PacketsIfDropped: 1,
	})

	sum2 := st.GetSummary(10)
	if sum2.CaptureStats == nil {
		t.Fatalf("expected CaptureStats to be set, got nil")
	}
	if sum2.CaptureStats.PacketsReceived != 100 || sum2.CaptureStats.PacketsDropped != 5 || sum2.CaptureStats.PacketsIfDropped != 1 {
		t.Errorf("unexpected capture stats values: %+v", sum2.CaptureStats)
	}

	// Verify JSON serialization includes capture_stats
	b, err := json.Marshal(sum2)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	if !strings.Contains(string(b), `"capture_stats":{"received":100,"dropped":5,"if_dropped":1}`) {
		t.Errorf("expected capture_stats JSON, got: %s", string(b))
	}

	// Verify Clear resets capture stats
	st.Clear()
	sum3 := st.GetSummary(10)
	if sum3.CaptureStats != nil {
		t.Errorf("expected CaptureStats to be cleared, got %+v", sum3.CaptureStats)
	}
}

func TestStatsTracker_SnapshotAndReset(t *testing.T) {
	st := NewTracker()
	st.AddEntryString("10.0.0.1", "host1", "msg1")
	st.AddEntryString("10.0.0.2", "host2", "msg2")

	snap := st.SnapshotAndReset(5)
	if snap.IntervalSeconds != 5 {
		t.Errorf("expected interval 5, got %d", snap.IntervalSeconds)
	}
	if len(snap.Hosts) != 2 {
		t.Errorf("expected 2 hosts in snapshot, got %d", len(snap.Hosts))
	}
	if !st.IsEmpty() {
		t.Errorf("expected tracker to be empty after SnapshotAndReset")
	}

	// Concurrent writes with periodic SnapshotAndReset
	var totalAdded uint64
	var totalSnapshotted uint64
	var mu sync.Mutex

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		workerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				st.AddEntryString(fmt.Sprintf("10.1.%d.%d", workerID, j), "host", "msg")
				mu.Lock()
				totalAdded++
				mu.Unlock()
			}
		}()
	}

	// Goroutine doing snapshots concurrently
	done := make(chan struct{})
	var snapWg sync.WaitGroup
	snapWg.Add(1)
	go func() {
		defer snapWg.Done()
		for {
			select {
			case <-done:
				return
			default:
				s := st.SnapshotAndReset(1)
				var count uint64
				for _, h := range s.Hosts {
					count += h.Count
				}
				mu.Lock()
				totalSnapshotted += count
				mu.Unlock()
			}
		}
	}()

	wg.Wait()
	close(done)
	snapWg.Wait()

	// Final snapshot
	finalSnap := st.SnapshotAndReset(1)
	for _, h := range finalSnap.Hosts {
		totalSnapshotted += h.Count
	}

	if totalSnapshotted != totalAdded {
		t.Errorf("expected totalSnapshotted (%d) == totalAdded (%d)", totalSnapshotted, totalAdded)
	}
}

func TestTracker_BoundedMemoryHeap(t *testing.T) {
	const (
		n           = 2000
		sampleBytes = 256
		messageSize = 65536 // 64 KB
	)

	// Force initial GC to stabilize baseline
	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	st := NewTrackerWithLimits(n, sampleBytes)

	// Generate 64 KB message pattern
	largePayload := make([]byte, messageSize)
	for i := range largePayload {
		largePayload[i] = 'A' + byte(i%26)
	}
	largeMsg := string(largePayload)

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/250, i%250)
		hostname := fmt.Sprintf("host-%d", i)
		st.AddEntryString(ip, hostname, largeMsg)
	}

	runtime.GC()
	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	var heapGrowth uint64
	if mAfter.HeapAlloc > mBefore.HeapAlloc {
		heapGrowth = mAfter.HeapAlloc - mBefore.HeapAlloc
	}

	// Maximum expected growth: N * (sampleBytes + 1500 bytes overhead)
	// Without strings.Clone, heap retention would be > 120 MB (N * 64KB).
	// With bounded samples, expected growth is < 4 MB.
	maxExpected := uint64(n * (sampleBytes + 1500))
	if heapGrowth > maxExpected {
		t.Errorf("heap growth (%d bytes, %.2f MB) exceeds bound (%d bytes, %.2f MB) - possible message pinning",
			heapGrowth, float64(heapGrowth)/(1024*1024), maxExpected, float64(maxExpected)/(1024*1024))
	}
}

func TestTracker_S1Acceptance(t *testing.T) {
	// 1. RecordTLS at max-hosts counts overflow
	st := NewTrackerWithOptions(1, 2048, false, false)
	ip1 := netip.MustParseAddr("10.0.0.1")
	ip2 := netip.MustParseAddr("10.0.0.2")

	st.RecordTLS(ip1)
	if st.overflowEvents != 0 {
		t.Errorf("expected 0 overflow events for first TLS host, got %d", st.overflowEvents)
	}

	st.RecordTLS(ip2)
	if st.overflowEvents != 1 {
		t.Errorf("expected 1 overflow event for second TLS host at cap, got %d", st.overflowEvents)
	}

	// 2. formatSample never ends mid-rune
	// UTF-8: "hello €" where € is \xe2\x82\xac (3 bytes).
	// Total length = 6 + 3 = 9 bytes.
	// If sampleBytes = 7 or 8, truncating at byte offset would slice mid-rune.
	stRune := NewTrackerWithOptions(10, 7, false, false)
	stRune.AddEntry(ip1, "host", "hello € world")
	sumRune := stRune.GetSummary(1)
	sample := sumRune.Hosts[ip1.String()].Sample
	if sample != "hello " {
		t.Errorf("expected sample to truncate before broken rune to 'hello ', got %q", sample)
	}
}

func TestTracker_S2Relays(t *testing.T) {
	st := NewTrackerWithOptions(10, 2048, false, false)
	relayIP := netip.MustParseAddr("10.10.10.1")

	// 10 distinct hostnames forwarded through single relay IP
	for i := 1; i <= 10; i++ {
		st.AddEntry(relayIP, fmt.Sprintf("origin-host-%02d", i), fmt.Sprintf("msg %d", i))
	}

	sum := st.GetSummary(10)
	h := sum.Hosts[relayIP.String()]
	if h.Count != 10 {
		t.Errorf("expected count 10, got %d", h.Count)
	}
	if h.Hostname != "origin-host-01" {
		t.Errorf("expected primary hostname 'origin-host-01', got %q", h.Hostname)
	}
	if len(h.ClaimedHostnames) != 8 {
		t.Errorf("expected ClaimedHostnames bounded to 8, got %d", len(h.ClaimedHostnames))
	}
	if h.ClaimedHostnamesTotal != 10 {
		t.Errorf("expected ClaimedHostnamesTotal 10, got %d", h.ClaimedHostnamesTotal)
	}
}
