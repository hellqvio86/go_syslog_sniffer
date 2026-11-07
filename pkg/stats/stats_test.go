package stats

import (
	"encoding/json"
	"sync"
	"testing"
)

func TestStatsTracker_Basic(t *testing.T) {
	st := NewStatsTracker()
	if !st.IsEmpty() {
		t.Fatal("expected new tracker to be empty")
	}

	st.AddEntry("host1", "msg1")
	if st.IsEmpty() {
		t.Fatal("expected tracker to not be empty")
	}

	st.AddEntry("host1", "msg2")

	summary := st.GetSummary(10)
	if summary.IntervalSeconds != 10 {
		t.Errorf("expected interval 10, got %d", summary.IntervalSeconds)
	}
	if len(summary.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(summary.Hosts))
	}

	h1 := summary.Hosts["host1"]
	if h1.Count != 2 {
		t.Errorf("expected count 2, got %d", h1.Count)
	}
	if h1.Sample != "msg1" {
		t.Errorf("expected sample 'msg1', got %q", h1.Sample)
	}

	// Verify JSON serialization
	b, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("failed to marshal summary: %v", err)
	}
	expectedJSON := `{"interval_seconds":10,"hosts":{"host1":{"count":2,"sample":"msg1"}}}`
	if string(b) != expectedJSON {
		t.Errorf("expected json %s, got %s", expectedJSON, string(b))
	}
}

func TestStatsTracker_Clear(t *testing.T) {
	st := NewStatsTracker()
	st.AddEntry("host1", "msg1")
	st.Clear()
	if !st.IsEmpty() {
		t.Fatal("expected tracker to be empty after Clear")
	}
	summary := st.GetSummary(5)
	if len(summary.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(summary.Hosts))
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
				st.AddEntry("hostA", "msgA")
				st.AddEntry("hostB", "msgB")
			}
		}()
	}

	wg.Wait()

	summary := st.GetSummary(10)
	if summary.Hosts["hostA"].Count != 5000 {
		t.Errorf("expected hostA count 5000, got %d", summary.Hosts["hostA"].Count)
	}
	if summary.Hosts["hostB"].Count != 5000 {
		t.Errorf("expected hostB count 5000, got %d", summary.Hosts["hostB"].Count)
	}
}
