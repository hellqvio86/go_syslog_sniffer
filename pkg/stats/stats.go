package stats

import (
	"sync"
)

// HostStats contains the packet count and the first sample message for a host.
type HostStats struct {
	Count  uint64 `json:"count"`
	Sample string `json:"sample"`
}

// JsonSummary represents the serialized JSON report.
type JsonSummary struct {
	IntervalSeconds uint64               `json:"interval_seconds"`
	Hosts           map[string]HostStats `json:"hosts"`
}

// StatsTracker tracks packet counts and samples per hostname thread-safely.
type StatsTracker struct {
	mu    sync.RWMutex
	stats map[string]*HostStats
}

// NewStatsTracker creates an empty StatsTracker.
func NewStatsTracker() *StatsTracker {
	return &StatsTracker{
		stats: make(map[string]*HostStats),
	}
}

// AddEntry records a packet for a given hostname.
// If the host is seen for the first time, its message becomes the sample.
func (st *StatsTracker) AddEntry(hostname string, message string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if entry, exists := st.stats[hostname]; exists {
		entry.Count++
	} else {
		st.stats[hostname] = &HostStats{
			Count:  1,
			Sample: message,
		}
	}
}

// IsEmpty reports whether any hosts have been tracked.
func (st *StatsTracker) IsEmpty() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.stats) == 0
}

// Clear resets all tracked stats.
func (st *StatsTracker) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.stats = make(map[string]*HostStats)
}

// GetSummary returns a snapshot of the current stats.
func (st *StatsTracker) GetSummary(intervalSeconds uint64) JsonSummary {
	st.mu.RLock()
	defer st.mu.RUnlock()

	hostsCopy := make(map[string]HostStats, len(st.stats))
	for k, v := range st.stats {
		hostsCopy[k] = HostStats{
			Count:  v.Count,
			Sample: v.Sample,
		}
	}

	return JsonSummary{
		IntervalSeconds: intervalSeconds,
		Hosts:           hostsCopy,
	}
}
