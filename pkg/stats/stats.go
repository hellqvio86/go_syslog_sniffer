package stats

import (
	"sync"
)

// IgnoredCounters tracks counters for packets that were seen and ignored.
type IgnoredCounters struct {
	NoPayload        uint64 `json:"no_payload,omitempty"`
	NotSyslog        uint64 `json:"not_syslog,omitempty"`
	NonUTF8Sanitized uint64 `json:"non_utf8_sanitized,omitempty"`
}

// HostStats contains the packet count, IP, claimed hostname, sample message, and security flags.
type HostStats struct {
	Count           uint64 `json:"count"`
	SrcIP           string `json:"src_ip"`
	Hostname        string `json:"hostname,omitempty"`
	Sample          string `json:"sample,omitempty"`
	SampleTruncated bool   `json:"sample_truncated,omitempty"`
	TLSSuspected    bool   `json:"tls_suspected,omitempty"`
}

// JsonSummary represents the serialized JSON report.
type JsonSummary struct {
	IntervalSeconds uint64               `json:"interval_seconds"`
	Hosts           map[string]HostStats `json:"hosts"`
	OverflowEvents  uint64               `json:"overflow_events,omitempty"`
	Ignored         IgnoredCounters      `json:"ignored,omitempty"`
}

// StatsTracker tracks packet counts and samples thread-safely.
type StatsTracker struct {
	mu             sync.RWMutex
	stats          map[string]*HostStats
	maxHosts       int
	sampleBytes    int
	overflowEvents uint64
	ignored        IgnoredCounters
}

// NewStatsTracker creates a StatsTracker with default limits (10000 max hosts, 2048 sample bytes).
func NewStatsTracker() *StatsTracker {
	return NewStatsTrackerWithLimits(10000, 2048)
}

// NewStatsTrackerWithLimits creates a StatsTracker with explicit bounds on tracked hosts and sample size.
func NewStatsTrackerWithLimits(maxHosts int, sampleBytes int) *StatsTracker {
	if maxHosts <= 0 {
		maxHosts = 10000
	}
	if sampleBytes <= 0 {
		sampleBytes = 2048
	}
	return &StatsTracker{
		stats:       make(map[string]*HostStats),
		maxHosts:    maxHosts,
		sampleBytes: sampleBytes,
	}
}

// AddEntry records a packet for a given source IP and claimed hostname.
// Entries are keyed by source IP so that claimed hostnames cannot forge or merge keys.
func (st *StatsTracker) AddEntry(srcIP string, hostname string, message string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	key := srcIP
	if key == "" {
		if hostname != "" {
			key = hostname
		} else {
			key = "unknown"
		}
	}

	if entry, exists := st.stats[key]; exists {
		entry.Count++
		if entry.Hostname == "" && hostname != "" {
			entry.Hostname = hostname
		}
		return
	}

	if len(st.stats) >= st.maxHosts {
		st.overflowEvents++
		return
	}

	sample := message
	truncated := false
	if len(sample) > st.sampleBytes {
		sample = sample[:st.sampleBytes]
		truncated = true
	}

	st.stats[key] = &HostStats{
		Count:           1,
		SrcIP:           srcIP,
		Hostname:        hostname,
		Sample:          sample,
		SampleTruncated: truncated,
	}
}

// RecordIgnoredNoPayload records a packet frame that contained no application payload.
func (st *StatsTracker) RecordIgnoredNoPayload() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ignored.NoPayload++
}

// RecordIgnoredNotSyslog records a payload that was not recognized as syslog.
func (st *StatsTracker) RecordIgnoredNotSyslog() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ignored.NotSyslog++
}

// RecordNonUTF8Sanitized records an event where non-UTF8 bytes were sanitized to U+FFFD.
func (st *StatsTracker) RecordNonUTF8Sanitized() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ignored.NonUTF8Sanitized++
}

// RecordTLS marks that TLS handshake data (e.g. ClientHello) was detected from the given source IP.
func (st *StatsTracker) RecordTLS(srcIP string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	key := srcIP
	if key == "" {
		key = "unknown"
	}
	if entry, exists := st.stats[key]; exists {
		entry.TLSSuspected = true
	} else if len(st.stats) < st.maxHosts {
		st.stats[key] = &HostStats{
			SrcIP:        srcIP,
			TLSSuspected: true,
		}
	}
}

// IsEmpty reports whether any hosts have been tracked.
func (st *StatsTracker) IsEmpty() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.stats) == 0
}

// Clear resets all tracked stats and overflow counters.
func (st *StatsTracker) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.stats = make(map[string]*HostStats)
	st.overflowEvents = 0
	st.ignored = IgnoredCounters{}
}

// GetSummary returns a snapshot of the current stats.
func (st *StatsTracker) GetSummary(intervalSeconds uint64) JsonSummary {
	st.mu.RLock()
	defer st.mu.RUnlock()

	hostsCopy := make(map[string]HostStats, len(st.stats))
	for k, v := range st.stats {
		hostsCopy[k] = HostStats{
			Count:           v.Count,
			SrcIP:           v.SrcIP,
			Hostname:        v.Hostname,
			Sample:          v.Sample,
			SampleTruncated: v.SampleTruncated,
			TLSSuspected:    v.TLSSuspected,
		}
	}

	return JsonSummary{
		IntervalSeconds: intervalSeconds,
		Hosts:           hostsCopy,
		OverflowEvents:  st.overflowEvents,
		Ignored:         st.ignored,
	}
}
