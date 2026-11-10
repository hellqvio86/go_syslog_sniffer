package stats

import (
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// IgnoredCounters tracks counters for packets that were seen and ignored.
type IgnoredCounters struct {
	NoPayload        uint64 `json:"no_payload,omitempty"`
	NotSyslog        uint64 `json:"not_syslog,omitempty"`
	NonUTF8Sanitized uint64 `json:"non_utf8_sanitized,omitempty"`
	DecodeErrors     uint64 `json:"decode_errors,omitempty"`
}

// CaptureStats holds kernel and interface packet capture statistics.
type CaptureStats struct {
	PacketsReceived  int `json:"received"`
	PacketsDropped   int `json:"dropped"`
	PacketsIfDropped int `json:"if_dropped"`
}

// HostStats contains the packet count, IP, claimed hostname, sample message, and security flags.
type HostStats struct {
	Count                 uint64   `json:"count"`
	SrcIP                 string   `json:"src_ip"`
	Hostname              string   `json:"hostname,omitempty"`
	ClaimedHostnames      []string `json:"claimed_hostnames,omitempty"`
	ClaimedHostnamesTotal int      `json:"claimed_hostnames_total,omitempty"`
	Sample                string   `json:"sample,omitempty"`
	SampleTruncated       bool     `json:"sample_truncated,omitempty"`
	TLSSuspected          bool     `json:"tls_suspected,omitempty"`
}

// JSONSummary represents the serialized JSON report.
type JSONSummary struct {
	StartTime       string               `json:"start_time,omitempty"`
	EndTime         string               `json:"end_time,omitempty"`
	IntervalSeconds uint64               `json:"interval_seconds"`
	Hosts           map[string]HostStats `json:"hosts"`
	OverflowEvents  uint64               `json:"overflow_events,omitempty"`
	Ignored         IgnoredCounters      `json:"ignored,omitempty"`
	CaptureStats    *CaptureStats        `json:"capture_stats,omitempty"`
}

// HasData returns true if any host stats, overflow events, or ignored counters are present.
func (s *JSONSummary) HasData() bool {
	return len(s.Hosts) > 0 ||
		s.OverflowEvents > 0 ||
		s.Ignored.NoPayload > 0 ||
		s.Ignored.NotSyslog > 0 ||
		s.Ignored.NonUTF8Sanitized > 0 ||
		s.Ignored.DecodeErrors > 0
}

// Tracker tracks packet counts and samples thread-safely.
type Tracker struct {
	mu             sync.RWMutex
	stats          map[netip.Addr]*HostStats
	namedStats     map[string]*HostStats
	maxHosts       int
	sampleBytes    int
	noSample       bool
	redactSample   bool
	overflowEvents uint64
	ignored        IgnoredCounters
	captureStats   *CaptureStats
}

// NewTracker creates a Tracker with default limits (10000 max hosts, 2048 sample bytes).
func NewTracker() *Tracker {
	return NewTrackerWithOptions(10000, 2048, false, false)
}

// NewTrackerWithLimits creates a Tracker with explicit bounds on tracked hosts and sample size.
func NewTrackerWithLimits(maxHosts int, sampleBytes int) *Tracker {
	return NewTrackerWithOptions(maxHosts, sampleBytes, false, false)
}

// NewTrackerWithOptions creates a Tracker with customizable limits and sample redaction/suppression.
func NewTrackerWithOptions(maxHosts int, sampleBytes int, noSample bool, redactSample bool) *Tracker {
	if maxHosts <= 0 {
		maxHosts = 10000
	}
	if sampleBytes <= 0 {
		sampleBytes = 2048
	}
	return &Tracker{
		stats:        make(map[netip.Addr]*HostStats),
		namedStats:   make(map[string]*HostStats),
		maxHosts:     maxHosts,
		sampleBytes:  sampleBytes,
		noSample:     noSample,
		redactSample: redactSample,
	}
}

func truncateToRune(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}

func (st *Tracker) formatSample(message string) string {
	if st.noSample {
		return ""
	}
	if st.redactSample {
		return "[REDACTED]"
	}
	if len(message) > st.sampleBytes {
		return strings.Clone(truncateToRune(message, st.sampleBytes))
	}
	return strings.Clone(message)
}

func (st *Tracker) isSampleTruncated(message string) bool {
	if st.noSample || st.redactSample {
		return false
	}
	return len(message) > st.sampleBytes
}

// AddEntry records a packet for a given source IP (netip.Addr) and claimed hostname.
func (st *Tracker) AddEntry(srcIP netip.Addr, hostname string, message string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	clonedHostname := strings.Clone(hostname)

	if !srcIP.IsValid() {
		key := "unknown"
		if entry, exists := st.namedStats[key]; exists {
			entry.Count++
			if entry.Hostname == "" && clonedHostname != "" {
				entry.Hostname = clonedHostname
			}
			if clonedHostname != "" {
				entry.ClaimedHostnamesTotal++
				found := false
				for _, h := range entry.ClaimedHostnames {
					if h == clonedHostname {
						found = true
						break
					}
				}
				if !found && len(entry.ClaimedHostnames) < 8 {
					entry.ClaimedHostnames = append(entry.ClaimedHostnames, clonedHostname)
				}
			}
			return
		}
		if len(st.stats)+len(st.namedStats) >= st.maxHosts {
			st.overflowEvents++
			return
		}
		var ch []string
		var chTotal int
		if clonedHostname != "" {
			ch = []string{clonedHostname}
			chTotal = 1
		}
		st.namedStats[key] = &HostStats{
			Count:                 1,
			SrcIP:                 "",
			Hostname:              clonedHostname,
			ClaimedHostnames:      ch,
			ClaimedHostnamesTotal: chTotal,
			Sample:                st.formatSample(message),
			SampleTruncated:       st.isSampleTruncated(message),
		}
		return
	}

	if entry, exists := st.stats[srcIP]; exists {
		entry.Count++
		if entry.Hostname == "" && clonedHostname != "" {
			entry.Hostname = clonedHostname
		}
		if clonedHostname != "" {
			entry.ClaimedHostnamesTotal++
			found := false
			for _, h := range entry.ClaimedHostnames {
				if h == clonedHostname {
					found = true
					break
				}
			}
			if !found && len(entry.ClaimedHostnames) < 8 {
				entry.ClaimedHostnames = append(entry.ClaimedHostnames, clonedHostname)
			}
		}
		return
	}

	if len(st.stats)+len(st.namedStats) >= st.maxHosts {
		st.overflowEvents++
		return
	}

	var ch []string
	var chTotal int
	if clonedHostname != "" {
		ch = []string{clonedHostname}
		chTotal = 1
	}

	st.stats[srcIP] = &HostStats{
		Count:                 1,
		SrcIP:                 srcIP.String(),
		Hostname:              clonedHostname,
		ClaimedHostnames:      ch,
		ClaimedHostnamesTotal: chTotal,
		Sample:                st.formatSample(message),
		SampleTruncated:       st.isSampleTruncated(message),
	}
}

// AddEntryString is a convenience helper for recording by string IP (useful in tests).
func (st *Tracker) AddEntryString(srcIP string, hostname string, message string) {
	addr, err := netip.ParseAddr(srcIP)
	if err != nil {
		st.AddEntry(netip.Addr{}, hostname, message)
		return
	}
	st.AddEntry(addr, hostname, message)
}

// RecordIgnoredNoPayload records a packet frame that contained no application payload.
func (st *Tracker) RecordIgnoredNoPayload() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ignored.NoPayload++
}

// RecordIgnoredNotSyslog records a payload that was not recognized as syslog.
func (st *Tracker) RecordIgnoredNotSyslog() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ignored.NotSyslog++
}

// RecordNonUTF8Sanitized records an event where non-UTF8 bytes were sanitized to U+FFFD.
func (st *Tracker) RecordNonUTF8Sanitized() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ignored.NonUTF8Sanitized++
}

// RecordTLS marks that TLS handshake data (e.g. ClientHello) was detected from the given source IP.
func (st *Tracker) RecordTLS(srcIP netip.Addr) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if !srcIP.IsValid() {
		return
	}
	if entry, exists := st.stats[srcIP]; exists {
		entry.TLSSuspected = true
	} else if len(st.stats)+len(st.namedStats) < st.maxHosts {
		st.stats[srcIP] = &HostStats{
			SrcIP:        srcIP.String(),
			TLSSuspected: true,
		}
	} else {
		st.overflowEvents++
	}
}

// IsEmpty reports whether any hosts have been tracked.
func (st *Tracker) IsEmpty() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.stats) == 0 && len(st.namedStats) == 0
}

// HasData returns true if any host stats, overflow events, or ignored counters are tracked.
func (st *Tracker) HasData() bool {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.stats) > 0 || len(st.namedStats) > 0 ||
		st.overflowEvents > 0 ||
		st.ignored.NoPayload > 0 ||
		st.ignored.NotSyslog > 0 ||
		st.ignored.NonUTF8Sanitized > 0 ||
		st.ignored.DecodeErrors > 0
}

// RecordIgnoredDecodeError records a packet frame that failed link-layer or IP decoding.
func (st *Tracker) RecordIgnoredDecodeError() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.ignored.DecodeErrors++
}

// SetCaptureStats updates the capture statistics reported in summary output.
func (st *Tracker) SetCaptureStats(cs *CaptureStats) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.captureStats = cs
}

// Clear resets all tracked stats and overflow counters.
func (st *Tracker) Clear() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.stats = make(map[netip.Addr]*HostStats)
	st.namedStats = make(map[string]*HostStats)
	st.overflowEvents = 0
	st.ignored = IgnoredCounters{}
	st.captureStats = nil
}

func (st *Tracker) buildSummaryLocked(intervalSeconds uint64, timestamps []time.Time) JSONSummary {
	hostsCopy := make(map[string]HostStats, len(st.stats)+len(st.namedStats))
	for addr, v := range st.stats {
		hostsCopy[addr.String()] = *v
	}
	for k, v := range st.namedStats {
		hostsCopy[k] = *v
	}

	var csCopy *CaptureStats
	if st.captureStats != nil {
		c := *st.captureStats
		csCopy = &c
	}

	var startTime, endTime string
	if len(timestamps) >= 1 && !timestamps[0].IsZero() {
		startTime = timestamps[0].UTC().Format(time.RFC3339)
	}
	if len(timestamps) >= 2 && !timestamps[1].IsZero() {
		endTime = timestamps[1].UTC().Format(time.RFC3339)
	}

	return JSONSummary{
		StartTime:       startTime,
		EndTime:         endTime,
		IntervalSeconds: intervalSeconds,
		Hosts:           hostsCopy,
		OverflowEvents:  st.overflowEvents,
		Ignored:         st.ignored,
		CaptureStats:    csCopy,
	}
}

// SnapshotAndReset atomically returns a snapshot of the current stats and resets the tracked state under a single lock.
func (st *Tracker) SnapshotAndReset(intervalSeconds uint64, timestamps ...time.Time) JSONSummary {
	st.mu.Lock()
	defer st.mu.Unlock()

	summary := st.buildSummaryLocked(intervalSeconds, timestamps)

	st.stats = make(map[netip.Addr]*HostStats)
	st.namedStats = make(map[string]*HostStats)
	st.overflowEvents = 0
	st.ignored = IgnoredCounters{}
	st.captureStats = nil

	return summary
}

// GetSummary returns a snapshot of the current stats with optional start and end timestamps.
func (st *Tracker) GetSummary(intervalSeconds uint64, timestamps ...time.Time) JSONSummary {
	st.mu.RLock()
	defer st.mu.RUnlock()

	return st.buildSummaryLocked(intervalSeconds, timestamps)
}
