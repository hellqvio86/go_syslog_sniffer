package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
	"github.com/hellqvio86/go_syslog_sniffer/internal/config"
	"github.com/hellqvio86/go_syslog_sniffer/internal/stats"
	"github.com/hellqvio86/go_syslog_sniffer/internal/syslog"
)

const (
	maxConsecutiveErrors    = 10
	consecutiveErrorBackoff = 2 * time.Millisecond
)

// RunSniffer executes the packet capture loop using the provided configuration and packet source.
// Output JSON is written to stdout; debug diagnostics (if enabled) are written to stderr.
func RunSniffer(
	ctx context.Context,
	cfg *config.Config,
	source capture.PacketSource,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if cfg.Debug {
		debugLog(stderr, "DEBUG: Port to sniff: %d\n", cfg.Port)
		debugLog(stderr, "DEBUG: Interface to sniff: %s\n", cfg.Interface)
		debugLog(stderr, "DEBUG: Interval: %d seconds\n", cfg.Interval)
		debugLog(stderr, "DEBUG: Starting capture loop\n")
	}

	statsTracker := stats.NewTrackerWithOptions(cfg.MaxHosts, cfg.SampleBytes, cfg.NoSample, cfg.RedactSample)
	startTime := time.Now()
	lastReportTime := startTime
	duration := time.Duration(cfg.Interval) * time.Second

	var (
		consecutiveErrors int
		captureErr        error
		firstPacketTime   time.Time
		lastPacketTime    time.Time
		lastCaptureStats  *capture.Stats
	)

	for ctx.Err() == nil {
		// Check duration timeout if finite interval requested
		if cfg.Interval > 0 && time.Since(startTime) >= duration {
			break
		}

		// Handle periodic output
		now := time.Now()
		if cfg.Periodic && now.Sub(lastReportTime) >= time.Duration(cfg.Frequency)*time.Second {
			elapsed := uint64(math.Ceil(now.Sub(lastReportTime).Seconds()))
			if elapsed == 0 {
				elapsed = 1
			}
			if cs, err := source.Stats(); err == nil && cs != nil {
				deltaStats, nextStats := computeCaptureStatsDelta(cs, lastCaptureStats)
				statsTracker.SetCaptureStats(deltaStats)
				lastCaptureStats = nextStats
				if cfg.Debug {
					debugLog(stderr, "DEBUG: Capture stats delta: received=%d dropped=%d if_dropped=%d\n",
						deltaStats.PacketsReceived, deltaStats.PacketsDropped, deltaStats.PacketsIfDropped)
				}
			}
			summary := statsTracker.SnapshotAndReset(elapsed, lastReportTime, now)
			if summary.HasData() || cfg.EmitEmpty {
				if err := writeSummary(stdout, summary, cfg.Format); err != nil {
					return err
				}
			}
			lastReportTime = now
		}

		packet, err := source.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Clean EOF from offline capture stream
				break
			}
			if errors.Is(err, capture.ErrCaptureClosed) {
				captureErr = fmt.Errorf("capture stream closed: %w", err)
				break
			}
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveErrors {
				captureErr = fmt.Errorf("exceeded max consecutive capture errors (%d): %w", maxConsecutiveErrors, err)
				break
			}
			if cfg.Debug {
				debugLog(stderr, "DEBUG: Error reading packet: %v\n", err)
			}
			if !sleepWithContext(ctx, consecutiveErrorBackoff) {
				break
			}
			continue
		}
		consecutiveErrors = 0

		if packet == nil {
			// No packet received (timeout); yield briefly unless cancelled
			if !sleepWithContext(ctx, 10*time.Millisecond) {
				break
			}
			continue
		}

		if !packet.Timestamp.IsZero() {
			if firstPacketTime.IsZero() {
				firstPacketTime = packet.Timestamp
			}
			lastPacketTime = packet.Timestamp
		}

		if packet.DecodeError {
			statsTracker.RecordIgnoredDecodeError()
			continue
		}

		if packet.NoPayload {
			statsTracker.RecordIgnoredNoPayload()
			continue
		}

		if cfg.Debug {
			debugLog(stderr, "DEBUG: Received packet: len=%d\n", len(packet.Data))
		}

		// Detect TLS ClientHello / TLS record
		if len(packet.Data) >= 2 && packet.Data[0] == 0x16 && packet.Data[1] == 0x03 {
			statsTracker.RecordTLS(packet.SrcIP)
			statsTracker.RecordIgnoredNotSyslog()
			if cfg.Debug {
				debugLog(stderr, "DEBUG: Suspected TLS traffic from %s (ignoring)\n", packet.SrcIP)
			}
			continue
		}

		messages := syslog.SplitMessages(packet.Data, packet.Transport)
		for _, msgBytes := range messages {
			syslogMsg, err := syslog.Parse(msgBytes)
			if err != nil || syslogMsg == nil {
				statsTracker.RecordIgnoredNotSyslog()
				if cfg.Debug && err != nil {
					debugLog(stderr, "DEBUG: Ignored packet: %v\n", err)
				}
				continue
			}

			if syslogMsg.WasSanitized {
				statsTracker.RecordNonUTF8Sanitized()
			}

			statsTracker.AddEntry(packet.SrcIP, syslogMsg.Hostname, syslogMsg.Message)

			if cfg.Debug {
				if cfg.NoSample {
					debugLog(stderr, "DEBUG: Captured from %s (claimed=%s): len=%d [sample suppressed]\n", packet.SrcIP, syslogMsg.Hostname, len(syslogMsg.Message))
				} else if cfg.RedactSample {
					debugLog(stderr, "DEBUG: Captured from %s (claimed=%s): [REDACTED]\n", packet.SrcIP, syslogMsg.Hostname)
				} else {
					sample := syslogMsg.Message
					if len(sample) > cfg.SampleBytes {
						for maxBytes := cfg.SampleBytes; maxBytes > 0; maxBytes-- {
							if (sample[maxBytes] & 0xC0) != 0x80 {
								sample = sample[:maxBytes]
								break
							}
						}
					}
					debugLog(stderr, "DEBUG: Captured from %s (claimed=%s): %q\n", packet.SrcIP, syslogMsg.Hostname, sample)
				}
			}
		}
	}

	// Output final report
	if cs, err := source.Stats(); err == nil && cs != nil {
		prev := lastCaptureStats
		if !cfg.Periodic {
			prev = nil
		}
		deltaStats, _ := computeCaptureStatsDelta(cs, prev)
		statsTracker.SetCaptureStats(deltaStats)
		if cfg.Debug {
			debugLog(stderr, "DEBUG: Capture stats: received=%d dropped=%d if_dropped=%d\n",
				deltaStats.PacketsReceived, deltaStats.PacketsDropped, deltaStats.PacketsIfDropped)
		}
	}

	now := time.Now()
	if cfg.Periodic {
		elapsed := uint64(math.Ceil(now.Sub(lastReportTime).Seconds()))
		if elapsed == 0 {
			elapsed = 1
		}
		summary := statsTracker.SnapshotAndReset(elapsed, lastReportTime, now)
		if summary.HasData() || cfg.EmitEmpty {
			if err := writeSummary(stdout, summary, cfg.Format); err != nil {
				return err
			}
		}
	} else {
		var (
			interval uint64
			start    time.Time
		)
		if cfg.PcapFile != "" && !firstPacketTime.IsZero() && !lastPacketTime.IsZero() {
			start = firstPacketTime
			now = lastPacketTime
			elapsed := uint64(math.Ceil(now.Sub(start).Seconds()))
			if elapsed == 0 {
				elapsed = 1
			}
			interval = elapsed
		} else {
			elapsed := uint64(math.Ceil(now.Sub(startTime).Seconds()))
			if elapsed == 0 {
				elapsed = 1
			}
			interval = elapsed
			start = startTime
		}

		summary := statsTracker.GetSummary(interval, start, now)
		if err := writeSummary(stdout, summary, cfg.Format); err != nil {
			return err
		}
	}

	if captureErr != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", captureErr)
		return captureErr
	}

	return nil
}

func debugLog(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func writeSummary(w io.Writer, summary stats.JSONSummary, format string) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if format == "ndjson" {
		return enc.Encode(summary)
	}
	enc.SetIndent("", "  ")
	return enc.Encode(summary)
}

func computeCaptureStatsDelta(curr *capture.Stats, prev *capture.Stats) (*stats.CaptureStats, *capture.Stats) {
	if curr == nil {
		return nil, prev
	}
	received := curr.PacketsReceived
	dropped := curr.PacketsDropped
	ifDropped := curr.PacketsIfDropped

	if prev != nil {
		received -= prev.PacketsReceived
		if received < 0 {
			received = 0
		}
		dropped -= prev.PacketsDropped
		if dropped < 0 {
			dropped = 0
		}
		ifDropped -= prev.PacketsIfDropped
		if ifDropped < 0 {
			ifDropped = 0
		}
	}

	diff := &stats.CaptureStats{
		PacketsReceived:  received,
		PacketsDropped:   dropped,
		PacketsIfDropped: ifDropped,
	}
	next := &capture.Stats{
		PacketsReceived:  curr.PacketsReceived,
		PacketsDropped:   curr.PacketsDropped,
		PacketsIfDropped: curr.PacketsIfDropped,
	}
	return diff, next
}

// sleepWithContext pauses execution for duration d or returns promptly if ctx is cancelled.
// It returns true if the full duration elapsed, or false if ctx was cancelled.
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer func() {
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
	}()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
