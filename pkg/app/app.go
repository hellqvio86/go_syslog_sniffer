package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hellqvio86/go_syslog_sniffer/pkg/capture"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/config"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/stats"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/syslog"
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
		fmt.Fprintf(stderr, "DEBUG: Port to sniff: %d\n", cfg.Port)
		fmt.Fprintf(stderr, "DEBUG: Interface to sniff: %s\n", cfg.Interface)
		fmt.Fprintf(stderr, "DEBUG: Interval: %d seconds\n", cfg.Interval)
		fmt.Fprintf(stderr, "DEBUG: Starting capture loop\n")
	}

	statsTracker := stats.NewStatsTrackerWithOptions(cfg.MaxHosts, cfg.SampleBytes, cfg.NoSample, cfg.RedactSample)
	startTime := time.Now()
	lastReportTime := startTime
	duration := time.Duration(cfg.Interval) * time.Second

	var (
		consecutiveErrors int
		captureErr        error
	)

	for {
		// Check context cancellation (e.g. SIGINT/SIGTERM)
		if ctx.Err() != nil {
			break
		}

		// Check duration timeout if finite interval requested
		if cfg.Interval > 0 && time.Since(startTime) >= duration {
			break
		}

		// Handle periodic output
		if cfg.Periodic && time.Since(lastReportTime) >= time.Duration(cfg.Frequency)*time.Second {
			if !statsTracker.IsEmpty() {
				if cs, err := source.Stats(); err == nil && cs != nil {
					statsTracker.SetCaptureStats(&stats.CaptureStats{
						PacketsReceived:  cs.PacketsReceived,
						PacketsDropped:   cs.PacketsDropped,
						PacketsIfDropped: cs.PacketsIfDropped,
					})
					if cfg.Debug {
						fmt.Fprintf(stderr, "DEBUG: Capture stats: received=%d dropped=%d if_dropped=%d\n",
							cs.PacketsReceived, cs.PacketsDropped, cs.PacketsIfDropped)
					}
				}
				summary := statsTracker.SnapshotAndReset(cfg.Frequency)
				if err := writeJSONPretty(stdout, summary); err != nil {
					return err
				}
			}
			lastReportTime = time.Now()
		}

		packet, err := source.NextPacket()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, capture.ErrCaptureClosed) {
				captureErr = fmt.Errorf("capture stream closed: %w", err)
				break
			}
			consecutiveErrors++
			if consecutiveErrors >= maxConsecutiveErrors {
				captureErr = fmt.Errorf("exceeded max consecutive capture errors (%d): %w", maxConsecutiveErrors, err)
				break
			}
			if cfg.Debug {
				fmt.Fprintf(stderr, "DEBUG: Error reading packet: %v\n", err)
			}
			time.Sleep(consecutiveErrorBackoff)
			continue
		}
		consecutiveErrors = 0

		if packet == nil {
			// No packet received (timeout); yield briefly
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if packet.NoPayload {
			statsTracker.RecordIgnoredNoPayload()
			continue
		}

		if cfg.Debug {
			fmt.Fprintf(stderr, "DEBUG: Received packet: len=%d\n", len(packet.Data))
		}

		// Detect TLS ClientHello / TLS record
		if len(packet.Data) >= 2 && packet.Data[0] == 0x16 && packet.Data[1] == 0x03 {
			statsTracker.RecordTLS(packet.SrcIP)
			statsTracker.RecordIgnoredNotSyslog()
			if cfg.Debug {
				fmt.Fprintf(stderr, "DEBUG: Suspected TLS traffic from %s (ignoring)\n", packet.SrcIP)
			}
			continue
		}

		messages := syslog.SplitMessages(packet.Data)
		for _, msgBytes := range messages {
			syslogMsg, err := syslog.ParseSyslogPacket(msgBytes)
			if err != nil || syslogMsg == nil {
				statsTracker.RecordIgnoredNotSyslog()
				if cfg.Debug && err != nil {
					fmt.Fprintf(stderr, "DEBUG: Ignored packet: %v\n", err)
				}
				continue
			}

			if syslogMsg.WasSanitized {
				statsTracker.RecordNonUTF8Sanitized()
			}

			statsTracker.AddEntry(packet.SrcIP, syslogMsg.Hostname, syslogMsg.Message)

			if cfg.Debug {
				fmt.Fprintf(stderr, "DEBUG: Captured from %s (claimed=%s): %q\n", packet.SrcIP, syslogMsg.Hostname, syslogMsg.Message)
			}
		}
	}

	// Output final report
	if cs, err := source.Stats(); err == nil && cs != nil {
		statsTracker.SetCaptureStats(&stats.CaptureStats{
			PacketsReceived:  cs.PacketsReceived,
			PacketsDropped:   cs.PacketsDropped,
			PacketsIfDropped: cs.PacketsIfDropped,
		})
		if cfg.Debug {
			fmt.Fprintf(stderr, "DEBUG: Capture stats: received=%d dropped=%d if_dropped=%d\n",
				cs.PacketsReceived, cs.PacketsDropped, cs.PacketsIfDropped)
		}
	}

	if !cfg.Periodic || !statsTracker.IsEmpty() {
		var interval uint64
		if cfg.Periodic {
			elapsed := uint64(time.Since(lastReportTime).Seconds())
			if elapsed == 0 {
				elapsed = 1
			}
			interval = elapsed
		} else {
			interval = cfg.Interval
		}

		summary := statsTracker.GetSummary(interval)
		if err := writeJSONPretty(stdout, summary); err != nil {
			return err
		}
	}

	if captureErr != nil {
		fmt.Fprintf(stderr, "Error: %v\n", captureErr)
		return captureErr
	}

	return nil
}

func writeJSONPretty(w io.Writer, v interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
