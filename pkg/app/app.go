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

	statsTracker := stats.NewStatsTracker()
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

		// Check duration timeout
		if time.Since(startTime) >= duration {
			break
		}

		// Handle periodic output
		if cfg.Periodic && time.Since(lastReportTime) >= time.Duration(cfg.Frequency)*time.Second {
			if !statsTracker.IsEmpty() {
				summary := statsTracker.GetSummary(cfg.Frequency)
				if err := writeJSONPretty(stdout, summary); err != nil {
					return err
				}
				statsTracker.Clear()
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

		if cfg.Debug {
			fmt.Fprintf(stderr, "DEBUG: Received packet: len=%d\n", len(packet.Data))
		}

		syslogMsg, err := syslog.ParseSyslogPacket(packet.Data)
		if err != nil || syslogMsg == nil {
			if cfg.Debug && err != nil {
				fmt.Fprintf(stderr, "DEBUG: Ignored packet: %v\n", err)
			}
			continue
		}

		hostname := syslogMsg.Hostname
		if hostname == "" {
			if packet.SrcIP != "" {
				hostname = packet.SrcIP
			} else {
				hostname = "Unknown"
			}
		}

		statsTracker.AddEntry(hostname, syslogMsg.Message)

		if cfg.Debug {
			fmt.Fprintf(stderr, "DEBUG: Captured from %s: %s\n", hostname, syslogMsg.Message)
		}
	}

	// Output final report
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
