package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket/pcap"
	"github.com/hellqvio86/go_syslog_sniffer/internal/app"
	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
	"github.com/hellqvio86/go_syslog_sniffer/internal/config"
)

// packetSourceFactory creates a packet source for the given configuration.
// It can be replaced in unit tests to verify lifecycle and error handling.
var packetSourceFactory = func(cfg *config.Config) (capture.PacketSource, error) {
	if cfg.PcapFile != "" {
		return capture.NewOfflinePacketSourceMultiPort(cfg.PcapFile, cfg.Ports, cfg.Direction)
	}
	return capture.NewPcapPacketSourceMultiPort(cfg.Interface, cfg.Ports, cfg.Direction, cfg.Promiscuous)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	cfg, err := config.ParseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	if cfg.ShowVersion {
		_, _ = fmt.Fprintf(stdout, "syslog_sniffer %s\n", config.Version)
		return 0
	}

	if cfg.ListInterfaces {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error listing interfaces: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintln(stdout, "Available network interfaces:")
		for _, dev := range devs {
			if dev.Description != "" {
				_, _ = fmt.Fprintf(stdout, "  - %s (%s)\n", dev.Name, dev.Description)
			} else {
				_, _ = fmt.Fprintf(stdout, "  - %s\n", dev.Name)
			}
		}
		return 0
	}

	// Setup signal handling. Calling stop on exit unregisters signal notifications.
	// A subsequent signal before shutdown finishes triggers default OS termination.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	source, err := packetSourceFactory(cfg)
	if err != nil {
		if cfg.PcapFile != "" {
			_, _ = fmt.Fprintf(stderr, "Error: Failed to open pcap file: %v\n", err)
		} else {
			_, _ = fmt.Fprintf(stderr, "Error: Failed to setup capture: %v\n", err)
		}
		return 1
	}
	defer func() {
		if closeErr := source.Close(); closeErr != nil {
			_, _ = fmt.Fprintf(stderr, "Warning: failed to close packet source: %v\n", closeErr)
		}
	}()

	if err := app.RunSniffer(ctx, cfg, source, stdout, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}
