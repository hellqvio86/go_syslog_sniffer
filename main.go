package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket/pcap"
	"github.com/hellqvio86/go_syslog_sniffer/internal/app"
	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
	"github.com/hellqvio86/go_syslog_sniffer/internal/config"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.ShowVersion {
		fmt.Printf("syslog_sniffer %s\n", config.Version)
		os.Exit(0)
	}

	if cfg.ListInterfaces {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error listing interfaces: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Available network interfaces:")
		for _, dev := range devs {
			if dev.Description != "" {
				fmt.Printf("  - %s (%s)\n", dev.Name, dev.Description)
			} else {
				fmt.Printf("  - %s\n", dev.Name)
			}
		}
		os.Exit(0)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		cancel()
	}()

	var (
		source capture.PacketSource
	)
	if cfg.PcapFile != "" {
		source, err = capture.NewOfflinePacketSourceMultiPort(cfg.PcapFile, cfg.Ports, cfg.Direction)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to open pcap file: %v\n", err)
			os.Exit(1)
		}
	} else {
		source, err = capture.NewPcapPacketSourceMultiPort(cfg.Interface, cfg.Ports, cfg.Direction, cfg.Promiscuous)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to setup capture: %v\n", err)
			os.Exit(1)
		}
	}
	defer func() {
		_ = source.Close()
	}()

	if err := app.RunSniffer(ctx, cfg, source, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
