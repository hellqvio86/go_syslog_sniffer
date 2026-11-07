package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/hellqvio86/go_syslog_sniffer/pkg/app"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/capture"
	"github.com/hellqvio86/go_syslog_sniffer/pkg/config"
)

func main() {
	cfg, err := config.Parse()
	if err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	source, err := capture.NewPcapPacketSource(cfg.Interface, cfg.Port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to setup capture: %v\n", err)
		os.Exit(1)
	}
	defer source.Close()

	if err := app.RunSniffer(ctx, cfg, source, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
