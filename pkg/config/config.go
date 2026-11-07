package config

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// Version holds the application version, injectible via ldflags.
var Version = "0.1.0"

// Config holds the runtime configuration parameters for syslog_sniffer.
type Config struct {
	Interface   string
	Port        int
	Debug       bool
	Interval    uint64
	Periodic    bool
	Frequency   uint64
	ShowVersion bool
}

// Parse parses CLI arguments from os.Args[1:] and returns the Config.
func Parse() (*Config, error) {
	return ParseArgs(os.Args[1:], os.Stderr)
}

// ParseArgs parses a given argument slice into a Config.
func ParseArgs(arguments []string, errorOutput io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("syslog_sniffer", flag.ContinueOnError)
	fs.SetOutput(errorOutput)

	var (
		intfShort, intfLong         string
		portShort, portLong         int
		debugShort, debugLong       bool
		intervalShort, intervalLong uint64
		periodic                    bool
		frequency                   uint64
		versionShort, versionLong   bool
	)

	// Short flags
	fs.StringVar(&intfShort, "i", "", "Network interface to sniff (e.g., eth0)")
	fs.IntVar(&portShort, "p", 0, "Syslog port to monitor (default 514)")
	fs.BoolVar(&debugShort, "d", false, "Enable debug output")
	fs.Uint64Var(&intervalShort, "t", 0, "Capture duration in seconds (default 10)")
	fs.BoolVar(&versionShort, "v", false, "Print version and exit")

	// Long flags (parities with rust_syslog_sniffer)
	fs.StringVar(&intfLong, "interface", "", "Network interface to sniff (e.g., eth0)")
	fs.IntVar(&portLong, "port", 0, "Syslog port to monitor (default 514)")
	fs.BoolVar(&debugLong, "debug", false, "Enable debug output")
	fs.Uint64Var(&intervalLong, "interval", 0, "Capture duration in seconds (default 10)")
	fs.BoolVar(&periodic, "periodic", false, "Enable periodic summary output")
	fs.Uint64Var(&frequency, "frequency", 5, "Frequency in seconds for periodic output")
	fs.BoolVar(&versionLong, "version", false, "Print version and exit")

	if err := fs.Parse(arguments); err != nil {
		return nil, err
	}

	// Resolve interface
	selectedInterface := "eth0"
	if intfLong != "" {
		selectedInterface = intfLong
	} else if intfShort != "" {
		selectedInterface = intfShort
	}

	// Resolve port
	selectedPort := 514
	if portLong != 0 {
		selectedPort = portLong
	} else if portShort != 0 {
		selectedPort = portShort
	}

	// Resolve interval
	var selectedInterval uint64 = 10
	if intervalLong != 0 {
		selectedInterval = intervalLong
	} else if intervalShort != 0 {
		selectedInterval = intervalShort
	}

	// Resolve debug
	selectedDebug := debugShort || debugLong
	if !selectedDebug && os.Getenv("DEBUG") == "1" {
		selectedDebug = true
	}

	if frequency == 0 {
		return nil, fmt.Errorf("frequency must be greater than 0")
	}

	return &Config{
		Interface:   selectedInterface,
		Port:        selectedPort,
		Debug:       selectedDebug,
		Interval:    selectedInterval,
		Periodic:    periodic,
		Frequency:   frequency,
		ShowVersion: versionShort || versionLong,
	}, nil
}
