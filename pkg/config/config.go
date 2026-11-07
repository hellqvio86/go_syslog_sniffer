package config

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Version holds the application version, injectible via ldflags.
var Version = "0.2.0"

// Config holds the runtime configuration parameters for syslog_sniffer.
type Config struct {
	Interface      string
	Port           int
	Debug          bool
	Interval       uint64
	Periodic       bool
	Frequency      uint64
	ShowVersion    bool
	MaxHosts       int
	SampleBytes    int
	ListInterfaces bool
	NoSample       bool
	RedactSample   bool
	PcapFile       string
	Format         string
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
		maxHosts                    int
		sampleBytes                 int
		listInterfaces              bool
		noSample                    bool
		redactSample                bool
		pcapFileShort, pcapFileLong string
		format                      string
	)

	// Short flags
	fs.StringVar(&intfShort, "i", "", "Network interface to sniff (e.g., eth0)")
	fs.IntVar(&portShort, "p", 0, "Syslog port to monitor (default 514)")
	fs.BoolVar(&debugShort, "d", false, "Enable debug output")
	fs.Uint64Var(&intervalShort, "t", 0, "Capture duration in seconds (default 10)")
	fs.BoolVar(&versionShort, "v", false, "Print version and exit")
	fs.StringVar(&pcapFileShort, "r", "", "Read packets from a pcap file instead of a live interface")

	// Long flags (parities with rust_syslog_sniffer)
	fs.StringVar(&intfLong, "interface", "", "Network interface to sniff (e.g., eth0)")
	fs.IntVar(&portLong, "port", 0, "Syslog port to monitor (default 514)")
	fs.BoolVar(&debugLong, "debug", false, "Enable debug output")
	fs.Uint64Var(&intervalLong, "interval", 0, "Capture duration in seconds (default 10)")
	fs.BoolVar(&periodic, "periodic", false, "Enable periodic summary output")
	fs.Uint64Var(&frequency, "frequency", 5, "Frequency in seconds for periodic output")
	fs.BoolVar(&versionLong, "version", false, "Print version and exit")
	fs.IntVar(&maxHosts, "max-hosts", 10000, "Maximum number of distinct hosts to track in memory (default 10000)")
	fs.IntVar(&sampleBytes, "sample-bytes", 2048, "Maximum byte length of message sample retained per host (default 2048)")
	fs.BoolVar(&listInterfaces, "list-interfaces", false, "List available network interfaces and exit")
	fs.BoolVar(&noSample, "no-sample", false, "Do not include sample messages in output")
	fs.BoolVar(&redactSample, "redact-sample", false, "Redact message samples in output")
	fs.StringVar(&pcapFileLong, "read-file", "", "Read packets from a pcap file instead of a live interface")
	fs.StringVar(&format, "format", "json", "Output format (json or ndjson, default json)")

	if err := fs.Parse(arguments); err != nil {
		return nil, err
	}

	if listInterfaces {
		return &Config{
			ListInterfaces: true,
		}, nil
	}

	// Check which flags were explicitly passed
	var (
		intervalSet bool
		portSet     bool
	)
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "t" || f.Name == "interval" {
			intervalSet = true
		}
		if f.Name == "p" || f.Name == "port" {
			portSet = true
		}
	})

	// Resolve interface (defaults to "any" on Linux)
	selectedInterface := "any"
	if intfLong != "" {
		selectedInterface = intfLong
	} else if intfShort != "" {
		selectedInterface = intfShort
	}

	// Resolve port
	selectedPort := 514
	if portSet {
		if portLong != 0 || (portShort == 0 && portLong != 0) {
			selectedPort = portLong
		} else {
			selectedPort = portShort
		}
	}

	if selectedPort < 1 || selectedPort > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535, got %d", selectedPort)
	}

	const maxAllowedDuration = 1 << 31

	// Resolve interval
	var selectedInterval uint64
	if intervalSet {
		if intervalLong != 0 || (intervalShort == 0 && intervalLong != 0) {
			selectedInterval = intervalLong
		} else {
			selectedInterval = intervalShort
		}
		if selectedInterval > maxAllowedDuration {
			return nil, fmt.Errorf("interval %d exceeds maximum supported limit (%d seconds)", selectedInterval, maxAllowedDuration)
		}
	} else {
		if periodic {
			selectedInterval = 0 // periodic defaults to unlimited
		} else {
			selectedInterval = 10 // standard mode defaults to 10s
		}
	}

	// Resolve debug
	selectedDebug := debugShort || debugLong
	if !selectedDebug && os.Getenv("DEBUG") == "1" {
		selectedDebug = true
	}

	if frequency == 0 {
		return nil, fmt.Errorf("frequency must be greater than 0")
	}
	if frequency > maxAllowedDuration {
		return nil, fmt.Errorf("frequency %d exceeds maximum supported limit (%d seconds)", frequency, maxAllowedDuration)
	}

	if maxHosts <= 0 {
		maxHosts = 10000
	}
	if sampleBytes <= 0 {
		sampleBytes = 2048
	}

	selectedFormat := strings.ToLower(strings.TrimSpace(format))
	if selectedFormat == "" {
		selectedFormat = "json"
	}
	if selectedFormat != "json" && selectedFormat != "ndjson" {
		return nil, fmt.Errorf("invalid output format %q: must be 'json' or 'ndjson'", format)
	}

	selectedPcapFile := ""
	if pcapFileLong != "" {
		selectedPcapFile = pcapFileLong
	} else if pcapFileShort != "" {
		selectedPcapFile = pcapFileShort
	}

	return &Config{
		Interface:      selectedInterface,
		Port:           selectedPort,
		Debug:          selectedDebug,
		Interval:       selectedInterval,
		Periodic:       periodic,
		Frequency:      frequency,
		ShowVersion:    versionShort || versionLong,
		MaxHosts:       maxHosts,
		SampleBytes:    sampleBytes,
		ListInterfaces: listInterfaces,
		NoSample:       noSample,
		RedactSample:   redactSample,
		PcapFile:       selectedPcapFile,
		Format:         selectedFormat,
	}, nil
}
