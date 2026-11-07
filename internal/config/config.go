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
	Promiscuous    bool
}

// Parse parses CLI arguments from os.Args[1:] and returns the Config.
func Parse() (*Config, error) {
	return ParseArgs(os.Args[1:], os.Stderr)
}

func stringVarAlias(fs *flag.FlagSet, p *string, long, short, val, usage string) {
	fs.StringVar(p, long, val, usage)
	if short != "" {
		fs.StringVar(p, short, val, usage)
	}
}

func intVarAlias(fs *flag.FlagSet, p *int, long, short string, val int, usage string) {
	fs.IntVar(p, long, val, usage)
	if short != "" {
		fs.IntVar(p, short, val, usage)
	}
}

func boolVarAlias(fs *flag.FlagSet, p *bool, long, short string, val bool, usage string) {
	fs.BoolVar(p, long, val, usage)
	if short != "" {
		fs.BoolVar(p, short, val, usage)
	}
}

func uint64VarAlias(fs *flag.FlagSet, p *uint64, long, short string, val uint64, usage string) {
	fs.Uint64Var(p, long, val, usage)
	if short != "" {
		fs.Uint64Var(p, short, val, usage)
	}
}

// ParseArgs parses a given argument slice into a Config.
func ParseArgs(arguments []string, errorOutput io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("syslog_sniffer", flag.ContinueOnError)
	fs.SetOutput(errorOutput)

	fs.Usage = func() {
		fmt.Fprintf(errorOutput, "syslog_sniffer %s\n\nUsage:\n  syslog_sniffer [OPTIONS]\n\nOptions:\n", Version)
		fmt.Fprintln(errorOutput, "  -i, --interface <INTERFACE>   Network interface to sniff (e.g., eth0, lo, default: \"any\")")
		fmt.Fprintln(errorOutput, "  -p, --port <PORT>             Syslog port to monitor (1-65535, default: 514)")
		fmt.Fprintln(errorOutput, "  -t, --interval <SECONDS>      Capture duration in seconds (0 = unlimited, default: 10)")
		fmt.Fprintln(errorOutput, "  -d, --debug                   Enable debug output")
		fmt.Fprintln(errorOutput, "  -v, --version                 Print version and exit")
		fmt.Fprintln(errorOutput, "  -r, --read-file <FILE>        Read packets from a pcap file instead of a live interface")
		fmt.Fprintln(errorOutput, "      --periodic                Enable periodic summary output")
		fmt.Fprintln(errorOutput, "      --frequency <SECONDS>     Frequency in seconds for periodic output (default: 5)")
		fmt.Fprintln(errorOutput, "      --format <FORMAT>         Output format: json or ndjson (default: json)")
		fmt.Fprintln(errorOutput, "      --max-hosts <COUNT>       Maximum distinct hosts to track in memory (default: 10000)")
		fmt.Fprintln(errorOutput, "      --sample-bytes <BYTES>    Maximum byte length of message sample retained per host (default: 2048)")
		fmt.Fprintln(errorOutput, "      --no-sample               Do not include sample messages in output")
		fmt.Fprintln(errorOutput, "      --redact-sample           Redact message samples in output")
		fmt.Fprintln(errorOutput, "      --promisc                 Enable promiscuous mode on network interface (default: false)")
		fmt.Fprintln(errorOutput, "      --list-interfaces         List available network interfaces and exit")
		fmt.Fprintln(errorOutput, "  -h, --help                    Print usage instructions")
		fmt.Fprintln(errorOutput, "\nEnvironment Variables:")
		fmt.Fprintln(errorOutput, "  DEBUG=1                       Enable debug output (equivalent to -d / --debug)")
	}

	var (
		intf           string = "any"
		port           int    = 514
		debug          bool
		interval       uint64 = 10
		periodic       bool
		frequency      uint64 = 5
		version        bool
		maxHosts       int = 10000
		sampleBytes    int = 2048
		listInterfaces bool
		noSample       bool
		redactSample   bool
		promisc        bool
		pcapFile       string
		format         string = "json"
	)

	stringVarAlias(fs, &intf, "interface", "i", "any", "Network interface to sniff")
	intVarAlias(fs, &port, "port", "p", 514, "Syslog port to monitor")
	boolVarAlias(fs, &debug, "debug", "d", false, "Enable debug output")
	uint64VarAlias(fs, &interval, "interval", "t", 10, "Capture duration in seconds")
	boolVarAlias(fs, &version, "version", "v", false, "Print version and exit")
	stringVarAlias(fs, &pcapFile, "read-file", "r", "", "Read packets from a pcap file")
	fs.BoolVar(&periodic, "periodic", false, "Enable periodic summary output")
	fs.Uint64Var(&frequency, "frequency", 5, "Frequency in seconds for periodic output")
	fs.IntVar(&maxHosts, "max-hosts", 10000, "Maximum number of distinct hosts to track in memory")
	fs.IntVar(&sampleBytes, "sample-bytes", 2048, "Maximum byte length of message sample retained per host")
	fs.BoolVar(&listInterfaces, "list-interfaces", false, "List available network interfaces and exit")
	fs.BoolVar(&noSample, "no-sample", false, "Do not include sample messages in output")
	fs.BoolVar(&redactSample, "redact-sample", false, "Redact message samples in output")
	fs.BoolVar(&promisc, "promisc", false, "Enable promiscuous mode on network interface")
	fs.StringVar(&format, "format", "json", "Output format (json or ndjson)")

	if err := fs.Parse(arguments); err != nil {
		return nil, err
	}

	if listInterfaces {
		return &Config{
			ListInterfaces: true,
		}, nil
	}

	// Check if interval was explicitly passed
	var intervalSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "t" || f.Name == "interval" {
			intervalSet = true
		}
	})

	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}

	const maxAllowedDuration = 1 << 31

	if intervalSet {
		if interval > maxAllowedDuration {
			return nil, fmt.Errorf("interval %d exceeds maximum supported limit (%d seconds)", interval, maxAllowedDuration)
		}
	} else {
		if periodic {
			interval = 0 // periodic defaults to unlimited
		} else {
			interval = 10 // standard mode defaults to 10s
		}
	}

	if !debug && os.Getenv("DEBUG") == "1" {
		debug = true
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

	return &Config{
		Interface:      intf,
		Port:           port,
		Debug:          debug,
		Interval:       interval,
		Periodic:       periodic,
		Frequency:      frequency,
		ShowVersion:    version,
		MaxHosts:       maxHosts,
		SampleBytes:    sampleBytes,
		ListInterfaces: listInterfaces,
		NoSample:       noSample,
		RedactSample:   redactSample,
		PcapFile:       pcapFile,
		Format:         selectedFormat,
		Promiscuous:    promisc,
	}, nil
}
