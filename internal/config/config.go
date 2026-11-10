package config

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Version holds the application version, injectible via ldflags.
var Version = "0.2.2"

// Config holds the runtime configuration parameters for syslog_sniffer.
type Config struct {
	Interface      string
	Port           int
	Ports          []int
	Direction      string
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
	EmitEmpty      bool
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
		usage := fmt.Sprintf(`syslog_sniffer %s

Usage:
  syslog_sniffer [OPTIONS]

Options:
  -i, --interface <INTERFACE>   Network interface to sniff (e.g., eth0, lo, default: "any")
  -p, --port <PORT>             Syslog port(s) to monitor (comma-separated, 1-65535, default: 514)
      --direction <DIR>         Traffic direction to capture: dst, src, or both (default: dst)
  -t, --interval <SECONDS>      Capture duration in seconds (0 = unlimited, default: 10)
  -d, --debug                   Enable debug output
  -v, --version                 Print version and exit
  -r, --read-file <FILE>        Read packets from a pcap file instead of a live interface
      --periodic                Enable periodic summary output
      --frequency <SECONDS>     Frequency in seconds for periodic output (default: 5)
      --format <FORMAT>         Output format: json or ndjson (default: json)
      --max-hosts <COUNT>       Maximum distinct hosts to track in memory (default: 10000)
      --sample-bytes <BYTES>    Maximum byte length of message sample retained per host (default: 2048)
      --no-sample               Do not include sample messages in output
      --redact-sample           Redact message samples in output
      --emit-empty              Emit empty summary reports when no traffic was seen
      --promisc                 Enable promiscuous mode on network interface (default: false)
      --list-interfaces         List available network interfaces and exit
  -h, --help                    Print usage instructions

Environment Variables:
  DEBUG=1                       Enable debug output (equivalent to -d / --debug)
`, Version)
		_, _ = io.WriteString(errorOutput, usage)
	}

	var (
		intf           = "any"
		portStr        = "514"
		direction      = "dst"
		debug          bool
		interval       uint64 = 10
		periodic       bool
		frequency      uint64 = 5
		version        bool
		maxHosts       = 10000
		sampleBytes    = 2048
		listInterfaces bool
		noSample       bool
		redactSample   bool
		promisc        bool
		emitEmpty      bool
		pcapFile       string
		format         = "json"
	)

	stringVarAlias(fs, &intf, "interface", "i", "any", "Network interface to sniff")
	stringVarAlias(fs, &portStr, "port", "p", "514", "Syslog port(s) to monitor")
	fs.StringVar(&direction, "direction", "dst", "Traffic direction to capture: dst, src, or both")
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
	fs.BoolVar(&emitEmpty, "emit-empty", false, "Emit empty summary reports when no traffic was seen")
	fs.StringVar(&format, "format", "json", "Output format (json or ndjson)")

	if err := fs.Parse(arguments); err != nil {
		return nil, err
	}

	if listInterfaces {
		return &Config{
			ListInterfaces: true,
		}, nil
	}

	// Check flags explicitly passed
	var intervalSet, intfSet, promiscSet, formatSet bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "t" || f.Name == "interval" {
			intervalSet = true
		}
		if f.Name == "i" || f.Name == "interface" {
			intfSet = true
		}
		if f.Name == "promisc" {
			promiscSet = true
		}
		if f.Name == "format" {
			formatSet = true
		}
	})

	if pcapFile != "" && (intfSet || promiscSet) {
		return nil, fmt.Errorf("cannot specify -i/--interface or --promisc when reading from a pcap file (-r)")
	}

	var ports []int
	for _, pStr := range strings.Split(portStr, ",") {
		pStr = strings.TrimSpace(pStr)
		if pStr == "" {
			continue
		}
		p, err := strconv.Atoi(pStr)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("port must be between 1 and 65535, got %s", pStr)
		}
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("at least one port must be specified")
	}

	direction = strings.ToLower(strings.TrimSpace(direction))
	if direction == "" {
		direction = "dst"
	}
	if direction != "dst" && direction != "src" && direction != "both" {
		return nil, fmt.Errorf("invalid direction %q: must be 'dst', 'src', or 'both'", direction)
	}

	const maxAllowedDuration = 1 << 31

	if intervalSet {
		if interval > maxAllowedDuration {
			return nil, fmt.Errorf("interval %d exceeds maximum supported limit (%d seconds)", interval, maxAllowedDuration)
		}
	} else {
		if pcapFile != "" {
			interval = 0 // pcap replay defaults to unlimited (no wall-clock cut off)
		} else if periodic {
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
		return nil, fmt.Errorf("max-hosts must be greater than 0, got %d", maxHosts)
	}
	if sampleBytes <= 0 {
		return nil, fmt.Errorf("sample-bytes must be greater than 0, got %d (use --no-sample to disable samples)", sampleBytes)
	}
	if noSample && redactSample {
		return nil, fmt.Errorf("cannot specify both --no-sample and --redact-sample")
	}

	selectedFormat := strings.ToLower(strings.TrimSpace(format))
	if selectedFormat == "" {
		if periodic && !formatSet {
			selectedFormat = "ndjson"
		} else {
			selectedFormat = "json"
		}
	} else if !formatSet && periodic {
		selectedFormat = "ndjson"
	}
	if selectedFormat != "json" && selectedFormat != "ndjson" {
		return nil, fmt.Errorf("invalid output format %q: must be 'json' or 'ndjson'", format)
	}

	return &Config{
		Interface:      intf,
		Port:           ports[0],
		Ports:          ports,
		Direction:      direction,
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
		EmitEmpty:      emitEmpty,
	}, nil
}
