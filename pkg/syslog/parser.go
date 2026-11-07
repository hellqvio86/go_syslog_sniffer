package syslog

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	// ErrEmpty is returned when the packet payload is empty.
	ErrEmpty = errors.New("empty payload")
	// ErrNotSyslog is returned when the payload does not have a valid syslog header.
	ErrNotSyslog = errors.New("not a valid syslog message")
)

var (
	// rfc5424Regex matches RFC 5424 syslog header:
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCT-DATA MSG
	// Group 4 captures the HOSTNAME.
	rfc5424Regex = regexp.MustCompile(`^<(\d{1,3})>(\d)\s+(\S+)\s+(\S+)\s+`)

	// rfc3164Regex matches RFC 3164 BSD syslog header:
	// <PRI>TIMESTAMP HOSTNAME MSG
	// Group 3 captures the HOSTNAME.
	rfc3164Regex = regexp.MustCompile(`^<(\d{1,3})>([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+`)

	// rfc3164ISORegex matches rsyslog high-precision ISO-timestamp RFC 3164 header:
	// <PRI>TIMESTAMP HOSTNAME MSG
	// Group 3 captures the HOSTNAME.
	rfc3164ISORegex = regexp.MustCompile(`^<(\d{1,3})>(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+`)

	// headerPrefixRegex matches optional RFC 6587 octet count followed by <PRI>.
	headerPrefixRegex = regexp.MustCompile(`^(?:(\d+)\s+)?<(\d{1,3})>`)
)

func cleanHostname(raw string) string {
	if raw == "" || raw == "-" {
		return ""
	}
	if len(raw) > 255 {
		raw = raw[:255]
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		// Must be printable ASCII and non-whitespace
		if b < 33 || b > 126 {
			return ""
		}
	}
	return raw
}

// SyslogPacket represents a parsed syslog packet.
type SyslogPacket struct {
	Message  string
	Hostname string
}

// ParseSyslogPacket attempts to parse raw packet bytes into a SyslogPacket.
// It requires the message to start with <PRI> where PRI <= 191, optionally preceded by
// an RFC 6587 octet count prefix.
func ParseSyslogPacket(data []byte) (*SyslogPacket, error) {
	if len(data) == 0 {
		return nil, ErrEmpty
	}

	matches := headerPrefixRegex.FindSubmatch(data)
	if matches == nil {
		return nil, ErrNotSyslog
	}

	priStr := string(matches[2])
	pri, err := strconv.Atoi(priStr)
	if err != nil || pri > 191 {
		return nil, ErrNotSyslog
	}

	// If there was an RFC 6587 octet-count prefix, advance to '<'
	payloadBytes := data
	if len(matches[1]) > 0 {
		if idx := bytes.IndexByte(data, '<'); idx != -1 {
			payloadBytes = data[idx:]
		}
	}

	// Sanitize sample to valid UTF-8 so non-UTF8 syslog is never dropped
	msg := strings.ToValidUTF8(string(payloadBytes), "\uFFFD")
	var hostname string

	if matches := rfc5424Regex.FindStringSubmatch(msg); len(matches) > 4 {
		hostname = cleanHostname(matches[4])
	} else if matches := rfc3164Regex.FindStringSubmatch(msg); len(matches) > 3 {
		hostname = cleanHostname(matches[3])
	} else if matches := rfc3164ISORegex.FindStringSubmatch(msg); len(matches) > 3 {
		hostname = cleanHostname(matches[3])
	}

	return &SyslogPacket{
		Message:  msg,
		Hostname: hostname,
	}, nil
}
