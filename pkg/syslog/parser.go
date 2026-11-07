package syslog

import (
	"bytes"
	"regexp"
	"unicode/utf8"
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
)

// SyslogPacket represents a parsed syslog packet.
type SyslogPacket struct {
	Message  string
	Hostname string
}

// ParseSyslogPacket attempts to parse raw packet bytes into a SyslogPacket.
// It checks for UTF-8 validity and extracts hostname if RFC 5424 or RFC 3164 headers are found.
func ParseSyslogPacket(data []byte) *SyslogPacket {
	if len(data) == 0 {
		return nil
	}

	// Heuristic: If there is a '<' byte, look for syslog message starting at '<'
	payloadBytes := data
	if idx := bytes.IndexByte(data, '<'); idx != -1 {
		payloadBytes = data[idx:]
	}

	if !utf8.Valid(payloadBytes) {
		return nil
	}

	msg := string(payloadBytes)
	var hostname string

	if matches := rfc5424Regex.FindStringSubmatch(msg); len(matches) > 4 {
		hostname = matches[4]
	} else if matches := rfc3164Regex.FindStringSubmatch(msg); len(matches) > 3 {
		hostname = matches[3]
	}

	return &SyslogPacket{
		Message:  msg,
		Hostname: hostname,
	}
}
