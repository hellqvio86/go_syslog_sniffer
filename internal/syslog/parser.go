package syslog

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
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

// Message represents a parsed syslog message.
type Message struct {
	Message      string
	Hostname     string
	WasSanitized bool
}

// SyslogPacket is an alias for Message for backwards compatibility.
type SyslogPacket = Message

// SplitMessages splits newline-delimited syslog messages into separate byte slices.
func SplitMessages(data []byte) [][]byte {
	if !bytes.Contains(data, []byte("\n")) {
		return [][]byte{data}
	}
	var res [][]byte
	lines := bytes.Split(data, []byte("\n"))
	for _, l := range lines {
		trimmed := bytes.TrimSpace(l)
		if len(trimmed) > 0 {
			res = append(res, trimmed)
		}
	}
	if len(res) == 0 {
		return [][]byte{data}
	}
	return res
}

// Parse attempts to parse raw packet bytes into a Message.
// It requires the message to start with <PRI> where PRI <= 191, optionally preceded by
// an RFC 6587 octet count prefix.
func Parse(data []byte) (*Message, error) {
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

	wasSanitized := !utf8.Valid(payloadBytes)
	msg := strings.ToValidUTF8(string(payloadBytes), "\uFFFD")
	var hostname string

	if matches := rfc5424Regex.FindStringSubmatch(msg); len(matches) > 4 {
		hostname = cleanHostname(matches[4])
	} else if matches := rfc3164Regex.FindStringSubmatch(msg); len(matches) > 3 {
		hostname = cleanHostname(matches[3])
	} else if matches := rfc3164ISORegex.FindStringSubmatch(msg); len(matches) > 3 {
		hostname = cleanHostname(matches[3])
	}

	return &Message{
		Message:      msg,
		Hostname:     hostname,
		WasSanitized: wasSanitized,
	}, nil
}

// ParseSyslogPacket is an alias for Parse.
func ParseSyslogPacket(data []byte) (*Message, error) {
	return Parse(data)
}
