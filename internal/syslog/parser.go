package syslog

import (
	"bytes"
	"errors"
	"fmt"
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
	// rfc5424Regex matches RFC 5424 syslog header with VERSION = 1:
	// <PRI>1 TIMESTAMP HOSTNAME
	// Group 2 captures the HOSTNAME.
	rfc5424Regex = regexp.MustCompile(`^<([1-9]\d{0,2}|0)>1\s+\S+\s+(\S+)`)

	// rfc3164Regex matches BSD syslog header including Cisco prefixes and variations:
	// <PRI>[seq:] [*|.]Mmm dd [yyyy] hh:mm:ss[.frac][:] HOSTNAME
	// Group 4 captures the HOSTNAME.
	rfc3164Regex = regexp.MustCompile(`^<([1-9]\d{0,2}|0)>(?:(\d+):\s*)?(?:[\*\.]\s*)?([A-Z][a-z]{2}\s+\d+(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?::)?\s+(\S+)`)

	// rfc3164ISORegex matches rsyslog high-precision ISO-timestamp RFC 3164 header:
	// <PRI>[seq:] TIMESTAMP HOSTNAME
	// Group 4 captures the HOSTNAME.
	rfc3164ISORegex = regexp.MustCompile(`^<([1-9]\d{0,2}|0)>(?:(\d+):\s*)?(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)`)

	// ciscoSeqOnlyRegex matches Cisco logs with sequence number prefix but no timestamp:
	// Group 3 captures the HOSTNAME.
	ciscoSeqOnlyRegex = regexp.MustCompile(`^<([1-9]\d{0,2}|0)>(\d+):\s+(\S+)`)

	// headerPrefixRegex matches optional RFC 6587 octet count followed by <PRI>.
	// PRI must not have leading zeros (e.g. <0>, <13>, <191>; rejects <007>).
	headerPrefixRegex = regexp.MustCompile(`^(?:(\d+)\s+)?<([1-9]\d{0,2}|0)>`)

	// octetPrefixRegex checks for RFC 6587 octet-counted framing (^<digits> <).
	octetPrefixRegex = regexp.MustCompile(`^(\d+)\s+<`)
)

func cleanHostname(raw string) string {
	raw = strings.TrimSuffix(raw, ":")
	if raw == "" || raw == "-" || len(raw) > 255 {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		// Must be printable ASCII and non-whitespace
		if b < 33 || b > 126 {
			return ""
		}
	}
	return strings.Clone(raw)
}

// Message represents a parsed syslog message.
type Message struct {
	Message      string
	Hostname     string
	WasSanitized bool
}

// MaxMessageBytes is the maximum allowed syslog message size in bytes (64 KiB - 1).
const MaxMessageBytes = 65535

// SplitMessages splits syslog messages based on transport ("udp" or "tcp") and framing.
// For UDP, each datagram represents exactly one message (RFC 5426) and is not split on newlines.
// For TCP, RFC 6587 octet-counted framing or LF delimiters are parsed.
func SplitMessages(data []byte, transport string) [][]byte {
	if len(data) == 0 {
		return nil
	}

	t := strings.ToLower(strings.TrimSpace(transport))
	if t == "" {
		t = "udp"
	}

	// UDP: RFC 5426 specifies that each UDP datagram carries exactly one syslog message.
	// Multi-line payloads (e.g. stack traces) must NOT be split.
	if t == "udp" {
		trimmed := bytes.TrimRight(data, "\r\n\x00")
		if len(trimmed) == 0 {
			return nil
		}
		if len(trimmed) > MaxMessageBytes {
			trimmed = trimmed[:MaxMessageBytes]
		}
		return [][]byte{trimmed}
	}

	// TCP transport: check for RFC 6587 octet-counted framing (^<digits> <)
	if octetPrefixRegex.Match(data) {
		var res [][]byte
		rem := data
		for len(rem) > 0 {
			idxSpace := bytes.IndexByte(rem, ' ')
			if idxSpace == -1 || idxSpace > 10 {
				res = append(res, rem)
				break
			}
			msgLen, err := strconv.Atoi(string(rem[:idxSpace]))
			if err != nil || msgLen <= 0 || msgLen > MaxMessageBytes {
				res = append(res, rem)
				break
			}
			msgStart := idxSpace + 1
			if msgStart >= len(rem) {
				res = append(res, rem)
				break
			}
			if msgStart+msgLen > len(rem) {
				// Octet count exceeds segment size: return non-syslog token to trigger not_syslog
				res = append(res, rem[:idxSpace])
				break
			}
			msg := rem[msgStart : msgStart+msgLen]
			res = append(res, bytes.TrimRight(msg, "\r\n\x00"))
			rem = rem[msgStart+msgLen:]
			rem = bytes.TrimLeft(rem, " \r\n")
		}
		return res
	}

	// TCP non-octet-counted: traditional LF delimiter (RFC 6587 non-transparent framing)
	var res [][]byte
	lines := bytes.Split(data, []byte("\n"))
	for _, l := range lines {
		trimmed := bytes.TrimRight(l, "\r\x00")
		if len(trimmed) > 0 {
			if len(trimmed) > MaxMessageBytes {
				trimmed = trimmed[:MaxMessageBytes]
			}
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
	if len(data) > MaxMessageBytes {
		return nil, fmt.Errorf("message length %d exceeds maximum %d: %w", len(data), MaxMessageBytes, ErrNotSyslog)
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

	var hostname string
	if m := rfc5424Regex.FindSubmatch(payloadBytes); len(m) > 2 {
		hostname = cleanHostname(string(m[2]))
	} else if m := rfc3164Regex.FindSubmatch(payloadBytes); len(m) > 4 {
		hostname = cleanHostname(string(m[4]))
	} else if m := rfc3164ISORegex.FindSubmatch(payloadBytes); len(m) > 4 {
		hostname = cleanHostname(string(m[4]))
	} else if m := ciscoSeqOnlyRegex.FindSubmatch(payloadBytes); len(m) > 3 {
		hostname = cleanHostname(string(m[3]))
	}

	wasSanitized := !utf8.Valid(payloadBytes)
	msg := strings.ToValidUTF8(string(payloadBytes), "\uFFFD")

	return &Message{
		Message:      msg,
		Hostname:     hostname,
		WasSanitized: wasSanitized,
	}, nil
}
