package syslog

import (
	"errors"
	"testing"
)

func TestParseSyslogPacket_Table(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		wantValid   bool
		wantErr     error
		wantHost    string
		wantMessage string
	}{
		{
			name:        "valid RFC 5424",
			input:       []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - An application log entry"),
			wantValid:   true,
			wantHost:    "mymachine.example.com",
			wantMessage: "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - An application log entry",
		},
		{
			name:        "valid RFC 3164",
			input:       []byte("<13>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick on /dev/pts/8"),
			wantValid:   true,
			wantHost:    "myhost",
			wantMessage: "<13>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick on /dev/pts/8",
		},
		{
			name:        "valid octet-counted RFC 6587",
			input:       []byte("79 <165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - A message"),
			wantValid:   true,
			wantHost:    "mymachine.example.com",
			wantMessage: "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - A message",
		},
		{
			name:        "valid RFC 5424 with NILVALUE hostname -",
			input:       []byte("<165>1 2026-11-07T12:00:00Z - app 1 - - msg"),
			wantValid:   true,
			wantHost:    "",
			wantMessage: "<165>1 2026-11-07T12:00:00Z - app 1 - - msg",
		},
		{
			name:        "valid RFC 3164 with ISO-8601 high-precision timestamp",
			input:       []byte("<13>2026-11-07T12:00:00+01:00 myhost app: msg"),
			wantValid:   true,
			wantHost:    "myhost",
			wantMessage: "<13>2026-11-07T12:00:00+01:00 myhost app: msg",
		},
		{
			name:        "valid basic PRI only",
			input:       []byte("<13>Hello world"),
			wantValid:   true,
			wantHost:    "",
			wantMessage: "<13>Hello world",
		},
		{
			name:      "rejected HTTP GET",
			input:     []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantValid: false,
			wantErr:   ErrNotSyslog,
		},
		{
			name:      "rejected PRI out of range (>191)",
			input:     []byte("<999>Oct 11 22:14:15 evil x: y"),
			wantValid: false,
			wantErr:   ErrNotSyslog,
		},
		{
			name:      "rejected text with < in the middle",
			input:     []byte("some text <13>Oct 11 22:14:15 server1 sshd: login"),
			wantValid: false,
			wantErr:   ErrNotSyslog,
		},
		{
			name:      "rejected empty payload",
			input:     []byte{},
			wantValid: false,
			wantErr:   ErrEmpty,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pkt, err := ParseSyslogPacket(tc.input)
			if tc.wantValid {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if pkt == nil {
					t.Fatal("expected non-nil packet")
				}
				if pkt.Hostname != tc.wantHost {
					t.Errorf("hostname mismatch: got %q, want %q", pkt.Hostname, tc.wantHost)
				}
				if pkt.Message != tc.wantMessage {
					t.Errorf("message mismatch: got %q, want %q", pkt.Message, tc.wantMessage)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error, got nil packet=%+v", pkt)
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				if pkt != nil {
					t.Errorf("expected nil packet, got %+v", pkt)
				}
			}
		})
	}
}

func TestParseWithTrailingNewline(t *testing.T) {
	data := []byte("<165>1 2026-11-07T12:00:00.000Z myhost.net app 1 - - Log message\n")
	pkt, err := ParseSyslogPacket(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pkt == nil {
		t.Fatal("expected packet, got nil")
	}
	if pkt.Hostname != "myhost.net" {
		t.Errorf("expected hostname 'myhost.net', got %q", pkt.Hostname)
	}
	if pkt.Message != "<165>1 2026-11-07T12:00:00.000Z myhost.net app 1 - - Log message\n" {
		t.Errorf("expected original message preserved with newline, got %q", pkt.Message)
	}
}

func TestParseNonUTF8_Sanitized(t *testing.T) {
	// Probe test case: truncated mid-multibyte sequence (\xc3)
	data := []byte("<13>Oct 11 22:14:15 h app: caf\xc3")
	pkt, err := ParseSyslogPacket(data)
	if err != nil {
		t.Fatalf("unexpected error for non-UTF-8 syslog: %v", err)
	}
	if pkt == nil {
		t.Fatal("expected packet to be counted/parsed, got nil")
	}
	if pkt.Hostname != "h" {
		t.Errorf("expected hostname 'h', got %q", pkt.Hostname)
	}
	wantMessage := "<13>Oct 11 22:14:15 h app: caf\uFFFD"
	if pkt.Message != wantMessage {
		t.Errorf("expected sanitized message %q, got %q", wantMessage, pkt.Message)
	}
}
