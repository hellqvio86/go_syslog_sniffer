package syslog

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
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
			name:        "valid boundary PRI minimum (0)",
			input:       []byte("<0>emergency message"),
			wantValid:   true,
			wantHost:    "",
			wantMessage: "<0>emergency message",
		},
		{
			name:        "valid boundary PRI maximum (191)",
			input:       []byte("<191>local7 debug message"),
			wantValid:   true,
			wantHost:    "",
			wantMessage: "<191>local7 debug message",
		},
		{
			name:        "valid RFC 5424 with long hostname truncated to 255 bytes",
			input:       []byte("<165>1 2003-10-11T22:14:15.003Z " + strings.Repeat("a", 300) + " app 1 - - log"),
			wantValid:   true,
			wantHost:    strings.Repeat("a", 255),
			wantMessage: "<165>1 2003-10-11T22:14:15.003Z " + strings.Repeat("a", 300) + " app 1 - - log",
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
			name:      "rejected boundary PRI exceeded (192)",
			input:     []byte("<192>Oct 11 22:14:15 evil x: y"),
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
	if !pkt.WasSanitized {
		t.Errorf("expected WasSanitized to be true")
	}
}

func TestSplitMessages(t *testing.T) {
	input := []byte("<13>msg1\n<13>msg2\r\n\n<13>msg3\n")
	msgs := SplitMessages(input)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
	if string(msgs[0]) != "<13>msg1" {
		t.Errorf("expected msg1, got %q", string(msgs[0]))
	}
	if string(msgs[1]) != "<13>msg2" {
		t.Errorf("expected msg2, got %q", string(msgs[1]))
	}
	if string(msgs[2]) != "<13>msg3" {
		t.Errorf("expected msg3, got %q", string(msgs[2]))
	}
}

func FuzzParseSyslogPacket(f *testing.F) {
	seeds := [][]byte{
		[]byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - An application log entry"),
		[]byte("<13>Oct 11 22:14:15 myhost su: 'su root' failed"),
		[]byte("<13>2026-11-07T12:00:00+01:00 myhost app: msg"),
		[]byte("79 <165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - A message"),
		[]byte("<13>Oct 11 22:14:15 h app: caf\xc3"),
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("<999>invalid pri"),
		[]byte("<0>test"),
		[]byte("<191>boundary pri"),
		[]byte("<192>exceeded pri"),
		[]byte("<165>1 2026-11-07T12:00:00Z - app 1 - - msg"),
		[]byte(""),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := ParseSyslogPacket(data)
		if err != nil {
			if msg != nil {
				t.Fatalf("expected nil message on error, got %+v", msg)
			}
			return
		}

		if msg == nil {
			t.Fatal("expected non-nil message when err is nil")
		}

		if !utf8.ValidString(msg.Message) {
			t.Fatalf("msg.Message is not valid UTF-8: %q", msg.Message)
		}

		if !utf8.ValidString(msg.Hostname) {
			t.Fatalf("msg.Hostname is not valid UTF-8: %q", msg.Hostname)
		}

		b, err := json.Marshal(msg)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}

		var decoded Message
		if err := json.Unmarshal(b, &decoded); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}

		if decoded.Message != msg.Message || decoded.Hostname != msg.Hostname || decoded.WasSanitized != msg.WasSanitized {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", decoded, msg)
		}
	})
}

func FuzzParse(f *testing.F) {
	FuzzParseSyslogPacket(f)
}

func BenchmarkParseSyslogPacket_RFC5424(b *testing.B) {
	data := []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - An application log entry")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSyslogPacket(data)
	}
}

func BenchmarkParseSyslogPacket_RFC3164(b *testing.B) {
	data := []byte("<13>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick on /dev/pts/8")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSyslogPacket(data)
	}
}
