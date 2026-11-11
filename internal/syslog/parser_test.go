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
			name:        "valid RFC 3164 with year",
			input:       []byte("<13>Oct 11 2026 22:14:15 myhost sshd: login"),
			wantValid:   true,
			wantHost:    "myhost",
			wantMessage: "<13>Oct 11 2026 22:14:15 myhost sshd: login",
		},
		{
			name:        "valid RFC 3164 with fractional seconds",
			input:       []byte("<13>Oct 11 22:14:15.123 myhost sshd: login"),
			wantValid:   true,
			wantHost:    "myhost",
			wantMessage: "<13>Oct 11 22:14:15.123 myhost sshd: login",
		},
		{
			name:        "valid RFC 3164 with Cisco asterisk NTP marker and colon",
			input:       []byte("<189>*Oct 11 22:14:15.123: router1 %SYS-5: configured"),
			wantValid:   true,
			wantHost:    "router1",
			wantMessage: "<189>*Oct 11 22:14:15.123: router1 %SYS-5: configured",
		},
		{
			name:        "valid RFC 3164 with Cisco dot NTP marker",
			input:       []byte("<189>.Oct 11 22:14:15 router1 sshd: msg"),
			wantValid:   true,
			wantHost:    "router1",
			wantMessage: "<189>.Oct 11 22:14:15 router1 sshd: msg",
		},
		{
			name:        "valid Cisco sequence number prefix",
			input:       []byte("<189>1234: *Oct 11 22:14:15.123: router1 %SYS-5: configured"),
			wantValid:   true,
			wantHost:    "router1",
			wantMessage: "<189>1234: *Oct 11 22:14:15.123: router1 %SYS-5: configured",
		},
		{
			name:        "valid Cisco sequence number only without timestamp",
			input:       []byte("<189>1234: router1 sshd: msg"),
			wantValid:   true,
			wantHost:    "router1",
			wantMessage: "<189>1234: router1 sshd: msg",
		},
		{
			name:      "rejected PRI with leading zero <007>",
			input:     []byte("<007>Oct 11 22:14:15 host msg"),
			wantValid: false,
			wantErr:   ErrNotSyslog,
		},
		{
			name:      "rejected PRI with leading zero <01>",
			input:     []byte("<01>Oct 11 22:14:15 host msg"),
			wantValid: false,
			wantErr:   ErrNotSyslog,
		},
		{
			name:        "RFC 5424 version 2 has no claimed hostname from 5424",
			input:       []byte("<165>2 2003-10-11T22:14:15.003Z myhost app 1 - - log"),
			wantValid:   true,
			wantHost:    "",
			wantMessage: "<165>2 2003-10-11T22:14:15.003Z myhost app 1 - - log",
		},
		{
			name:        "valid RFC 5424 with long hostname rejected (>255 bytes)",
			input:       []byte("<165>1 2003-10-11T22:14:15.003Z " + strings.Repeat("a", 300) + " app 1 - - log"),
			wantValid:   true,
			wantHost:    "",
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
			pkt, err := Parse(tc.input)
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
	pkt, err := Parse(data)
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
	pkt, err := Parse(data)
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
	msgs := SplitMessages(input, "tcp")
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

	udpInput := []byte("<13>msg1\nstack line 1\nstack line 2\r\n")
	udpMsgs := SplitMessages(udpInput, "udp")
	if len(udpMsgs) != 1 {
		t.Fatalf("expected 1 message for UDP datagram, got %d", len(udpMsgs))
	}
	if string(udpMsgs[0]) != "<13>msg1\nstack line 1\nstack line 2" {
		t.Errorf("unexpected UDP message: %q", string(udpMsgs[0]))
	}
}

func TestSplitMessages_F1_Table(t *testing.T) {
	tests := []struct {
		name         string
		transport    string
		payload      []byte
		wantMessages int
		wantValid    int
		wantIgnored  int
	}{
		{
			name:         "UDP multi-line datagram (1 message, 0 ignored)",
			transport:    "udp",
			payload:      []byte("<13>Oct 11 22:14:15 host1 stack trace line 1\nline 2\nline 3"),
			wantMessages: 1,
			wantValid:    1,
			wantIgnored:  0,
		},
		{
			name:         "TCP two octet-counted frames in one segment (2 messages)",
			transport:    "tcp",
			payload:      []byte("28 <13>Oct 11 22:14:15 host1 m128 <13>Oct 11 22:14:16 host1 m2"),
			wantMessages: 2,
			wantValid:    2,
			wantIgnored:  0,
		},
		{
			name:         "TCP octet length longer than payload (ignored)",
			transport:    "tcp",
			payload:      []byte("100 <13>Oct 11 22:14:15 host1 short"),
			wantMessages: 1,
			wantValid:    0,
			wantIgnored:  1,
		},
		{
			name:         "TCP LF-framed three messages (3)",
			transport:    "tcp",
			payload:      []byte("<13>Oct 11 22:14:15 host1 m1\n<13>Oct 11 22:14:16 host1 m2\n<13>Oct 11 22:14:17 host1 m3\n"),
			wantMessages: 3,
			wantValid:    3,
			wantIgnored:  0,
		},
		{
			name:         "UDP with trailing NUL byte",
			transport:    "udp",
			payload:      []byte("<13>Oct 11 22:14:15 host1 m1\x00"),
			wantMessages: 1,
			wantValid:    1,
			wantIgnored:  0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msgs := SplitMessages(tc.payload, tc.transport)
			if len(msgs) != tc.wantMessages {
				t.Fatalf("expected %d messages from SplitMessages, got %d", tc.wantMessages, len(msgs))
			}
			valid := 0
			ignored := 0
			for _, m := range msgs {
				_, err := Parse(m)
				if err == nil {
					valid++
				} else {
					ignored++
				}
			}
			if valid != tc.wantValid {
				t.Errorf("expected %d valid messages, got %d", tc.wantValid, valid)
			}
			if ignored != tc.wantIgnored {
				t.Errorf("expected %d ignored messages, got %d", tc.wantIgnored, ignored)
			}
		})
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
		[]byte("<13>Oct 11 2026 22:14:15 myhost sshd: login"),
		[]byte("<189>*Oct 11 22:14:15.123: router1 %SYS-5: configured"),
		[]byte("<189>1234: *Oct 11 22:14:15.123: router1 %SYS-5: configured"),
		[]byte("<189>1234: router1 sshd: msg"),
		[]byte("<007>invalid leading zero"),
		[]byte(""),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := Parse(data)
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

func FuzzSplitMessages(f *testing.F) {
	seeds := [][]byte{
		[]byte("19 <13>hello world 123"),
		[]byte("9999999999999 <13>huge length"),
		[]byte("0000000010 <13>leading zero"),
		[]byte("-5 <13>negative length"),
		[]byte("0 <13>zero length"),
		[]byte("100 <13>truncated"),
		[]byte("<13>line 1\n<14>line 2\n<15>line 3"),
		[]byte("<13>no delimiter at all"),
		[]byte(strings.Repeat("A", 70000)),
		[]byte("18446744073709551615 <13>overflow"),
	}
	for _, seed := range seeds {
		f.Add(seed, "tcp")
		f.Add(seed, "udp")
	}

	f.Fuzz(func(t *testing.T, data []byte, transport string) {
		msgs := SplitMessages(data, transport)
		for _, m := range msgs {
			if len(m) > MaxMessageBytes {
				t.Fatalf("split message length %d exceeds MaxMessageBytes %d", len(m), MaxMessageBytes)
			}
			// Must not panic on parse
			_, _ = Parse(m)
		}
	})
}

func BenchmarkParseSyslogPacket_RFC5424(b *testing.B) {
	data := []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - An application log entry")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(data)
	}
}

func BenchmarkParseSyslogPacket_RFC3164(b *testing.B) {
	data := []byte("<13>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick on /dev/pts/8")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Parse(data)
	}
}
