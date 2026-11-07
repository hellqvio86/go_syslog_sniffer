package syslog

import (
	"testing"
)

func TestParseValidSyslog(t *testing.T) {
	data := []byte("<13>Hello world")
	pkt := ParseSyslogPacket(data)
	if pkt == nil {
		t.Fatal("expected packet, got nil")
	}
	if pkt.Message != "<13>Hello world" {
		t.Errorf("expected message '<13>Hello world', got %q", pkt.Message)
	}
	if pkt.Hostname != "" {
		t.Errorf("expected empty hostname, got %q", pkt.Hostname)
	}
}

func TestParseEmpty(t *testing.T) {
	pkt := ParseSyslogPacket([]byte{})
	if pkt != nil {
		t.Fatalf("expected nil for empty packet, got %+v", pkt)
	}
}

func TestParseInvalidUTF8(t *testing.T) {
	data := []byte{0xff, 0xff, 0xff}
	pkt := ParseSyslogPacket(data)
	if pkt != nil {
		t.Fatalf("expected nil for invalid UTF-8, got %+v", pkt)
	}
}

func TestParseNoHostname(t *testing.T) {
	data := []byte("Simple message without pri")
	pkt := ParseSyslogPacket(data)
	if pkt == nil {
		t.Fatal("expected packet, got nil")
	}
	if pkt.Message != "Simple message without pri" {
		t.Errorf("expected message, got %q", pkt.Message)
	}
	if pkt.Hostname != "" {
		t.Errorf("expected empty hostname, got %q", pkt.Hostname)
	}
}

func TestParseRFC5424(t *testing.T) {
	data := []byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - An application log entry")
	pkt := ParseSyslogPacket(data)
	if pkt == nil {
		t.Fatal("expected packet, got nil")
	}
	if pkt.Hostname != "mymachine.example.com" {
		t.Errorf("expected hostname 'mymachine.example.com', got %q", pkt.Hostname)
	}
}

func TestParseRFC3164(t *testing.T) {
	data := []byte("<13>Oct 11 22:14:15 myhost su: 'su root' failed for lonvick on /dev/pts/8")
	pkt := ParseSyslogPacket(data)
	if pkt == nil {
		t.Fatal("expected packet, got nil")
	}
	if pkt.Hostname != "myhost" {
		t.Errorf("expected hostname 'myhost', got %q", pkt.Hostname)
	}
}

func TestParseWithTrailingNewline(t *testing.T) {
	data := []byte("<165>1 2026-11-07T12:00:00.000Z myhost.net app 1 - - Log message\n")
	pkt := ParseSyslogPacket(data)
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

func TestParseWithPrefixGarbage(t *testing.T) {
	data := []byte("SOME_RANDOM_HEADERS_<13>Oct 11 22:14:15 server1 sshd: login")
	pkt := ParseSyslogPacket(data)
	if pkt == nil {
		t.Fatal("expected packet, got nil")
	}
	if pkt.Hostname != "server1" {
		t.Errorf("expected hostname 'server1', got %q", pkt.Hostname)
	}
	if pkt.Message != "<13>Oct 11 22:14:15 server1 sshd: login" {
		t.Errorf("expected trimmed message, got %q", pkt.Message)
	}
}
