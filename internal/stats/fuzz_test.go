package stats

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/hellqvio86/go_syslog_sniffer/internal/syslog"
)

func FuzzFramingAndStats(f *testing.F) {
	seeds := [][]byte{
		[]byte("<165>1 2003-10-11T22:14:15.003Z mymachine.example.com appname 1234 ID47 - An application log entry"),
		[]byte("<13>Oct 11 22:14:15 myhost su: 'su root' failed"),
		[]byte("34 <13>Oct 11 22:14:15 myhost su: failed34 <13>Oct 11 22:14:16 myhost su: failed"),
		[]byte("<13>Oct 11 22:14:15 myhost msg 1\n<13>Oct 11 22:14:16 myhost msg 2\n"),
		[]byte("<189>1234: *Oct 11 22:14:15.123: %SYS-5-CONFIG_I: Configured"),
		[]byte("GET / HTTP/1.1\r\n"),
		{0x16, 0x03, 0x01, 0x00, 0x50},
		{},
	}
	for _, seed := range seeds {
		f.Add(seed, "udp")
		f.Add(seed, "tcp")
	}

	f.Fuzz(func(t *testing.T, data []byte, transport string) {
		const maxHosts = 50
		const sampleBytes = 128
		tracker := NewTrackerWithOptions(maxHosts, sampleBytes, false, false)

		msgs := syslog.SplitMessages(data, transport)
		dummyIP := netip.MustParseAddr("192.168.1.1")

		for _, m := range msgs {
			if len(m) == 0 {
				continue
			}
			msg, err := syslog.Parse(m)
			if err != nil {
				tracker.RecordIgnoredNotSyslog()
				continue
			}
			tracker.AddEntry(dummyIP, msg.Hostname, msg.Message)
		}

		summary := tracker.GetSummary(10)
		if len(summary.Hosts) > maxHosts {
			t.Fatalf("hosts %d exceeded maxHosts %d", len(summary.Hosts), maxHosts)
		}
		for _, h := range summary.Hosts {
			if len(h.Sample) > sampleBytes {
				t.Fatalf("sample length %d exceeded sampleBytes %d", len(h.Sample), sampleBytes)
			}
		}

		b, err := json.Marshal(summary)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		var unmarshaled JSONSummary
		if err := json.Unmarshal(b, &unmarshaled); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
	})
}
