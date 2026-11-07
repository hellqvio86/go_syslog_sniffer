package testutil

import (
	"io"
	"net/netip"
	"testing"

	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
)

func TestMockPacketSource(t *testing.T) {
	packets := []*capture.PacketData{
		{Data: []byte("<13>msg1"), SrcIP: netip.MustParseAddr("192.168.1.1")},
		{Data: []byte("<13>msg2"), SrcIP: netip.MustParseAddr("192.168.1.2")},
	}

	mock := NewMockPacketSource(packets)
	defer mock.Close()

	p1, err := mock.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 == nil || string(p1.Data) != "<13>msg1" || p1.SrcIP.String() != "192.168.1.1" {
		t.Errorf("unexpected packet 1: %+v", p1)
	}

	p2, err := mock.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p2 == nil || string(p2.Data) != "<13>msg2" || p2.SrcIP.String() != "192.168.1.2" {
		t.Errorf("unexpected packet 2: %+v", p2)
	}

	p3, err := mock.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p3 != nil {
		t.Errorf("expected nil after exhausting packets, got %+v", p3)
	}

	// Test ReturnEOFOnExhaust
	mockEOF := NewMockPacketSource(nil)
	mockEOF.ReturnEOFOnExhaust = true
	_, errEOF := mockEOF.NextPacket()
	if errEOF != io.EOF {
		t.Errorf("expected io.EOF, got %v", errEOF)
	}

	// Test Stats
	mock.MockStats = &capture.Stats{
		PacketsReceived: 42,
		PacketsDropped:  2,
	}
	st, err := mock.Stats()
	if err != nil {
		t.Fatalf("unexpected stats error: %v", err)
	}
	if st == nil || st.PacketsReceived != 42 || st.PacketsDropped != 2 {
		t.Errorf("unexpected stats: %+v", st)
	}
}
