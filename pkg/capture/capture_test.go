package capture

import (
	"testing"
)

func TestMockPacketSource(t *testing.T) {
	packets := []*PacketData{
		{Data: []byte("<13>msg1"), SrcIP: "192.168.1.1"},
		{Data: []byte("<13>msg2"), SrcIP: "192.168.1.2"},
	}

	mock := NewMockPacketSource(packets)
	defer mock.Close()

	p1, err := mock.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p1 == nil || string(p1.Data) != "<13>msg1" || p1.SrcIP != "192.168.1.1" {
		t.Errorf("unexpected packet 1: %+v", p1)
	}

	p2, err := mock.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p2 == nil || string(p2.Data) != "<13>msg2" || p2.SrcIP != "192.168.1.2" {
		t.Errorf("unexpected packet 2: %+v", p2)
	}

	p3, err := mock.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p3 != nil {
		t.Errorf("expected nil after exhausting packets, got %+v", p3)
	}
}

func TestNewPcapPacketSource_InvalidInterface(t *testing.T) {
	_, err := NewPcapPacketSource("non_existent_device_xyz123", 514)
	if err == nil {
		t.Fatal("expected error opening non-existent interface, got nil")
	}
}
