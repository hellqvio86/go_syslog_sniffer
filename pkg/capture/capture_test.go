package capture

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildFrame(t *testing.T, l4 gopacket.SerializableLayer, payload []byte, proto layers.IPProtocol) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: proto,
		SrcIP:    net.IP{192, 168, 1, 100},
		DstIP:    net.IP{192, 168, 1, 1},
	}
	switch v := l4.(type) {
	case *layers.TCP:
		if err := v.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
	case *layers.UDP:
		if err := v.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var err error
	if len(payload) > 0 {
		err = gopacket.SerializeLayers(buf, opts, eth, ip, l4, gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, eth, ip, l4)
	}
	if err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestNextPacket_SyntheticFrames(t *testing.T) {
	tests := []struct {
		name        string
		pkt         gopacket.Packet
		wantPayload string
		wantSrcIP   string
		wantDropped bool
	}{
		{
			name: "pure TCP ACK (no payload)",
			pkt: buildFrame(t, &layers.TCP{
				SrcPort: 514,
				DstPort: 54321,
				ACK:     true,
				Seq:     1000,
				Ack:     2000,
			}, nil, layers.IPProtocolTCP),
			wantDropped: true,
		},
		{
			name: "TCP SYN-ACK (no payload)",
			pkt: buildFrame(t, &layers.TCP{
				SrcPort: 514,
				DstPort: 54321,
				SYN:     true,
				ACK:     true,
				Seq:     1000,
				Ack:     2000,
			}, nil, layers.IPProtocolTCP),
			wantDropped: true,
		},
		{
			name: "empty UDP datagram (no payload)",
			pkt: buildFrame(t, &layers.UDP{
				SrcPort: 54321,
				DstPort: 514,
			}, nil, layers.IPProtocolUDP),
			wantDropped: true,
		},
		{
			name: "UDP datagram with syslog payload",
			pkt: buildFrame(t, &layers.UDP{
				SrcPort: 54321,
				DstPort: 514,
			}, []byte("<13>Hello syslog"), layers.IPProtocolUDP),
			wantPayload: "<13>Hello syslog",
			wantSrcIP:   "192.168.1.100",
			wantDropped: false,
		},
		{
			name: "TCP segment with syslog payload",
			pkt: buildFrame(t, &layers.TCP{
				SrcPort: 54321,
				DstPort: 514,
				PSH:     true,
				ACK:     true,
				Seq:     1000,
				Ack:     2000,
			}, []byte("<14>TCP syslog"), layers.IPProtocolTCP),
			wantPayload: "<14>TCP syslog",
			wantSrcIP:   "192.168.1.100",
			wantDropped: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan gopacket.Packet, 1)
			ch <- tc.pkt
			source := &PcapPacketSource{packets: ch}
			pd, err := source.NextPacket()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantDropped {
				if pd != nil {
					t.Fatalf("expected packet to be dropped (nil), got %+v (data=%q)", pd, string(pd.Data))
				}
			} else {
				if pd == nil {
					t.Fatal("expected packet, got nil")
				}
				if string(pd.Data) != tc.wantPayload {
					t.Errorf("payload mismatch: got %q, want %q", string(pd.Data), tc.wantPayload)
				}
				if pd.SrcIP != tc.wantSrcIP {
					t.Errorf("srcIP mismatch: got %q, want %q", pd.SrcIP, tc.wantSrcIP)
				}
			}
		})
	}
}

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
