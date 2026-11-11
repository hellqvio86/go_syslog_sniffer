package capture

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
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

func buildIPv6Frame(t *testing.T, l4 gopacket.SerializableLayer, payload []byte, proto layers.IPProtocol) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: proto,
		SrcIP:      net.ParseIP("2001:db8::42"),
		DstIP:      net.ParseIP("2001:db8::1"),
	}
	switch v := l4.(type) {
	case *layers.TCP:
		if err := v.SetNetworkLayerForChecksum(ip6); err != nil {
			t.Fatal(err)
		}
	case *layers.UDP:
		if err := v.SetNetworkLayerForChecksum(ip6); err != nil {
			t.Fatal(err)
		}
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	var err error
	if len(payload) > 0 {
		err = gopacket.SerializeLayers(buf, opts, eth, ip6, l4, gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, eth, ip6, l4)
	}
	if err != nil {
		t.Fatal(err)
	}
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func buildVLANFrame(t *testing.T, l4 gopacket.SerializableLayer, payload []byte, proto layers.IPProtocol) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeDot1Q,
	}
	dot1q := &layers.Dot1Q{
		VLANIdentifier: 100,
		Priority:       0,
		Type:           layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: proto,
		SrcIP:    net.IP{10, 0, 100, 50},
		DstIP:    net.IP{10, 0, 100, 1},
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
		err = gopacket.SerializeLayers(buf, opts, eth, dot1q, ip, l4, gopacket.Payload(payload))
	} else {
		err = gopacket.SerializeLayers(buf, opts, eth, dot1q, ip, l4)
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
			}, []byte("<14>TCP syslog\n"), layers.IPProtocolTCP),
			wantPayload: "<14>TCP syslog",
			wantSrcIP:   "192.168.1.100",
			wantDropped: false,
		},
		{
			name: "IPv6 UDP datagram with syslog payload",
			pkt: buildIPv6Frame(t, &layers.UDP{
				SrcPort: 54321,
				DstPort: 514,
			}, []byte("<165>IPv6 syslog"), layers.IPProtocolUDP),
			wantPayload: "<165>IPv6 syslog",
			wantSrcIP:   "2001:db8::42",
			wantDropped: false,
		},
		{
			name: "IPv6 TCP pure ACK (no payload)",
			pkt: buildIPv6Frame(t, &layers.TCP{
				SrcPort: 514,
				DstPort: 54321,
				ACK:     true,
				Seq:     1000,
				Ack:     2000,
			}, nil, layers.IPProtocolTCP),
			wantDropped: true,
		},
		{
			name: "802.1Q VLAN tagged UDP syslog frame",
			pkt: buildVLANFrame(t, &layers.UDP{
				SrcPort: 54321,
				DstPort: 514,
			}, []byte("<13>VLAN syslog"), layers.IPProtocolUDP),
			wantPayload: "<13>VLAN syslog",
			wantSrcIP:   "10.0.100.50",
			wantDropped: false,
		},
		{
			name: "802.1Q VLAN tagged TCP pure ACK frame (no payload)",
			pkt: buildVLANFrame(t, &layers.TCP{
				SrcPort: 514,
				DstPort: 54321,
				ACK:     true,
				Seq:     1000,
				Ack:     2000,
			}, nil, layers.IPProtocolTCP),
			wantDropped: true,
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
				if pd != nil && !pd.NoPayload {
					t.Fatalf("expected packet to be dropped (no payload), got %+v (data=%q)", pd, string(pd.Data))
				}
			} else {
				if pd == nil {
					t.Fatal("expected packet, got nil")
				}
				if string(pd.Data) != tc.wantPayload {
					t.Errorf("payload mismatch: got %q, want %q", string(pd.Data), tc.wantPayload)
				}
				if pd.SrcIP.String() != tc.wantSrcIP {
					t.Errorf("srcIP mismatch: got %q, want %q", pd.SrcIP.String(), tc.wantSrcIP)
				}
			}
		})
	}
}

func TestNextPacket_ChannelClosed(t *testing.T) {
	ch := make(chan gopacket.Packet, 1)
	close(ch)
	source := &PcapPacketSource{packets: ch}
	pd, err := source.NextPacket()
	if err == nil {
		t.Fatalf("expected error on closed channel, got nil (pd=%+v)", pd)
	}
	if err != os.ErrDeadlineExceeded && err.Error() != "capture closed" && err.Error() != "EOF" {
		t.Logf("got error: %v", err)
	}
}

func TestNewPcapPacketSource_InvalidInterface(t *testing.T) {
	_, err := NewPcapPacketSourceMultiPort("non_existent_device_xyz123", []int{514}, "dst", false)
	if err == nil {
		t.Fatal("expected error opening non-existent interface, got nil")
	}
	devs, findErr := pcap.FindAllDevs()
	if findErr == nil && len(devs) > 0 {
		if !strings.Contains(err.Error(), "available interfaces:") {
			t.Errorf("expected error message to contain available interfaces list, got: %v", err)
		}
	}
}

func TestBuildBPFFilter(t *testing.T) {
	tests := []struct {
		name      string
		direction string
		ports     []int
		want      string
	}{
		{
			name:      "default dst single port",
			direction: "dst",
			ports:     []int{514},
			want:      "(dst port 514) or (vlan and dst port 514)",
		},
		{
			name:      "empty direction defaults to dst",
			direction: "",
			ports:     []int{514},
			want:      "(dst port 514) or (vlan and dst port 514)",
		},
		{
			name:      "src single port",
			direction: "src",
			ports:     []int{514},
			want:      "(src port 514) or (vlan and src port 514)",
		},
		{
			name:      "both directions single port",
			direction: "both",
			ports:     []int{514},
			want:      "(port 514) or (vlan and port 514)",
		},
		{
			name:      "dst multiple ports",
			direction: "dst",
			ports:     []int{514, 601},
			want:      "((dst port 514 or dst port 601)) or (vlan and (dst port 514 or dst port 601))",
		},
		{
			name:      "both multiple ports",
			direction: "both",
			ports:     []int{514, 601},
			want:      "((port 514 or port 601)) or (vlan and (port 514 or port 601))",
		},
		{
			name:      "empty ports defaults to 514",
			direction: "dst",
			ports:     nil,
			want:      "(dst port 514) or (vlan and dst port 514)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildBPFFilter(tc.direction, tc.ports...)
			if got != tc.want {
				t.Errorf("BuildBPFFilter(%q, %v) = %q, want %q", tc.direction, tc.ports, got, tc.want)
			}
			// Verify with libpcap that the generated BPF filter expression compiles cleanly
			insns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, defaultSnapLen, got)
			if err != nil {
				t.Fatalf("failed to compile BPF filter %q: %v", got, err)
			}
			if len(insns) == 0 {
				t.Errorf("compiled BPF filter returned empty instructions for %q", got)
			}
		})
	}
}

func TestNextPacket_TCPHandshakeAndData(t *testing.T) {
	clientIP := net.IP{192, 168, 1, 100}
	serverIP := net.IP{192, 168, 1, 1}

	buildDirectionalFrame := func(src, dst net.IP, l4 gopacket.SerializableLayer, payload []byte) gopacket.Packet {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    src,
			DstIP:    dst,
		}
		if tcp, ok := l4.(*layers.TCP); ok {
			if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
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

	// 1. Client -> Server SYN (Seq = 1000)
	syn := buildDirectionalFrame(clientIP, serverIP, &layers.TCP{SrcPort: 54321, DstPort: 514, SYN: true, Seq: 1000}, nil)
	// 2. Server -> Client SYN-ACK (Seq = 2000, Ack = 1001)
	synAck := buildDirectionalFrame(serverIP, clientIP, &layers.TCP{SrcPort: 514, DstPort: 54321, SYN: true, ACK: true, Seq: 2000, Ack: 1001}, nil)
	// 3. Client -> Server ACK (Seq = 1001, Ack = 2001)
	ack := buildDirectionalFrame(clientIP, serverIP, &layers.TCP{SrcPort: 54321, DstPort: 514, ACK: true, Seq: 1001, Ack: 2001}, nil)
	// 4. Client -> Server DATA (syslog payload, Seq = 1001, Ack = 2001)
	data := buildDirectionalFrame(clientIP, serverIP, &layers.TCP{SrcPort: 54321, DstPort: 514, PSH: true, ACK: true, Seq: 1001, Ack: 2001}, []byte("<13>Hello from client\n"))
	// 5. Server -> Client ACK (Seq = 2001, Ack = 1024)
	serverAck := buildDirectionalFrame(serverIP, clientIP, &layers.TCP{SrcPort: 514, DstPort: 54321, ACK: true, Seq: 2001, Ack: 1024}, nil)

	frames := []gopacket.Packet{syn, synAck, ack, data, serverAck}
	ch := make(chan gopacket.Packet, len(frames))
	for _, f := range frames {
		ch <- f
	}

	source := &PcapPacketSource{packets: ch}
	var received []*PacketData

	for i := 0; i < len(frames); i++ {
		pd, err := source.NextPacket()
		if err != nil {
			t.Fatalf("unexpected error at packet %d: %v", i, err)
		}
		if pd != nil && !pd.NoPayload {
			received = append(received, pd)
		}
	}

	// Only the sender data packet should be received
	if len(received) != 1 {
		t.Fatalf("expected exactly 1 packet received, got %d", len(received))
	}
	if received[0].SrcIP.String() != clientIP.String() {
		t.Errorf("expected SrcIP %q, got %q", clientIP.String(), received[0].SrcIP.String())
	}
	if string(received[0].Data) != "<13>Hello from client" {
		t.Errorf("expected payload '<13>Hello from client', got %q", string(received[0].Data))
	}
}

func TestPcapPacketSource_StatsAndClose(t *testing.T) {
	// 1. PcapPacketSource with nil handle returns nil stats without error
	p := &PcapPacketSource{}
	st, err := p.Stats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st != nil {
		t.Errorf("expected nil stats for nil handle, got %+v", st)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestNewOfflinePacketSource(t *testing.T) {
	// 1. Invalid file path returns error
	_, err := NewOfflinePacketSource("non_existent_file.pcap", 514, "dst")
	if err == nil {
		t.Fatal("expected error opening non-existent pcap file, got nil")
	}

	// 2. Valid pcap file created with pcapgo
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create temp pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write pcap header: %v", err)
	}

	// Write UDP syslog packet
	udpPkt := buildFrame(t, &layers.UDP{SrcPort: 54321, DstPort: 514}, []byte("<13>Oct 11 22:14:15 host app: offline test"), layers.IPProtocolUDP)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(udpPkt.Data()),
		Length:        len(udpPkt.Data()),
	}
	if err := w.WritePacket(ci, udpPkt.Data()); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write packet to pcap: %v", err)
	}
	_ = f.Close()

	// Open offline source
	offlineSource, err := NewOfflinePacketSource(pcapPath, 514, "dst")
	if err != nil {
		t.Fatalf("failed to open offline source: %v", err)
	}
	defer func() {
		_ = offlineSource.Close()
	}()

	pd, err := offlineSource.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error reading offline packet: %v", err)
	}
	if pd == nil {
		t.Fatal("expected packet data, got nil")
	}
	if string(pd.Data) != "<13>Oct 11 22:14:15 host app: offline test" {
		t.Errorf("unexpected offline packet payload: %q", string(pd.Data))
	}
	if pd.SrcIP.String() != "192.168.1.100" {
		t.Errorf("unexpected offline packet src ip: %q", pd.SrcIP.String())
	}

	// Next packet should return io.EOF (channel closed on file end)
	pd2, err := offlineSource.NextPacket()
	if err == nil && pd2 != nil {
		t.Errorf("expected EOF or nil after single packet file, got %+v", pd2)
	}
}

func TestNewOfflinePacketSource_VLAN(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "vlan_test.pcap")

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create temp pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write pcap header: %v", err)
	}

	vlanPkt := buildVLANFrame(t, &layers.UDP{SrcPort: 54321, DstPort: 514}, []byte("<13>Oct 11 22:14:15 host app: vlan syslog"), layers.IPProtocolUDP)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(vlanPkt.Data()),
		Length:        len(vlanPkt.Data()),
	}
	if err := w.WritePacket(ci, vlanPkt.Data()); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write packet to pcap: %v", err)
	}
	_ = f.Close()

	offlineSource, err := NewOfflinePacketSource(pcapPath, 514, "dst")
	if err != nil {
		t.Fatalf("failed to open offline source: %v", err)
	}
	defer func() { _ = offlineSource.Close() }()

	pd, err := offlineSource.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error reading offline vlan packet: %v", err)
	}
	if pd == nil {
		t.Fatal("expected packet data for vlan frame, got nil")
	}
	if string(pd.Data) != "<13>Oct 11 22:14:15 host app: vlan syslog" {
		t.Errorf("unexpected payload: %q", string(pd.Data))
	}
	if pd.SrcIP.String() != "10.0.100.50" {
		t.Errorf("unexpected src ip: %q", pd.SrcIP.String())
	}
}

func TestNewOfflinePacketSource_MultiPortSecondPortOnly(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "multiport_test.pcap")

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create temp pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write pcap header: %v", err)
	}

	// Packet sent to port 6514 only (second port of [514, 6514])
	pkt := buildFrame(t, &layers.UDP{SrcPort: 54321, DstPort: 6514}, []byte("<13>Oct 11 22:14:15 host app: port 6514"), layers.IPProtocolUDP)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(pkt.Data()),
		Length:        len(pkt.Data()),
	}
	if err := w.WritePacket(ci, pkt.Data()); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write packet: %v", err)
	}
	_ = f.Close()

	src, err := NewOfflinePacketSourceMultiPort(pcapPath, []int{514, 6514}, "dst")
	if err != nil {
		t.Fatalf("failed to open offline multiport: %v", err)
	}
	defer func() { _ = src.Close() }()

	pd, err := src.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pd == nil {
		t.Fatal("expected packet on second port 6514, got nil")
	}
	if string(pd.Data) != "<13>Oct 11 22:14:15 host app: port 6514" {
		t.Errorf("unexpected payload: %q", string(pd.Data))
	}
}

func TestDecodeError_TruncatedFrame(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "truncated.pcap")

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write header: %v", err)
	}

	// Valid Ethernet (14 bytes) + IPv4 (20 bytes) + partial UDP (4 bytes: src port 54321, dst port 514)
	// BPF checks bytes up to dst port 514 and matches!
	// But gopacket fails to decode full UDP header (requires 8 bytes), creating an ErrorLayer.
	badFrame := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x08, 0x00, // IPv4
		0x45, 0x00, 0x00, 0x30, // Version 4, IHL 5, Total Length 48
		0x00, 0x01, 0x00, 0x00, // ID, flags
		0x40, 0x11, 0x00, 0x00, // TTL 64, Protocol UDP (17), checksum 0
		0x0a, 0x00, 0x00, 0x01, // Src IP 10.0.0.1
		0x0a, 0x00, 0x00, 0x02, // Dst IP 10.0.0.2
		0xd4, 0x31, 0x02, 0x02, // SrcPort 54321, DstPort 514 (only 4 bytes of UDP instead of 8)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(badFrame),
		Length:        len(badFrame) + 10,
	}
	if err := w.WritePacket(ci, badFrame); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write bad packet: %v", err)
	}
	_ = f.Close()

	src, err := NewOfflinePacketSource(pcapPath, 514, "both")
	if err != nil {
		t.Fatalf("failed to open pcap: %v", err)
	}
	defer func() { _ = src.Close() }()

	pd, err := src.NextPacket()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !pd.DecodeError {
		t.Errorf("expected DecodeError true, got false")
	}
}

func TestUnsupportedLinkType(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "unsupported_linktype.pcap")

	f, err := os.Create(pcapPath)
	if err != nil {
		t.Fatalf("failed to create pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	// LinkTypeFDDI is 10, not in supported list
	if err := w.WriteFileHeader(65535, layers.LinkType(10)); err != nil {
		_ = f.Close()
		t.Fatalf("failed to write header: %v", err)
	}
	_ = f.Close()

	_, err = NewOfflinePacketSource(pcapPath, 514, "dst")
	if err == nil {
		t.Fatal("expected error for unsupported link type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported link type") {
		t.Errorf("expected error message to contain 'unsupported link type', got: %v", err)
	}
}

func BenchmarkOfflineReplay_100kPackets(b *testing.B) {
	tmpDir := b.TempDir()
	pcapPath := filepath.Join(tmpDir, "bench_100k.pcap")

	f, err := os.Create(pcapPath)
	if err != nil {
		b.Fatalf("failed to create bench pcap: %v", err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		_ = f.Close()
		b.Fatalf("failed to write header: %v", err)
	}

	udpPkt := buildFrame(&testing.T{}, &layers.UDP{SrcPort: 54321, DstPort: 514}, []byte("<165>1 2026-11-07T12:00:00Z mymachine.example.com app 1234 ID47 - Benchmark message"), layers.IPProtocolUDP)
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(udpPkt.Data()),
		Length:        len(udpPkt.Data()),
	}

	const packetCount = 100000
	for i := 0; i < packetCount; i++ {
		if err := w.WritePacket(ci, udpPkt.Data()); err != nil {
			_ = f.Close()
			b.Fatalf("failed to write packet %d: %v", i, err)
		}
	}
	_ = f.Close()

	b.ReportAllocs()
	b.SetBytes(int64(len(udpPkt.Data()) * packetCount))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		src, err := NewOfflinePacketSource(pcapPath, 514, "dst")
		if err != nil {
			b.Fatalf("failed to open pcap: %v", err)
		}
		var count int
		for {
			pd, err := src.NextPacket()
			if err != nil {
				break
			}
			if pd != nil && !pd.NoPayload {
				count++
			}
		}
		_ = src.Close()
		if count != packetCount {
			b.Fatalf("expected %d packets, read %d", packetCount, count)
		}
	}
}

func TestValidateCaptureOptions(t *testing.T) {
	tests := []struct {
		name        string
		direction   string
		ports       []int
		wantDir     string
		wantPorts   []int
		wantErr     bool
		errContains string
	}{
		{
			name:      "empty direction and empty ports defaults to dst and 514",
			direction: "",
			ports:     nil,
			wantDir:   "dst",
			wantPorts: []int{514},
		},
		{
			name:      "valid dst single port",
			direction: "dst",
			ports:     []int{514},
			wantDir:   "dst",
			wantPorts: []int{514},
		},
		{
			name:      "valid src uppercase",
			direction: "SRC",
			ports:     []int{1514},
			wantDir:   "src",
			wantPorts: []int{1514},
		},
		{
			name:      "valid both with duplicates and unordered",
			direction: "both",
			ports:     []int{2514, 514, 2514, 1514, 514},
			wantDir:   "both",
			wantPorts: []int{514, 1514, 2514},
		},
		{
			name:        "invalid direction",
			direction:   "upstream",
			ports:       []int{514},
			wantErr:     true,
			errContains: "invalid capture direction",
		},
		{
			name:        "port zero invalid",
			direction:   "dst",
			ports:       []int{0},
			wantErr:     true,
			errContains: "invalid port number",
		},
		{
			name:        "negative port invalid",
			direction:   "dst",
			ports:       []int{-514},
			wantErr:     true,
			errContains: "invalid port number",
		},
		{
			name:        "port > 65535 invalid",
			direction:   "dst",
			ports:       []int{65536},
			wantErr:     true,
			errContains: "invalid port number",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, ports, err := ValidateCaptureOptions(tc.direction, tc.ports)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errContains)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("expected error containing %q, got %v", tc.errContains, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if dir != tc.wantDir {
				t.Errorf("expected direction %q, got %q", tc.wantDir, dir)
			}
			if len(ports) != len(tc.wantPorts) {
				t.Fatalf("expected ports %v, got %v", tc.wantPorts, ports)
			}
			for i := range ports {
				if ports[i] != tc.wantPorts[i] {
					t.Errorf("at index %d: expected port %d, got %d", i, tc.wantPorts[i], ports[i])
				}
			}
		})
	}
}

func TestNewOfflinePacketSource_Validation(t *testing.T) {
	// Must fail early before attempting to read non-existent pcap
	_, err := NewOfflinePacketSource("non_existent_file.pcap", 70000, "dst")
	if err == nil {
		t.Fatal("expected error for port 70000, got nil")
	}
	if !strings.Contains(err.Error(), "invalid port number") {
		t.Errorf("expected invalid port error, got: %v", err)
	}

	_, err = NewOfflinePacketSource("non_existent_file.pcap", 514, "invalid_dir")
	if err == nil {
		t.Fatal("expected error for invalid direction, got nil")
	}
	if !strings.Contains(err.Error(), "invalid capture direction") {
		t.Errorf("expected invalid direction error, got: %v", err)
	}
}

func TestNewPcapPacketSource_BufferSizeError(t *testing.T) {
	// Hook setBufferSize to simulate error
	origHook := setBufferSizeHook
	defer func() { setBufferSizeHook = origHook }()

	setBufferSizeHook = func(h *pcap.InactiveHandle, sz int) error {
		return fmt.Errorf("simulated buffer allocation failure")
	}

	// Try on loopback/lo interface if available or mock
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		t.Skip("no interface available for buffer size hook test")
	}

	intf := devs[0].Name
	_, err = NewPcapPacketSourceMultiPort(intf, []int{514}, "dst", false)
	if err == nil {
		t.Fatal("expected error when SetBufferSize fails, got nil")
	}
	if !strings.Contains(err.Error(), "failed to set capture buffer size") {
		t.Errorf("expected 'failed to set capture buffer size' error, got: %v", err)
	}
}
