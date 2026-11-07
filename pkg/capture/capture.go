package capture

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	defaultSnapLen = 262144
	readTimeout    = 250 * time.Millisecond
)

// PacketData contains the payload bytes and source IP extracted from a captured packet.
type PacketData struct {
	Data  []byte
	SrcIP string
}

// PacketSource defines the interface for consuming captured network packets.
type PacketSource interface {
	NextPacket() (*PacketData, error)
	Close() error
}

// PcapPacketSource captures packets live from a network interface using libpcap.
type PcapPacketSource struct {
	handle  *pcap.Handle
	packets <-chan gopacket.Packet
}

// BuildBPFFilter creates a BPF filter expression for the specified direction and ports.
// Supported directions are "dst" (default), "src", and "both".
func BuildBPFFilter(direction string, ports ...int) string {
	if len(ports) == 0 {
		ports = []int{514}
	}
	prefix := "dst port "
	switch direction {
	case "src":
		prefix = "src port "
	case "both":
		prefix = "port "
	default:
		prefix = "dst port "
	}

	if len(ports) == 1 {
		return fmt.Sprintf("%s%d", prefix, ports[0])
	}

	var parts []string
	for _, p := range ports {
		parts = append(parts, fmt.Sprintf("%s%d", prefix, p))
	}
	return fmt.Sprintf("(%s)", strings.Join(parts, " or "))
}

// NewPcapPacketSource opens a live pcap handle on the given interface and port with default "dst" direction.
func NewPcapPacketSource(intf string, port int) (*PcapPacketSource, error) {
	return NewPcapPacketSourceWithDirection(intf, port, "dst")
}

// NewPcapPacketSourceWithDirection opens a live pcap handle with explicit direction ("dst", "src", or "both").
func NewPcapPacketSourceWithDirection(intf string, port int, direction string) (*PcapPacketSource, error) {
	handle, err := pcap.OpenLive(intf, defaultSnapLen, true, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", intf, err)
	}

	filter := BuildBPFFilter(direction, port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter %q: %w", filter, err)
	}

	pktSource := gopacket.NewPacketSource(handle, handle.LinkType())
	return &PcapPacketSource{
		handle:  handle,
		packets: pktSource.Packets(),
	}, nil
}

// NextPacket reads the next packet from the pcap stream.
// If no packet is available within readTimeout or channel is empty, it returns (nil, nil).
func (p *PcapPacketSource) NextPacket() (*PacketData, error) {
	select {
	case pkt, ok := <-p.packets:
		if !ok || pkt == nil {
			return nil, nil
		}

		var srcIP string
		if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			if ip, ok := ipLayer.(*layers.IPv4); ok {
				srcIP = ip.SrcIP.String()
			}
		} else if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			if ip6, ok := ip6Layer.(*layers.IPv6); ok {
				srcIP = ip6.SrcIP.String()
			}
		}

		// Prefer ApplicationLayer payload; never fallback to raw packet data
		var payload []byte
		if appLayer := pkt.ApplicationLayer(); appLayer != nil {
			payload = appLayer.Payload()
		}
		if len(payload) == 0 {
			return nil, nil
		}

		return &PacketData{
			Data:  payload,
			SrcIP: srcIP,
		}, nil
	case <-time.After(readTimeout):
		return nil, nil
	}
}

// Close closes the underlying pcap handle.
func (p *PcapPacketSource) Close() error {
	if p.handle != nil {
		p.handle.Close()
	}
	return nil
}

// MockPacketSource is an in-memory packet source for testing.
type MockPacketSource struct {
	packets []*PacketData
	idx     int
}

// NewMockPacketSource creates a mock packet source with a predetermined packet sequence.
func NewMockPacketSource(packets []*PacketData) *MockPacketSource {
	return &MockPacketSource{
		packets: packets,
	}
}

// NextPacket returns the next mock packet or (nil, nil) when exhausted.
func (m *MockPacketSource) NextPacket() (*PacketData, error) {
	if m.idx >= len(m.packets) {
		return nil, nil
	}
	pkt := m.packets[m.idx]
	m.idx++
	return pkt, nil
}

// Close is a no-op for MockPacketSource.
func (m *MockPacketSource) Close() error {
	return nil
}
