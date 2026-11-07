package capture

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ErrCaptureClosed is returned when the underlying packet capture channel closes.
var ErrCaptureClosed = errors.New("capture closed")

const (
	defaultSnapLen    = 262144
	defaultBufferSize = 8 * 1024 * 1024 // 8 MB buffer for busy collectors
	readTimeout       = 250 * time.Millisecond
)

// Stats holds kernel and interface packet capture statistics.
type Stats struct {
	PacketsReceived  int `json:"received"`
	PacketsDropped   int `json:"dropped"`
	PacketsIfDropped int `json:"if_dropped"`
}

// PacketData contains the payload bytes and source IP extracted from a captured packet.
type PacketData struct {
	Data      []byte
	SrcIP     string
	NoPayload bool
}

// PacketSource defines the interface for consuming captured network packets.
type PacketSource interface {
	NextPacket() (*PacketData, error)
	Close() error
	Stats() (*Stats, error)
}

// PcapPacketSource captures packets live from a network interface using libpcap.
type PcapPacketSource struct {
	handle    *pcap.Handle
	packets   <-chan gopacket.Packet
	lastStats *Stats
	timer     *time.Timer
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

func formatInterfaceError(intf string, phase string, err error) error {
	devs, findErr := pcap.FindAllDevs()
	var candidateNames []string
	if findErr == nil {
		for _, d := range devs {
			candidateNames = append(candidateNames, d.Name)
		}
	}
	if len(candidateNames) > 0 {
		return fmt.Errorf("failed to %s interface %s: %w (available interfaces: %s)", phase, intf, err, strings.Join(candidateNames, ", "))
	}
	return fmt.Errorf("failed to %s interface %s: %w", phase, intf, err)
}

// NewPcapPacketSource opens a live pcap handle on the given interface and port with default "dst" direction.
func NewPcapPacketSource(intf string, port int) (*PcapPacketSource, error) {
	return NewPcapPacketSourceWithDirection(intf, port, "dst")
}

// NewPcapPacketSourceWithDirection opens a live pcap handle with explicit direction ("dst", "src", or "both").
func NewPcapPacketSourceWithDirection(intf string, port int, direction string) (*PcapPacketSource, error) {
	inactive, err := pcap.NewInactiveHandle(intf)
	if err != nil {
		return nil, formatInterfaceError(intf, "open", err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(defaultSnapLen); err != nil {
		return nil, fmt.Errorf("failed to set snaplen on interface %s: %w", intf, err)
	}
	if err := inactive.SetPromisc(true); err != nil {
		return nil, fmt.Errorf("failed to set promisc on interface %s: %w", intf, err)
	}
	if err := inactive.SetTimeout(readTimeout); err != nil {
		return nil, fmt.Errorf("failed to set timeout on interface %s: %w", intf, err)
	}
	_ = inactive.SetBufferSize(defaultBufferSize)

	handle, err := inactive.Activate()
	if err != nil {
		return nil, formatInterfaceError(intf, "open", err)
	}

	filter := BuildBPFFilter(direction, port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter %q: %w", filter, err)
	}

	pktSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktSource.DecodeOptions = gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	}
	return &PcapPacketSource{
		handle:  handle,
		packets: pktSource.Packets(),
	}, nil
}

// NextPacket reads the next packet from the pcap stream.
// If no packet is available within readTimeout or channel is empty, it returns (nil, nil).
func (p *PcapPacketSource) NextPacket() (*PacketData, error) {
	if p.timer == nil {
		p.timer = time.NewTimer(readTimeout)
	} else {
		if !p.timer.Stop() {
			select {
			case <-p.timer.C:
			default:
			}
		}
		p.timer.Reset(readTimeout)
	}

	select {
	case pkt, ok := <-p.packets:
		if !ok {
			return nil, io.EOF
		}
		if pkt == nil {
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

		// Prefer ApplicationLayer payload; never fallback to raw packet data.
		// Because NoCopy: true is enabled on packet decoding, explicitly copy the payload slice.
		var payload []byte
		if appLayer := pkt.ApplicationLayer(); appLayer != nil {
			raw := appLayer.Payload()
			if len(raw) > 0 {
				payload = make([]byte, len(raw))
				copy(payload, raw)
			}
		}
		if len(payload) == 0 {
			return &PacketData{
				SrcIP:     srcIP,
				NoPayload: true,
			}, nil
		}

		return &PacketData{
			Data:  payload,
			SrcIP: srcIP,
		}, nil
	case <-p.timer.C:
		return nil, nil
	}
}

// Stats returns capture statistics from the underlying pcap handle, or the last cached stats if closed.
func (p *PcapPacketSource) Stats() (*Stats, error) {
	if p.handle != nil {
		if st, err := p.handle.Stats(); err == nil && st != nil {
			p.lastStats = &Stats{
				PacketsReceived:  st.PacketsReceived,
				PacketsDropped:   st.PacketsDropped,
				PacketsIfDropped: st.PacketsIfDropped,
			}
			return p.lastStats, nil
		}
	}
	return p.lastStats, nil
}

// Close closes the underlying pcap handle after saving final statistics.
func (p *PcapPacketSource) Close() error {
	if p.timer != nil {
		p.timer.Stop()
	}
	if p.handle != nil {
		if st, err := p.handle.Stats(); err == nil && st != nil {
			p.lastStats = &Stats{
				PacketsReceived:  st.PacketsReceived,
				PacketsDropped:   st.PacketsDropped,
				PacketsIfDropped: st.PacketsIfDropped,
			}
		}
		p.handle.Close()
		p.handle = nil
	}
	return nil
}

// NewOfflinePacketSource opens a saved pcap file and sets a BPF filter for the specified port and direction.
func NewOfflinePacketSource(pcapFile string, port int, direction string) (*PcapPacketSource, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", pcapFile, err)
	}

	filter := BuildBPFFilter(direction, port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter %q on %s: %w", filter, pcapFile, err)
	}

	pktSource := gopacket.NewPacketSource(handle, handle.LinkType())
	pktSource.DecodeOptions = gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	}
	return &PcapPacketSource{
		handle:  handle,
		packets: pktSource.Packets(),
	}, nil
}
