package capture

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ErrCaptureClosed is returned when the underlying packet capture channel closes.
var ErrCaptureClosed = errors.New("capture closed")

const (
	defaultSnapLen    = 65535
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
	Data        []byte
	SrcIP       netip.Addr
	NoPayload   bool
	Timestamp   time.Time
	Transport   string // "udp" or "tcp"
	DecodeError bool
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
	isOffline bool
}

// BuildBPFFilter creates a BPF filter expression for the specified direction and ports,
// matching both untagged and 802.1Q VLAN-tagged traffic.
// Supported directions are "dst" (default), "src", and "both".
func BuildBPFFilter(direction string, ports ...int) string {
	if len(ports) == 0 {
		ports = []int{514}
	}
	var prefix string
	switch direction {
	case "src":
		prefix = "src port "
	case "both":
		prefix = "port "
	default:
		prefix = "dst port "
	}

	var portExpr string
	if len(ports) == 1 {
		portExpr = fmt.Sprintf("%s%d", prefix, ports[0])
	} else {
		var parts []string
		for _, p := range ports {
			parts = append(parts, fmt.Sprintf("%s%d", prefix, p))
		}
		portExpr = fmt.Sprintf("(%s)", strings.Join(parts, " or "))
	}

	return fmt.Sprintf("(%s) or (vlan and %s)", portExpr, portExpr)
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

func isSupportedLinkType(lt layers.LinkType) bool {
	switch lt {
	case layers.LinkTypeEthernet,
		layers.LinkTypeLinuxSLL,
		layers.LinkTypeNull,
		layers.LinkTypeLoop,
		layers.LinkTypeRaw,
		layers.LinkTypeIPv4,
		layers.LinkTypeIPv6:
		return true
	default:
		return false
	}
}

// NewPcapPacketSourceWithOptions opens a live pcap handle with explicit direction and promiscuous mode setting.
func NewPcapPacketSourceWithOptions(intf string, port int, direction string, promisc bool) (*PcapPacketSource, error) {
	return NewPcapPacketSourceMultiPort(intf, []int{port}, direction, promisc)
}

// NewPcapPacketSourceMultiPort opens a live pcap handle with multiple ports, explicit direction, and promiscuous mode.
func NewPcapPacketSourceMultiPort(intf string, ports []int, direction string, promisc bool) (*PcapPacketSource, error) {
	inactive, err := pcap.NewInactiveHandle(intf)
	if err != nil {
		return nil, formatInterfaceError(intf, "open", err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(defaultSnapLen); err != nil {
		return nil, fmt.Errorf("failed to set snaplen on interface %s: %w", intf, err)
	}
	if err := inactive.SetPromisc(promisc); err != nil {
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

	lt := handle.LinkType()
	if !isSupportedLinkType(lt) {
		handle.Close()
		return nil, fmt.Errorf("unsupported link type %s (linktype %d); consider specifying a network interface with -i", lt, lt)
	}

	filter := BuildBPFFilter(direction, ports...)
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
		handle:    handle,
		packets:   pktSource.Packets(),
		isOffline: false,
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
			if p.isOffline {
				return nil, io.EOF
			}
			return nil, ErrCaptureClosed
		}
		if pkt == nil {
			return nil, nil
		}

		var ts time.Time
		if md := pkt.Metadata(); md != nil {
			ts = md.Timestamp
		}

		if pkt.ErrorLayer() != nil {
			return &PacketData{
				DecodeError: true,
				Timestamp:   ts,
			}, nil
		}

		var transport string
		if pkt.Layer(layers.LayerTypeUDP) != nil {
			transport = "udp"
		} else if pkt.Layer(layers.LayerTypeTCP) != nil {
			transport = "tcp"
		}

		var srcIP netip.Addr
		if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			if ip, ok := ipLayer.(*layers.IPv4); ok {
				if addr, ok := netip.AddrFromSlice(ip.SrcIP); ok {
					srcIP = addr.Unmap()
				}
			}
		} else if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			if ip6, ok := ip6Layer.(*layers.IPv6); ok {
				if addr, ok := netip.AddrFromSlice(ip6.SrcIP); ok {
					srcIP = addr.Unmap()
				}
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
				Timestamp: ts,
				Transport: transport,
			}, nil
		}

		return &PacketData{
			Data:      payload,
			SrcIP:     srcIP,
			Timestamp: ts,
			Transport: transport,
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
	return NewOfflinePacketSourceMultiPort(pcapFile, []int{port}, direction)
}

// NewOfflinePacketSourceMultiPort opens a saved pcap file and sets a BPF filter for multiple ports and direction.
func NewOfflinePacketSourceMultiPort(pcapFile string, ports []int, direction string) (*PcapPacketSource, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", pcapFile, err)
	}

	lt := handle.LinkType()
	if !isSupportedLinkType(lt) {
		handle.Close()
		return nil, fmt.Errorf("unsupported link type %s (linktype %d); consider specifying a network interface with -i", lt, lt)
	}

	filter := BuildBPFFilter(direction, ports...)
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
		handle:    handle,
		packets:   pktSource.Packets(),
		isOffline: true,
	}, nil
}
