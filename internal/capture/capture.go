package capture

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// ErrCaptureClosed is returned when the underlying packet capture channel closes.
var ErrCaptureClosed = errors.New("capture closed")

// ErrInvalidDirection is returned when an unsupported BPF capture direction is requested.
var ErrInvalidDirection = errors.New("invalid capture direction")

// ErrInvalidPort is returned when a port number is outside the valid TCP/UDP range (1-65535).
var ErrInvalidPort = errors.New("invalid port number")

const (
	defaultSnapLen    = 65535
	defaultBufferSize = 8 * 1024 * 1024 // 8 MB buffer for busy collectors
	readTimeout       = 250 * time.Millisecond
	idleFlushInterval = 5 * time.Second
	idleFlowTimeout   = 30 * time.Second
)

// setBufferSizeHook provides a test seam for verifying buffer configuration failure without physical hardware.
var setBufferSizeHook = func(h *pcap.InactiveHandle, sz int) error {
	return h.SetBufferSize(sz)
}

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

// PcapPacketSource captures packets live from a network interface or offline pcap using libpcap.
// It performs TCP stream reassembly and UDP datagram extraction.
type PcapPacketSource struct {
	mu          sync.Mutex
	handle      *pcap.Handle
	packets     <-chan gopacket.Packet
	lastStats   *Stats
	timer       *time.Timer
	isOffline   bool
	reassembler *TCPReassembler
	lastFlush   time.Time
}

// ValidateCaptureOptions validates and normalizes the packet direction and port list.
// Direction must be "dst", "src", or "both" (empty defaults to "dst").
// Ports must be within 1-65535. Empty port list defaults to [514].
// Returns the normalized direction and deduplicated sorted port list.
func ValidateCaptureOptions(direction string, ports []int) (string, []int, error) {
	dir := strings.ToLower(strings.TrimSpace(direction))
	if dir == "" {
		dir = "dst"
	}
	switch dir {
	case "dst", "src", "both":
	default:
		return "", nil, fmt.Errorf("%w: %q (must be 'dst', 'src', or 'both')", ErrInvalidDirection, direction)
	}

	if len(ports) == 0 {
		return dir, []int{514}, nil
	}

	seen := make(map[int]bool, len(ports))
	var cleanPorts []int
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return "", nil, fmt.Errorf("%w: %d (must be between 1 and 65535)", ErrInvalidPort, p)
		}
		if !seen[p] {
			seen[p] = true
			cleanPorts = append(cleanPorts, p)
		}
	}
	sort.Ints(cleanPorts)
	return dir, cleanPorts, nil
}

// BuildBPFFilter creates a BPF filter expression for the specified direction and ports,
// matching both untagged and 802.1Q VLAN-tagged traffic.
// Supported directions are "dst" (default), "src", and "both".
func BuildBPFFilter(direction string, ports ...int) string {
	dir, cleanPorts, err := ValidateCaptureOptions(direction, ports)
	if err != nil {
		dir = "dst"
		if len(ports) == 0 {
			cleanPorts = []int{514}
		} else {
			cleanPorts = ports
		}
	}

	var prefix string
	switch dir {
	case "src":
		prefix = "src port "
	case "both":
		prefix = "port "
	default:
		prefix = "dst port "
	}

	var portExpr string
	if len(cleanPorts) == 1 {
		portExpr = fmt.Sprintf("%s%d", prefix, cleanPorts[0])
	} else {
		var parts []string
		for _, p := range cleanPorts {
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
	dir, cleanPorts, err := ValidateCaptureOptions(direction, ports)
	if err != nil {
		return nil, err
	}

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
	if err := setBufferSizeHook(inactive, defaultBufferSize); err != nil {
		return nil, fmt.Errorf("failed to set capture buffer size on interface %s: %w", intf, err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, formatInterfaceError(intf, "open", err)
	}

	lt := handle.LinkType()
	if !isSupportedLinkType(lt) {
		handle.Close()
		return nil, fmt.Errorf("unsupported link type %s (linktype %d); consider specifying a network interface with -i", lt, lt)
	}

	filter := BuildBPFFilter(dir, cleanPorts...)
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
		handle:      handle,
		packets:     pktSource.Packets(),
		isOffline:   false,
		reassembler: NewTCPReassembler(),
		lastFlush:   time.Now(),
	}, nil
}

// NextPacket reads the next packet or reassembled syslog message from the pcap stream.
// If no packet is available within readTimeout or channel is empty, it returns (nil, nil).
func (p *PcapPacketSource) NextPacket() (*PacketData, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.reassembler == nil {
		p.reassembler = NewTCPReassembler()
	}

	// 1. Return any already-reassembled TCP messages
	if p.reassembler.HasReady() {
		return p.reassembler.PopReady(), nil
	}

	// 2. Check periodic idle flow flush
	now := time.Now()
	if !p.isOffline && now.Sub(p.lastFlush) >= idleFlushInterval {
		p.reassembler.FlushOlderThan(now.Add(-idleFlowTimeout))
		p.lastFlush = now
		if p.reassembler.HasReady() {
			return p.reassembler.PopReady(), nil
		}
	}

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

	for {
		select {
		case pkt, ok := <-p.packets:
			if !ok {
				p.reassembler.FlushAll()
				if p.reassembler.HasReady() {
					return p.reassembler.PopReady(), nil
				}
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

			if transport == "tcp" {
				tcpLayer := pkt.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp := tcpLayer.(*layers.TCP)
					netFlow := pkt.NetworkLayer().NetworkFlow()
					p.reassembler.Assemble(netFlow, tcp, ts)
					if p.reassembler.HasReady() {
						return p.reassembler.PopReady(), nil
					}
					// If the stream started mid-capture without a SYN, flush to start processing
					if !tcp.SYN && len(tcp.LayerPayload()) > 0 {
						p.reassembler.FlushWithOptions(tcpassembly.FlushOptions{
							T:        ts.Add(time.Nanosecond),
							CloseAll: false,
						})
						if p.reassembler.HasReady() {
							return p.reassembler.PopReady(), nil
						}
					}
					// If the TCP packet carried no payload (pure ACK, SYN, or FIN),
					// report it so the caller can record ignored/no_payload if needed.
					if len(tcp.LayerPayload()) == 0 {
						return &PacketData{
							SrcIP:     srcIP,
							NoPayload: true,
							Timestamp: ts,
							Transport: "tcp",
						}, nil
					}
					// TCP packet had payload, but incomplete message: continue reading next packet
					continue
				}
			}

			// UDP or other protocols
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
}

// Stats returns capture statistics from the underlying pcap handle, or the last cached stats if closed.
func (p *PcapPacketSource) Stats() (*Stats, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
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

// Close closes the underlying pcap handle after saving final statistics and flushing TCP reassembly.
func (p *PcapPacketSource) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.timer != nil {
		p.timer.Stop()
	}
	if p.reassembler != nil {
		p.reassembler.FlushAll()
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
	dir, cleanPorts, err := ValidateCaptureOptions(direction, ports)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", pcapFile, err)
	}

	lt := handle.LinkType()
	if !isSupportedLinkType(lt) {
		handle.Close()
		return nil, fmt.Errorf("unsupported link type %s (linktype %d); consider specifying a network interface with -i", lt, lt)
	}

	filter := BuildBPFFilter(dir, cleanPorts...)
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
		handle:      handle,
		packets:     pktSource.Packets(),
		isOffline:   true,
		reassembler: NewTCPReassembler(),
		lastFlush:   time.Now(),
	}, nil
}
