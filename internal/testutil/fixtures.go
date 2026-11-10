package testutil

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// GenerateTestFixtures creates standard pcap test fixtures in the given directory.
func GenerateTestFixtures(targetDir string) error {
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return err
	}

	// 1. valid_syslog.pcap: UDP packets spanning > 12 seconds with RFC 5424 and 3164
	validPath := filepath.Join(targetDir, "valid_syslog.pcap")
	if err := generateValidSyslogPcap(validPath); err != nil {
		return err
	}

	// 2. vlan_syslog.pcap: 802.1Q tagged frame
	vlanPath := filepath.Join(targetDir, "vlan_syslog.pcap")
	if err := generateVlanSyslogPcap(vlanPath); err != nil {
		return err
	}

	// 3. tcp_syslog.pcap: TCP segments with octet-counting and LF-framing
	tcpPath := filepath.Join(targetDir, "tcp_syslog.pcap")
	if err := generateTCPSyslogPcap(tcpPath); err != nil {
		return err
	}

	// 4. ipv6_syslog.pcap: IPv6 UDP syslog
	ipv6Path := filepath.Join(targetDir, "ipv6_syslog.pcap")
	if err := generateIPv6SyslogPcap(ipv6Path); err != nil {
		return err
	}

	return nil
}

func writePcapFile(path string, linkType layers.LinkType, writeFn func(w *pcapgo.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, linkType); err != nil {
		return err
	}
	return writeFn(w)
}

func generateValidSyslogPcap(path string) error {
	baseTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	return writePcapFile(path, layers.LinkTypeEthernet, func(w *pcapgo.Writer) error {
		for i := 0; i < 15; i++ {
			ts := baseTime.Add(time.Duration(i) * time.Second)
			msg := fmt.Sprintf("<165>1 %s host%d app 1 - - Valid syslog message %d", ts.Format(time.RFC3339), i%3, i)
			srcIP := net.IP{192, 168, 1, byte(10 + (i % 3))}
			data := buildEthernetUDPPacket(srcIP, net.IP{192, 168, 1, 1}, 50000+uint16(i), 514, []byte(msg))
			ci := gopacket.CaptureInfo{
				Timestamp:      ts,
				CaptureLength:  len(data),
				Length:         len(data),
				InterfaceIndex: 0,
			}
			if err := w.WritePacket(ci, data); err != nil {
				return err
			}
		}
		return nil
	})
}

func generateVlanSyslogPcap(path string) error {
	baseTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	return writePcapFile(path, layers.LinkTypeEthernet, func(w *pcapgo.Writer) error {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			EthernetType: layers.EthernetTypeDot1Q,
		}
		dot1q := &layers.Dot1Q{
			VLANIdentifier: 100,
			Type:           layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    net.IP{192, 168, 1, 50},
			DstIP:    net.IP{192, 168, 1, 1},
		}
		udp := &layers.UDP{
			SrcPort: 54321,
			DstPort: 514,
		}
		_ = udp.SetNetworkLayerForChecksum(ip)

		msg := "<13>Oct 11 22:14:15 vlanhost test message"
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, dot1q, ip, udp, gopacket.Payload([]byte(msg))); err != nil {
			return err
		}

		data := buf.Bytes()
		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime,
			CaptureLength: len(data),
			Length:        len(data),
		}
		return w.WritePacket(ci, data)
	})
}

func generateTCPSyslogPcap(path string) error {
	baseTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	return writePcapFile(path, layers.LinkTypeEthernet, func(w *pcapgo.Writer) error {
		// Frame 1: LF-delimited
		msg1 := "<13>Oct 11 22:14:15 tcphost1 msg 1\n<13>Oct 11 22:14:16 tcphost1 msg 2\n"
		data1 := buildEthernetTCPPacket(net.IP{10, 0, 0, 1}, net.IP{10, 0, 0, 2}, 40001, 514, []byte(msg1))
		ci1 := gopacket.CaptureInfo{
			Timestamp:     baseTime,
			CaptureLength: len(data1),
			Length:        len(data1),
		}
		if err := w.WritePacket(ci1, data1); err != nil {
			return err
		}

		// Frame 2: RFC 6587 octet-counted
		msg2 := "34 <13>Oct 11 22:14:17 tcphost2 msg A34 <13>Oct 11 22:14:18 tcphost2 msg B"
		data2 := buildEthernetTCPPacket(net.IP{10, 0, 0, 2}, net.IP{10, 0, 0, 2}, 40002, 514, []byte(msg2))
		ci2 := gopacket.CaptureInfo{
			Timestamp:     baseTime.Add(2 * time.Second),
			CaptureLength: len(data2),
			Length:        len(data2),
		}
		return w.WritePacket(ci2, data2)
	})
}

func generateIPv6SyslogPcap(path string) error {
	baseTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	return writePcapFile(path, layers.LinkTypeEthernet, func(w *pcapgo.Writer) error {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			EthernetType: layers.EthernetTypeIPv6,
		}
		ip6 := &layers.IPv6{
			Version:    6,
			NextHeader: layers.IPProtocolUDP,
			HopLimit:   64,
			SrcIP:      net.ParseIP("2001:db8::1"),
			DstIP:      net.ParseIP("2001:db8::2"),
		}
		udp := &layers.UDP{
			SrcPort: 52000,
			DstPort: 514,
		}
		_ = udp.SetNetworkLayerForChecksum(ip6)

		msg := "<165>1 2026-11-10T12:00:00Z ipv6host app 1 - - IPv6 Syslog"
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip6, udp, gopacket.Payload([]byte(msg))); err != nil {
			return err
		}

		data := buf.Bytes()
		ci := gopacket.CaptureInfo{
			Timestamp:     baseTime,
			CaptureLength: len(data),
			Length:        len(data),
		}
		return w.WritePacket(ci, data)
	})
}

func buildEthernetUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	_ = udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	return buf.Bytes()
}

func buildEthernetTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
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
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1000,
		ACK:     true,
		Window:  65535,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	return buf.Bytes()
}
