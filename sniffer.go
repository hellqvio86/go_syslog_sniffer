package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var ipAddrs = make(map[string]uint64)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func analyse_packet(pkt gopacket.Packet) {
	ethernetLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		// Ethernet type is typically IPv4 but could be ARP or other
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		scrIp := ip.SrcIP.String()

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()

		ipAddrs[scrIp] = ipAddrs[scrIp] + 1
	}

	ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		fmt.Println("IPv6 layer detected.")
		ip, _ := ip6Layer.(*layers.IPv6)
		scrIp := ip.SrcIP.String()

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println()

		ipAddrs[scrIp] = ipAddrs[scrIp] + 1
	}
}

func sniff(intf string, bpffiler string, duration time.Duration) {
	//handle, err := pcap.OpenLive(intf, defaultSnapLen, true, pcap.BlockForever)
	//handle, err := pcap.OpenLive(intf, defaultSnapLen, true, duration)
	handle, err := pcap.OpenLive(intf, defaultSnapLen, true, 1000)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpffiler); err != nil {
		panic(err)
	}
	//timer := time.NewTicker(2 * time.Second)
	timer := time.NewTicker(duration)
	defer timer.Stop()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case pkt := <-src.Packets():
			// process a packet in pkt
			analyse_packet(pkt)
		case <-timer.C:
			// timed out waiting for 2s seconds
			log.Println("Timeout occure!")
			return
		}
	}
}

func main() {
	//ipAddrs := make(map[string]uint64)

	interfacePtr := flag.String("i", "", "Interface to listen on")
	portPtr := flag.Int("p", 514, "Port to listen for")
	secondsPtr := flag.Int64("t", 60, "Number of seconds to listen on interface")
	flag.Parse()

	bpffiler := "port " + strconv.Itoa(*portPtr)

	duration := time.Duration(*secondsPtr * int64(time.Second))

	if *interfacePtr == "" {
		log.Fatal("Interface flag (-i) needs to be set!")
		os.Exit(1)
	}

	//now := time.Now() // current local time
	//startTimeSec := now.Unix()

	fmt.Println("Interface:", *interfacePtr)
	fmt.Println("BPFfilter:", bpffiler)

	log.Printf("Will listen %d on interface %s", *secondsPtr, *interfacePtr)

	log.Printf("Duration: %s", duration)
	log.Println("Duration in seconds:", duration.Seconds())

	sniff(*interfacePtr, bpffiler, duration)

	fmt.Println("ipAddrs: ", ipAddrs)
	fmt.Println("Sniffing done! Exit")
}
