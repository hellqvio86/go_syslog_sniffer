package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
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
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		scrIp := ip.SrcIP.String()

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		//fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		//fmt.Println("Protocol: ", ip.Protocol)
		//fmt.Println()

		ipAddrs[scrIp] = ipAddrs[scrIp] + 1
	}

	ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		//fmt.Println("IPv6 layer detected.")
		ip, _ := ip6Layer.(*layers.IPv6)
		scrIp := ip.SrcIP.String()

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		//fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		//fmt.Println()

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
			return
		}
	}
}

func main() {
	interfacePtr := flag.String("i", "eth0", "Interface to listen on")
	portPtr := flag.Int("p", 514, "Port to listen for")
	secondsPtr := flag.Int64("t", 60, "Number of seconds to listen on interface")
	flag.Parse()

	bpffiler := "port " + strconv.Itoa(*portPtr)

	duration := time.Duration(*secondsPtr * int64(time.Second))

	if *interfacePtr == "" {
		log.Fatal("Interface flag (-i) needs to be set!")
		os.Exit(1)
	}

	sniff(*interfacePtr, bpffiler, duration)

	if len(ipAddrs) == 0 {
		return
	}

	keys := make([]string, 0, len(ipAddrs))

	for k := range ipAddrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Println("IP,count")
	for _, key := range keys {
		fmt.Print(key)
		fmt.Print(",")
		fmt.Print(ipAddrs[key])
		fmt.Println("")
	}
}
