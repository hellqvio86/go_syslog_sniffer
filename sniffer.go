package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type syslogCapture struct {
	Payload   string `json:"payload"`
	Unix_time int64  `json:"unix_time"`
}
type sysloghost struct {
	IPv4Package  uint64        `json:"ipv4Package"`
	IPv6Package  uint64        `json:"ipv6Package"`
	UDPDatagrams uint64        `json:"udpDatagrams"`
	TCPPackages  uint64        `json:"tcpPackages"`
	SampleEvent  syslogCapture `json:"sampleEvent"`
}

var ipAddrs = make(map[string]sysloghost)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func add_payload_to_map(srcIp string, pkt gopacket.Packet) {
	var syslogMsgRegexp = regexp.MustCompile(`.*<\d+>.*$`)
	syslog_host := ipAddrs[srcIp]

	if syslog_host.SampleEvent.Payload != "" {
		// Seen before
		return
	}

	applicationLayer := pkt.ApplicationLayer()
	if applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		//log.Print("Source ip: ", srcIp, " Payload: ", payload)

		if syslogMsgRegexp.MatchString(payload) {
			new_syslog_msg := syslogCapture{payload, time.Now().Unix()}
			syslog_host.SampleEvent = new_syslog_msg

			ipAddrs[srcIp] = syslog_host
		}
	}
}

func analyse_packet(pkt gopacket.Packet) {
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	scrIp := ""

	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		scrIp = ip.SrcIP.String()

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		//fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		//fmt.Println("Protocol: ", ip.Protocol)
		//fmt.Println()

		sysloghost := ipAddrs[scrIp]
		sysloghost.IPv4Package = sysloghost.IPv4Package + 1
		ipAddrs[scrIp] = sysloghost
	}

	ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		//fmt.Println("IPv6 layer detected.")
		ip, _ := ip6Layer.(*layers.IPv6)
		scrIp = ip.SrcIP.String()

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		//fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		//fmt.Println()

		sysloghost := ipAddrs[scrIp]
		sysloghost.IPv6Package = sysloghost.IPv6Package + 1
		ipAddrs[scrIp] = sysloghost
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		sysloghost := ipAddrs[scrIp]
		sysloghost.TCPPackages = sysloghost.TCPPackages + 1
		ipAddrs[scrIp] = sysloghost
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		sysloghost := ipAddrs[scrIp]
		sysloghost.UDPDatagrams = sysloghost.UDPDatagrams + 1
		ipAddrs[scrIp] = sysloghost
	}

	add_payload_to_map(scrIp, pkt)
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

func _UnescapeUnicodeCharactersInJSON(_jsonRaw json.RawMessage) (json.RawMessage, error) {
	str, err := strconv.Unquote(strings.Replace(strconv.Quote(string(_jsonRaw)), `\\u`, `\u`, -1))
	if err != nil {
		return nil, err
	}
	return []byte(str), nil
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

	fmt.Println("Sample events:")
	for _, key := range keys {
		fmt.Print("IP: ")
		fmt.Print(key)
		fmt.Print(" Syslog message: ")
		fmt.Println(ipAddrs[key].SampleEvent.Payload)
	}

	jsonByte, err := json.Marshal(ipAddrs)
	if err != nil {
		log.Println("Failed with json Mashal", err)
	}
	jsonRawUnescapedBytes, _ := _UnescapeUnicodeCharactersInJSON(jsonByte)

	_ = ioutil.WriteFile("syslog_flow.json", jsonRawUnescapedBytes, 0644)

	//fmt.Println("\n")
	//look_for_invalid_timestamps(keys)
	//fmt.Println("\n")

	fmt.Println("IP,ipv4Package,ipv6Package,udpDatagrams,tcpPackages")
	for _, key := range keys {
		fmt.Print(key)
		fmt.Print(",")
		fmt.Print(ipAddrs[key].IPv4Package)
		fmt.Print(",")
		fmt.Print(ipAddrs[key].IPv6Package)
		fmt.Print(",")
		fmt.Print(ipAddrs[key].UDPDatagrams)
		fmt.Print(",")
		fmt.Print(ipAddrs[key].TCPPackages)
		fmt.Println("")
	}
}
