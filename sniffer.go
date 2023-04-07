package main

import (
	"encoding/json"
	"flag"
	"fmt"
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
	Payload  string `json:"payload"`
	UnixTime int64  `json:"unixTime"`
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

func addPayloadToMap(srcIP string, pkt gopacket.Packet) {
	var syslogMsgRegexp = regexp.MustCompile(`.*<\d+>.*$`)
	syslogHost := ipAddrs[srcIP]

	if syslogHost.SampleEvent.Payload != "" {
		// Seen before
		return
	}

	applicationLayer := pkt.ApplicationLayer()
	if applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		//log.Print("Source ip: ", srcIP, " Payload: ", payload)

		if syslogMsgRegexp.MatchString(payload) {
			newSyslogMsg := syslogCapture{payload, time.Now().Unix()}
			syslogHost.SampleEvent = newSyslogMsg

			ipAddrs[srcIP] = syslogHost
		}
	}
}

func analysePacket(pkt gopacket.Packet) {
	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	scrIP := ""

	if ipLayer != nil {
		//fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)
		scrIP = ip.SrcIP.String()

		sysloghost := ipAddrs[scrIP]
		sysloghost.IPv4Package = sysloghost.IPv4Package + 1
		ipAddrs[scrIP] = sysloghost
	}

	ip6Layer := pkt.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		//fmt.Println("IPv6 layer detected.")
		ip, _ := ip6Layer.(*layers.IPv6)
		scrIP = ip.SrcIP.String()

		sysloghost := ipAddrs[scrIP]
		sysloghost.IPv6Package = sysloghost.IPv6Package + 1
		ipAddrs[scrIP] = sysloghost
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		sysloghost := ipAddrs[scrIP]
		sysloghost.TCPPackages = sysloghost.TCPPackages + 1
		ipAddrs[scrIP] = sysloghost
	}

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		sysloghost := ipAddrs[scrIP]
		sysloghost.UDPDatagrams = sysloghost.UDPDatagrams + 1
		ipAddrs[scrIP] = sysloghost
	}

	addPayloadToMap(scrIP, pkt)
}

func sniff(intf string, bpffiler string, duration time.Duration) {
	handle, err := pcap.OpenLive(intf, defaultSnapLen, true, 1000)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpffiler); err != nil {
		panic(err)
	}

	timer := time.NewTicker(duration)
	defer timer.Stop()

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case pkt := <-src.Packets():
			// process a packet in pkt
			analysePacket(pkt)
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

	jsonByte, err := json.Marshal(ipAddrs)
	if err != nil {
		log.Println("Failed with json Mashal", err)
	}
	jsonRawUnescapedBytes, _ := _UnescapeUnicodeCharactersInJSON(jsonByte)

	fmt.Println(string(jsonRawUnescapedBytes))
}
