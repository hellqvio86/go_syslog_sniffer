package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func analyse_packet(pkt gopacket.Packet) {
	log.Println("Handling pkt %s", pkt)
}

func sniff(intf string, bpffiler string, duration time.Duration) {
	handle, err := pcap.OpenLive(intf, defaultSnapLen, true, duration)
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

	fmt.Println("Sniffing done! Exit")
}
