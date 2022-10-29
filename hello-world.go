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

func main() {
	//ipAddrs := make(map[string]uint64)

	interfacePtr := flag.String("i", "", "Interface to listen on")
	portPtr := flag.Int("p", 514, "Port to listen for")
	secondsPtr := flag.Int64("t", 60, "Number of seconds to listen on interface")
	flag.Parse()

	bpffiler := "port " + strconv.Itoa(*portPtr)

	now := time.Now() // current local time
	startTimeSec := now.Unix()

	duration := time.Duration(*secondsPtr * int64(time.Second))

	if *interfacePtr == "" {
		log.Fatal("Interface flag (-i) needs to be set!")
		os.Exit(1)
	}

	fmt.Println("Interface:", *interfacePtr)
	fmt.Println("BPFfilter:", bpffiler)

	log.Printf("Will listen %d on interface %s", *secondsPtr, *interfacePtr)

	log.Printf("Current time: %s will end: %s", startTimeSec, startTimeSec+*secondsPtr)
	log.Printf("Duration: %s", duration)

	handle, err := pcap.OpenLive(*interfacePtr, defaultSnapLen, true, duration)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpffiler); err != nil {
		panic(err)
	}

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// Your analysis here!
		analyse_packet(pkt)
	}

	fmt.Printf("Stopped listening to interface. Exiting!")
}
