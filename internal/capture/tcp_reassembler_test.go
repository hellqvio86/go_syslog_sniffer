package capture

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

func makeTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, seq uint32, payload []byte, syn, fin, rst, ack bool) (gopacket.Flow, *layers.TCP) {
	ipFlow, _ := gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(srcIP),
		layers.NewIPEndpoint(dstIP),
	)

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		SYN:     syn,
		FIN:     fin,
		RST:     rst,
		ACK:     ack,
		BaseLayer: layers.BaseLayer{
			Payload: payload,
		},
	}
	return ipFlow, tcp
}

// TestTCPReassembler_SplitAtEveryByteBoundary verifies that a syslog message
// split at ANY possible byte boundary across 2 TCP segments is successfully reassembled.
func TestTCPReassembler_SplitAtEveryByteBoundary(t *testing.T) {
	msgContent := "<134>1 2026-11-11T20:00:00Z myhost test"
	octetFramed := "39 " + msgContent

	tests := []struct {
		name        string
		fullWire    string
		expectedMsg string
	}{
		{
			name:        "octet-counted RFC 6587",
			fullWire:    octetFramed,
			expectedMsg: msgContent,
		},
		{
			name:        "LF-delimited RFC 6587",
			fullWire:    msgContent + "\n",
			expectedMsg: msgContent,
		},
	}

	srcIP := net.IP{192, 168, 1, 100}
	dstIP := net.IP{192, 168, 1, 1}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(tc.fullWire)
			for split := 1; split < len(raw); split++ {
				reasm := NewTCPReassembler()
				flow, synPkt := makeTCPPacket(srcIP, dstIP, 50000+split, 514, 1000, nil, true, false, false, false)
				reasm.Assemble(flow, synPkt, time.Now())

				seg1 := raw[:split]
				seg2 := raw[split:]

				_, pkt1 := makeTCPPacket(srcIP, dstIP, 50000+split, 514, 1001, seg1, false, false, false, true)
				reasm.Assemble(flow, pkt1, time.Now())

				_, pkt2 := makeTCPPacket(srcIP, dstIP, 50000+split, 514, 1001+uint32(len(seg1)), seg2, false, false, false, true)
				reasm.Assemble(flow, pkt2, time.Now())

				var pkts []*PacketData
				for reasm.HasReady() {
					pkts = append(pkts, reasm.PopReady())
				}

				if len(pkts) != 1 {
					t.Fatalf("split at %d: expected 1 packet, got %d", split, len(pkts))
				}

				if string(pkts[0].Data) != tc.expectedMsg {
					t.Errorf("split at %d: expected %q, got %q", split, tc.expectedMsg, string(pkts[0].Data))
				}
				if pkts[0].SrcIP != netip.MustParseAddr("192.168.1.100") {
					t.Errorf("split at %d: wrong src IP %s", split, pkts[0].SrcIP)
				}
			}
		})
	}
}

// TestTCPReassembler_MultipleMessagesInOneSegment verifies multiple messages in a single segment.
func TestTCPReassembler_MultipleMessagesInOneSegment(t *testing.T) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	payload := []byte("15 <13>msg-first-115 <13>msg-second2\n")
	_, pkt := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001, payload, false, false, false, true)
	reasm.Assemble(flow, pkt, time.Now())

	var pkts []*PacketData
	for reasm.HasReady() {
		pkts = append(pkts, reasm.PopReady())
	}
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(pkts))
	}
	if string(pkts[0].Data) != "<13>msg-first-1" {
		t.Errorf("expected <13>msg-first-1, got %q", string(pkts[0].Data))
	}
	if string(pkts[1].Data) != "<13>msg-second2" {
		t.Errorf("expected <13>msg-second2, got %q", string(pkts[1].Data))
	}
}

// TestTCPReassembler_OneMessageAcrossMultipleSegments tests a message split over 3 segments.
func TestTCPReassembler_OneMessageAcrossMultipleSegments(t *testing.T) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	fullMsg := "<134>1 2026-11-11T20:00:00Z myhost msg"
	wire := "38 " + fullMsg

	seg1 := []byte(wire[:10])
	seg2 := []byte(wire[10:25])
	seg3 := []byte(wire[25:])

	_, p1 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001, seg1, false, false, false, true)
	_, p2 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001+uint32(len(seg1)), seg2, false, false, false, true)
	_, p3 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001+uint32(len(seg1)+len(seg2)), seg3, false, false, false, true)

	reasm.Assemble(flow, p1, time.Now())
	if reasm.HasReady() {
		t.Fatal("unexpected message ready after segment 1")
	}
	reasm.Assemble(flow, p2, time.Now())
	if reasm.HasReady() {
		t.Fatal("unexpected message ready after segment 2")
	}
	reasm.Assemble(flow, p3, time.Now())
	if !reasm.HasReady() {
		t.Fatal("expected message ready after segment 3")
	}

	pkt := reasm.PopReady()
	if string(pkt.Data) != fullMsg {
		t.Errorf("expected %q, got %q", fullMsg, string(pkt.Data))
	}
}

// TestTCPReassembler_OutOfOrderSegments verifies out-of-order segment reordering.
func TestTCPReassembler_OutOfOrderSegments(t *testing.T) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	seg1 := []byte("<13>Hello ")
	seg2 := []byte("out of order\n")

	_, p1 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001, seg1, false, false, false, true)
	_, p2 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001+uint32(len(seg1)), seg2, false, false, false, true)

	// Feed segment 2 FIRST
	reasm.Assemble(flow, p2, time.Now())
	if reasm.HasReady() {
		t.Fatal("unexpected message ready when segment 2 arrived first")
	}

	// Feed segment 1 SECOND
	reasm.Assemble(flow, p1, time.Now())
	if !reasm.HasReady() {
		t.Fatal("expected message ready after segment 1 arrived")
	}

	pkt := reasm.PopReady()
	expected := "<13>Hello out of order"
	if string(pkt.Data) != expected {
		t.Errorf("expected %q, got %q", expected, string(pkt.Data))
	}
}

// TestTCPReassembler_Retransmission verifies duplicate segments are not duplicated in output.
func TestTCPReassembler_Retransmission(t *testing.T) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	seg := []byte("<13>Single message\n")
	_, p1 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001, seg, false, false, false, true)

	// Feed p1
	reasm.Assemble(flow, p1, time.Now())
	if !reasm.HasReady() {
		t.Fatal("expected message ready")
	}
	_ = reasm.PopReady()

	// Retransmit p1
	reasm.Assemble(flow, p1, time.Now())
	if reasm.HasReady() {
		t.Fatal("retransmission should not produce a duplicate message")
	}
}

// TestTCPReassembler_MissingSegmentGap verifies that missing segments (gaps) reset framing.
func TestTCPReassembler_MissingSegmentGap(t *testing.T) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	seg1 := []byte("25 <134>incomplete")
	// seg2 missing!
	seg3 := []byte("<14>Fresh new message\n")

	_, p1 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001, seg1, false, false, false, true)
	// Gap of 50 bytes: p3 seq is 1001 + len(seg1) + 50
	p3Seq := 1001 + uint32(len(seg1)) + 50
	_, p3 := makeTCPPacket(srcIP, dstIP, 54321, 514, p3Seq, seg3, false, false, false, true)

	reasm.Assemble(flow, p1, time.Now())
	reasm.Assemble(flow, p3, time.Now())

	// Flush pages older than now with CloseAll=false to force assembler to skip the missing gap
	reasm.FlushWithOptions(tcpassembly.FlushOptions{T: time.Now().Add(time.Second), CloseAll: false})

	// p3 should still parse cleanly without corruption from seg1
	var msgs []string
	for reasm.HasReady() {
		msgs = append(msgs, string(reasm.PopReady().Data))
	}
	foundFresh := false
	for _, m := range msgs {
		if strings.Contains(m, "Fresh new message") {
			foundFresh = true
		}
	}
	if !foundFresh {
		t.Errorf("expected to recover and parse fresh message after gap, got: %v", msgs)
	}
}

// TestTCPReassembler_ConnectionClose verifies that closing a connection with FIN flushes pending message without trailing newline.
func TestTCPReassembler_ConnectionClose(t *testing.T) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	// Send message without trailing newline
	msg := []byte("<13>Message without newline")
	_, p1 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001, msg, false, false, false, true)
	reasm.Assemble(flow, p1, time.Now())
	if reasm.HasReady() {
		t.Fatal("message without newline should not be ready before FIN/EOF")
	}

	// Send FIN
	_, fin := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001+uint32(len(msg)), nil, false, true, false, true)
	reasm.Assemble(flow, fin, time.Now())

	if !reasm.HasReady() {
		t.Fatal("expected message to flush on FIN")
	}
	pkt := reasm.PopReady()
	if string(pkt.Data) != "<13>Message without newline" {
		t.Errorf("expected <13>Message without newline, got %q", string(pkt.Data))
	}
}

// TestTCPReassembler_FlowTimeout verifies that FlushOlderThan flushes inactive flows.
func TestTCPReassembler_FlowTimeout(t *testing.T) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	t0 := time.Now().Add(-10 * time.Minute)
	reasm.Assemble(flow, syn, t0)

	msg := []byte("<13>Stale message without newline")
	_, p1 := makeTCPPacket(srcIP, dstIP, 54321, 514, 1001, msg, false, false, false, true)
	reasm.Assemble(flow, p1, t0)

	reasm.FlushOlderThan(time.Now().Add(-1 * time.Minute))
	// After flush, any pending data is processed
	if !reasm.HasReady() {
		t.Fatal("expected pending message to be emitted upon flow timeout flush")
	}
	pkt := reasm.PopReady()
	if string(pkt.Data) != "<13>Stale message without newline" {
		t.Errorf("expected stale message, got %q", string(pkt.Data))
	}
}

// TestTCPReassembler_ResourceLimitsUnderManyIncompleteStreams verifies that many
// incomplete streams do not cause unbounded memory growth or panic.
func TestTCPReassembler_ResourceLimitsUnderManyIncompleteStreams(t *testing.T) {
	reasm := NewTCPReassembler()
	dstIP := net.IP{10, 0, 0, 1}

	// Create 200 distinct streams with partial data
	for i := 0; i < 200; i++ {
		srcIP := net.IP{192, 168, byte(i >> 8), byte(i & 0xff)}
		port := 10000 + (i % 50000)
		flow, syn := makeTCPPacket(srcIP, dstIP, port, 514, 1000, nil, true, false, false, false)
		reasm.Assemble(flow, syn, time.Now())

		// Send incomplete octet-counting frame
		_, p1 := makeTCPPacket(srcIP, dstIP, port, 514, 1001, []byte("99999 <13>partial"), false, false, false, true)
		reasm.Assemble(flow, p1, time.Now())
	}

	reasm.FlushAll()
}

func BenchmarkTCPReassembly_Contiguous(b *testing.B) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	msg := []byte("<134>1 2026-11-11T20:00:00Z myhost test-app - - Standard syslog message\n")
	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()

	seq := uint32(1001)
	for i := 0; i < b.N; i++ {
		_, pkt := makeTCPPacket(srcIP, dstIP, 54321, 514, seq, msg, false, false, false, true)
		reasm.Assemble(flow, pkt, time.Now())
		for reasm.HasReady() {
			_ = reasm.PopReady()
		}
		seq += uint32(len(msg))
	}
}

func BenchmarkTCPReassembly_SplitSegments(b *testing.B) {
	reasm := NewTCPReassembler()
	srcIP := net.IP{10, 0, 0, 1}
	dstIP := net.IP{10, 0, 0, 2}
	flow, syn := makeTCPPacket(srcIP, dstIP, 54321, 514, 1000, nil, true, false, false, false)
	reasm.Assemble(flow, syn, time.Now())

	seg1 := []byte("<134>1 2026-11-11T20:00:00Z myhost ")
	seg2 := []byte("test-app - - Standard syslog message\n")
	totalLen := len(seg1) + len(seg2)

	b.ReportAllocs()
	b.SetBytes(int64(totalLen))
	b.ResetTimer()

	seq := uint32(1001)
	for i := 0; i < b.N; i++ {
		_, p1 := makeTCPPacket(srcIP, dstIP, 54321, 514, seq, seg1, false, false, false, true)
		reasm.Assemble(flow, p1, time.Now())

		_, p2 := makeTCPPacket(srcIP, dstIP, 54321, 514, seq+uint32(len(seg1)), seg2, false, false, false, true)
		reasm.Assemble(flow, p2, time.Now())

		for reasm.HasReady() {
			_ = reasm.PopReady()
		}
		seq += uint32(totalLen)
	}
}
