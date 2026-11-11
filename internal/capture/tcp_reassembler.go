package capture

import (
	"bytes"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

const (
	maxStreamBufferBytes = 65535
	maxMessageBytes      = 65535
	maxConcurrentFlows   = 1024
)

// TCPReassembler coordinates TCP stream reassembly for syslog streams.
type TCPReassembler struct {
	asmMu       sync.Mutex
	readyMu     sync.Mutex
	streamPool  *tcpassembly.StreamPool
	assembler   *tcpassembly.Assembler
	factory     *syslogStreamFactory
	ready       []*PacketData
	activeFlows int
}

// syslogStreamFactory implements tcpassembly.StreamFactory.
type syslogStreamFactory struct {
	reasm *TCPReassembler
}

func (f *syslogStreamFactory) New(netFlow, tcpFlow gopacket.Flow) tcpassembly.Stream {
	f.reasm.readyMu.Lock()
	f.reasm.activeFlows++
	f.reasm.readyMu.Unlock()

	var srcIP netip.Addr
	if addr, ok := netip.AddrFromSlice(netFlow.Src().Raw()); ok {
		srcIP = addr.Unmap()
	}

	return &syslogStream{
		reasm: f.reasm,
		srcIP: srcIP,
	}
}

// syslogStream implements tcpassembly.Stream.
type syslogStream struct {
	reasm    *TCPReassembler
	srcIP    netip.Addr
	buf      []byte
	lastSeen time.Time
}

// Reassembled handles contiguous in-order bytes for a TCP stream.
func (s *syslogStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	for _, r := range reassemblies {
		if !r.Seen.IsZero() {
			s.lastSeen = r.Seen
		}
		// If bytes were skipped (gap in TCP sequence), stream synchronization is lost.
		// Reset incomplete buffer to avoid corrupting syslog messages.
		if r.Skip > 0 {
			s.buf = nil
		}

		if len(r.Bytes) > 0 {
			// Check per-flow buffer limit (adversarial protection)
			if len(s.buf)+len(r.Bytes) > maxStreamBufferBytes {
				// Buffer overflowed: reset buffer to bounded state
				s.buf = nil
				continue
			}
			s.buf = append(s.buf, r.Bytes...)
			s.extractMessages(r.Seen)
		}

		if r.End {
			// Stream ended (FIN/RST seen)
			s.flushRemaining(r.Seen)
		}
	}
}

// extractMessages extracts all complete syslog frames (RFC 6587 octet-counted or LF-delimited) from s.buf.
func (s *syslogStream) extractMessages(seen time.Time) {
	for len(s.buf) > 0 {
		// 1. Check for RFC 6587 octet-counted framing: starts with ASCII digits followed by space
		if s.buf[0] >= '1' && s.buf[0] <= '9' {
			idxSpace := bytes.IndexByte(s.buf, ' ')
			if idxSpace == -1 {
				// Space not found yet. If buffer has > 10 digits without space, it cannot be a valid length prefix.
				if len(s.buf) > 10 {
					s.scanLF(seen)
				}
				return
			}
			if idxSpace > 10 {
				// Length prefix exceeds 10 digits - invalid
				s.buf = s.buf[idxSpace+1:]
				continue
			}

			// Validate that all bytes before space are digits
			allDigits := true
			for i := 0; i < idxSpace; i++ {
				if s.buf[i] < '0' || s.buf[i] > '9' {
					allDigits = false
					break
				}
			}
			if !allDigits {
				if !s.scanLF(seen) {
					return
				}
				continue
			}

			msgLen, err := strconv.Atoi(string(s.buf[:idxSpace]))
			if err != nil || msgLen <= 0 || msgLen > maxMessageBytes {
				s.buf = s.buf[idxSpace+1:]
				continue
			}

			msgStart := idxSpace + 1
			if len(s.buf) < msgStart+msgLen {
				// Incomplete frame: wait for remaining bytes
				return
			}

			// Complete octet-counted message extracted
			msg := make([]byte, msgLen)
			copy(msg, s.buf[msgStart:msgStart+msgLen])
			s.emitPacket(msg, seen)

			// Advance buffer past message
			s.buf = s.buf[msgStart+msgLen:]
			// Trim optional newline / space after octet-counted message
			s.buf = bytes.TrimLeft(s.buf, "\r\n")
			continue
		}

		// 2. Non-transparent framing (LF-delimited)
		if !s.scanLF(seen) {
			return
		}
	}
}

// scanLF attempts to extract an LF-delimited message from s.buf.
// Returns true if a message was extracted, false if more bytes are needed.
func (s *syslogStream) scanLF(seen time.Time) bool {
	idxNL := bytes.IndexByte(s.buf, '\n')
	if idxNL == -1 {
		if len(s.buf) >= maxMessageBytes {
			s.buf = nil
		}
		return false
	}

	raw := s.buf[:idxNL]
	msg := bytes.TrimRight(raw, "\r\x00")
	if len(msg) > 0 {
		msgCopy := make([]byte, len(msg))
		copy(msgCopy, msg)
		s.emitPacket(msgCopy, seen)
	}

	s.buf = s.buf[idxNL+1:]
	return true
}

func (s *syslogStream) flushRemaining(seen time.Time) {
	if len(s.buf) > 0 {
		msg := bytes.Trim(s.buf, "\r\n\x00")
		if len(msg) > 0 {
			msgCopy := make([]byte, len(msg))
			copy(msgCopy, msg)
			s.emitPacket(msgCopy, seen)
		}
		s.buf = nil
	}
}

func (s *syslogStream) emitPacket(data []byte, ts time.Time) {
	s.reasm.readyMu.Lock()
	defer s.reasm.readyMu.Unlock()
	s.reasm.ready = append(s.reasm.ready, &PacketData{
		Data:      data,
		SrcIP:     s.srcIP,
		Timestamp: ts,
		Transport: "tcp",
	})
}

// ReassemblyComplete is called when assembly finishes with this stream.
func (s *syslogStream) ReassemblyComplete() {
	s.flushRemaining(s.lastSeen)
	s.reasm.readyMu.Lock()
	defer s.reasm.readyMu.Unlock()
	if s.reasm.activeFlows > 0 {
		s.reasm.activeFlows--
	}
}

// NewTCPReassembler creates a new TCPReassembler with bounded assembly options.
func NewTCPReassembler() *TCPReassembler {
	r := &TCPReassembler{}
	r.factory = &syslogStreamFactory{reasm: r}
	r.streamPool = tcpassembly.NewStreamPool(r.factory)
	r.assembler = tcpassembly.NewAssembler(r.streamPool)
	r.assembler.AssemblerOptions = tcpassembly.AssemblerOptions{
		MaxBufferedPagesTotal:         1024,
		MaxBufferedPagesPerConnection: 64,
	}
	return r
}

// Assemble passes a TCP packet to the stream assembler.
func (r *TCPReassembler) Assemble(netFlow gopacket.Flow, tcp *layers.TCP, timestamp time.Time) {
	r.asmMu.Lock()
	defer r.asmMu.Unlock()
	r.assembler.AssembleWithTimestamp(netFlow, tcp, timestamp)
}

// FlushOlderThan flushes inactive connections older than t.
func (r *TCPReassembler) FlushOlderThan(t time.Time) {
	r.asmMu.Lock()
	defer r.asmMu.Unlock()
	r.assembler.FlushOlderThan(t)
}

// FlushWithOptions flushes connections according to opt.
func (r *TCPReassembler) FlushWithOptions(opt tcpassembly.FlushOptions) (flushed, closed int) {
	r.asmMu.Lock()
	defer r.asmMu.Unlock()
	return r.assembler.FlushWithOptions(opt)
}

// FlushAll flushes all connections and closes them.
func (r *TCPReassembler) FlushAll() {
	r.asmMu.Lock()
	defer r.asmMu.Unlock()
	r.assembler.FlushAll()
}

// PopReady retrieves the next reassembled packet, if any.
func (r *TCPReassembler) PopReady() *PacketData {
	r.readyMu.Lock()
	defer r.readyMu.Unlock()
	if len(r.ready) == 0 {
		return nil
	}
	pkt := r.ready[0]
	r.ready = r.ready[1:]
	return pkt
}

// HasReady returns true if reassembled packets are waiting.
func (r *TCPReassembler) HasReady() bool {
	r.readyMu.Lock()
	defer r.readyMu.Unlock()
	return len(r.ready) > 0
}

// ActiveFlows returns the count of actively tracked streams.
func (r *TCPReassembler) ActiveFlows() int {
	r.readyMu.Lock()
	defer r.readyMu.Unlock()
	return r.activeFlows
}
