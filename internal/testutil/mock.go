package testutil

import (
	"io"

	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
)

// MockPacketSource is an in-memory packet source for testing.
type MockPacketSource struct {
	packets            []*capture.PacketData
	idx                int
	ReturnEOFOnExhaust bool
	MockStats          *capture.Stats
}

// NewMockPacketSource creates a mock packet source with a predetermined packet sequence.
func NewMockPacketSource(packets []*capture.PacketData) *MockPacketSource {
	return &MockPacketSource{
		packets: packets,
	}
}

// Stats returns the configured MockStats.
func (m *MockPacketSource) Stats() (*capture.Stats, error) {
	return m.MockStats, nil
}

// NextPacket returns the next mock packet or (nil, nil) (or io.EOF if ReturnEOFOnExhaust is set) when exhausted.
func (m *MockPacketSource) NextPacket() (*capture.PacketData, error) {
	if m.idx >= len(m.packets) {
		if m.ReturnEOFOnExhaust {
			return nil, io.EOF
		}
		return nil, nil
	}
	pkt := m.packets[m.idx]
	m.idx++
	return pkt, nil
}

// Close is a no-op for MockPacketSource.
func (m *MockPacketSource) Close() error {
	return nil
}
