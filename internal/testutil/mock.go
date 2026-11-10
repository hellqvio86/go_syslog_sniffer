package testutil

import (
	"io"

	"github.com/hellqvio86/go_syslog_sniffer/internal/capture"
)

// MockPacketSource is an in-memory packet source for testing.
type MockPacketSource struct {
	packets                      []*capture.PacketData
	idx                          int
	ReturnEOFOnExhaust           bool
	ReturnCaptureClosedOnExhaust bool
	MockStats                    *capture.Stats
	StatsFunc                    func() (*capture.Stats, error)
}

// NewMockPacketSource creates a mock packet source with a predetermined packet sequence.
func NewMockPacketSource(packets []*capture.PacketData) *MockPacketSource {
	return &MockPacketSource{
		packets: packets,
	}
}

// Stats returns the configured MockStats or invokes StatsFunc if provided.
func (m *MockPacketSource) Stats() (*capture.Stats, error) {
	if m.StatsFunc != nil {
		return m.StatsFunc()
	}
	return m.MockStats, nil
}

// NextPacket returns the next mock packet or (nil, nil) (or io.EOF / ErrCaptureClosed if set) when exhausted.
func (m *MockPacketSource) NextPacket() (*capture.PacketData, error) {
	if m.idx >= len(m.packets) {
		if m.ReturnCaptureClosedOnExhaust {
			return nil, capture.ErrCaptureClosed
		}
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
