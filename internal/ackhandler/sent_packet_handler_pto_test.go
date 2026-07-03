package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

type ptoTrackingSendAlgorithm struct {
	ptoInflight []protocol.ByteCount
}

func (*ptoTrackingSendAlgorithm) TimeUntilSend(protocol.ByteCount) monotime.Time { return 0 }
func (*ptoTrackingSendAlgorithm) HasPacingBudget(monotime.Time) bool             { return true }
func (*ptoTrackingSendAlgorithm) OnPacketSent(monotime.Time, protocol.ByteCount, protocol.PacketNumber, protocol.ByteCount, bool) {
}
func (*ptoTrackingSendAlgorithm) CanSend(protocol.ByteCount) bool { return true }
func (*ptoTrackingSendAlgorithm) MaybeExitSlowStart()             {}
func (*ptoTrackingSendAlgorithm) OnPacketAcked(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount, monotime.Time) {
}
func (*ptoTrackingSendAlgorithm) OnCongestionEvent(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount) {
}
func (*ptoTrackingSendAlgorithm) OnRetransmissionTimeout(bool)          {}
func (*ptoTrackingSendAlgorithm) SetMaxDatagramSize(protocol.ByteCount) {}
func (*ptoTrackingSendAlgorithm) InSlowStart() bool                     { return false }
func (*ptoTrackingSendAlgorithm) InRecovery() bool                      { return false }
func (*ptoTrackingSendAlgorithm) GetCongestionWindow() protocol.ByteCount {
	return 32 * 1200
}
func (c *ptoTrackingSendAlgorithm) OnPTO(_ monotime.Time, bytesInFlight protocol.ByteCount) {
	c.ptoInflight = append(c.ptoInflight, bytesInFlight)
}

func TestSentPacketHandlerPTONotifiesOptionalTimeoutHandler(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(200*time.Millisecond, 0)
	cong := &ptoTrackingSendAlgorithm{}
	sph := NewSentPacketHandler(
		0,
		1200,
		rttStats,
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		cong,
		utils.DefaultLogger,
	)

	now := monotime.Now()
	pn := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 1000, false, false)

	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	require.NoError(t, sph.OnLossDetectionTimeout(timeout))
	require.Equal(t, []protocol.ByteCount{1000}, cong.ptoInflight)
}
