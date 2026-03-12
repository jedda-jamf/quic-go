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

type hookTrackingCongestion struct {
	maxDatagramSize protocol.ByteCount
	rttStats        *utils.RTTStats

	ackStartTimes         []monotime.Time
	ackStartBytesInFlight []protocol.ByteCount
	ackEndTimes           []monotime.Time
	lossDetectionStarts   int
	ecnAckedBytes         []protocol.ByteCount
	ecnECT0               []int64
	ecnECT1               []int64
	ecnCE                 []int64
	ecnPriorInFlight      []protocol.ByteCount
	ptoBytesInFlight      []protocol.ByteCount
	spuriousLosses        []int
	migrationSizes        []protocol.ByteCount
	appLimitedBytes       []protocol.ByteCount
}

func (*hookTrackingCongestion) TimeUntilSend(protocol.ByteCount) monotime.Time { return 0 }
func (*hookTrackingCongestion) HasPacingBudget(monotime.Time) bool             { return true }
func (*hookTrackingCongestion) OnPacketSent(monotime.Time, protocol.ByteCount, protocol.PacketNumber, protocol.ByteCount, bool) {
}
func (*hookTrackingCongestion) CanSend(protocol.ByteCount) bool { return true }
func (*hookTrackingCongestion) MaybeExitSlowStart()             {}
func (*hookTrackingCongestion) OnPacketAcked(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount, monotime.Time) {
}
func (*hookTrackingCongestion) OnCongestionEvent(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount) {
}
func (*hookTrackingCongestion) OnRetransmissionTimeout(bool) {}
func (h *hookTrackingCongestion) SetMaxDatagramSize(s protocol.ByteCount) {
	h.maxDatagramSize = s
}
func (*hookTrackingCongestion) InSlowStart() bool { return false }
func (*hookTrackingCongestion) InRecovery() bool  { return false }
func (h *hookTrackingCongestion) GetCongestionWindow() protocol.ByteCount {
	return h.maxDatagramSize * 10
}
func (h *hookTrackingCongestion) SetRTTStats(rttStats *utils.RTTStats) { h.rttStats = rttStats }
func (h *hookTrackingCongestion) OnAckEventStart(eventTime monotime.Time, bytesInFlight protocol.ByteCount) {
	h.ackStartTimes = append(h.ackStartTimes, eventTime)
	h.ackStartBytesInFlight = append(h.ackStartBytesInFlight, bytesInFlight)
}
func (h *hookTrackingCongestion) OnAckEventEnd(eventTime monotime.Time) {
	h.ackEndTimes = append(h.ackEndTimes, eventTime)
}
func (h *hookTrackingCongestion) OnLossDetectionStart() { h.lossDetectionStarts++ }
func (h *hookTrackingCongestion) OnECNFeedback(
	ackedBytes protocol.ByteCount,
	ect0Total, ect1Total, ceTotal int64,
	priorInFlight protocol.ByteCount,
	_ monotime.Time,
) {
	h.ecnAckedBytes = append(h.ecnAckedBytes, ackedBytes)
	h.ecnECT0 = append(h.ecnECT0, ect0Total)
	h.ecnECT1 = append(h.ecnECT1, ect1Total)
	h.ecnCE = append(h.ecnCE, ceTotal)
	h.ecnPriorInFlight = append(h.ecnPriorInFlight, priorInFlight)
}
func (h *hookTrackingCongestion) MarkAppLimited(bytesInFlight protocol.ByteCount) {
	h.appLimitedBytes = append(h.appLimitedBytes, bytesInFlight)
}
func (h *hookTrackingCongestion) OnSpuriousLossDetected(spuriousCount int) {
	h.spuriousLosses = append(h.spuriousLosses, spuriousCount)
}
func (h *hookTrackingCongestion) OnPTO(bytesInFlight protocol.ByteCount) {
	h.ptoBytesInFlight = append(h.ptoBytesInFlight, bytesInFlight)
}
func (h *hookTrackingCongestion) OnConnectionMigration(initialMaxDatagramSize protocol.ByteCount) {
	h.migrationSizes = append(h.migrationSizes, initialMaxDatagramSize)
	h.maxDatagramSize = initialMaxDatagramSize
}

type fallbackOnlyCongestion struct {
	maxDatagramSize protocol.ByteCount
}

func (*fallbackOnlyCongestion) TimeUntilSend(protocol.ByteCount) monotime.Time { return 0 }
func (*fallbackOnlyCongestion) HasPacingBudget(monotime.Time) bool             { return true }
func (*fallbackOnlyCongestion) OnPacketSent(monotime.Time, protocol.ByteCount, protocol.PacketNumber, protocol.ByteCount, bool) {
}
func (*fallbackOnlyCongestion) CanSend(protocol.ByteCount) bool { return true }
func (*fallbackOnlyCongestion) MaybeExitSlowStart()             {}
func (*fallbackOnlyCongestion) OnPacketAcked(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount, monotime.Time) {
}
func (*fallbackOnlyCongestion) OnCongestionEvent(protocol.PacketNumber, protocol.ByteCount, protocol.ByteCount) {
}
func (*fallbackOnlyCongestion) OnRetransmissionTimeout(bool) {}
func (f *fallbackOnlyCongestion) SetMaxDatagramSize(s protocol.ByteCount) {
	f.maxDatagramSize = s
}
func (*fallbackOnlyCongestion) InSlowStart() bool { return false }
func (*fallbackOnlyCongestion) InRecovery() bool  { return false }
func (f *fallbackOnlyCongestion) GetCongestionWindow() protocol.ByteCount {
	return f.maxDatagramSize * 10
}

func TestSentPacketHandlerBindsCustomControllerState(t *testing.T) {
	rttStats := utils.NewRTTStats()
	cong := &hookTrackingCongestion{}

	sph := NewSentPacketHandler(
		0,
		1234,
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

	handler := sph.(*sentPacketHandler)
	require.False(t, handler.usesDefaultCongestion)
	require.Same(t, cong, handler.congestion)
	require.Same(t, rttStats, cong.rttStats)
	require.Equal(t, protocol.ByteCount(1234), cong.maxDatagramSize)
}

func TestSentPacketHandlerMigrationHookForCustomController(t *testing.T) {
	cong := &hookTrackingCongestion{}
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		cong,
		utils.DefaultLogger,
	)

	handler := sph.(*sentPacketHandler)
	handler.MigratedPath(monotime.Now(), 1400)

	require.Same(t, cong, handler.congestion)
	require.Equal(t, []protocol.ByteCount{1400}, cong.migrationSizes)
}

func TestSentPacketHandlerMigrationFallsBackWithoutHook(t *testing.T) {
	cong := &fallbackOnlyCongestion{}
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		cong,
		utils.DefaultLogger,
	)

	handler := sph.(*sentPacketHandler)
	handler.MigratedPath(monotime.Now(), 1400)

	require.NotSame(t, cong, handler.congestion)
}

func TestSentPacketHandlerNotifiesAckLossAndECNHooks(t *testing.T) {
	now := monotime.Now()
	cong := &hookTrackingCongestion{}
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		cong,
		utils.DefaultLogger,
	)

	pn := sph.PopPacketNumber(protocol.Encryption1RTT)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECT0, 1200, false, false)

	acked, err := sph.ReceivedAck(&wire.AckFrame{
		AckRanges: []wire.AckRange{{Smallest: pn, Largest: pn}},
		ECT0:      1,
	}, protocol.Encryption1RTT, now.Add(20*time.Millisecond))
	require.NoError(t, err)
	require.True(t, acked)

	require.Equal(t, 1, cong.lossDetectionStarts)
	require.Len(t, cong.ackStartTimes, 1)
	require.Len(t, cong.ackEndTimes, 1)
	require.Equal(t, []protocol.ByteCount{1200}, cong.ackStartBytesInFlight)
	require.Equal(t, []protocol.ByteCount{1200}, cong.ecnAckedBytes)
	require.Equal(t, []int64{1}, cong.ecnECT0)
	require.Equal(t, []int64{0}, cong.ecnECT1)
	require.Equal(t, []int64{0}, cong.ecnCE)
	require.Equal(t, []protocol.ByteCount{1200}, cong.ecnPriorInFlight)
}

func TestSentPacketHandlerNotifiesPTOHook(t *testing.T) {
	now := monotime.Now()
	cong := &hookTrackingCongestion{}
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		cong,
		utils.DefaultLogger,
	)

	pn := sph.PopPacketNumber(protocol.EncryptionInitial)
	sph.SentPacket(now, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.EncryptionInitial, protocol.ECNNon, 1200, false, false)

	timeout := sph.GetLossDetectionTimeout()
	require.NotZero(t, timeout)
	require.NoError(t, sph.OnLossDetectionTimeout(timeout))
	require.Equal(t, []protocol.ByteCount{1200}, cong.ptoBytesInFlight)
}

func TestSentPacketHandlerNotifiesSpuriousLossHook(t *testing.T) {
	now := monotime.Now()
	cong := &hookTrackingCongestion{}
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		cong,
		utils.DefaultLogger,
	)

	var firstSendTime monotime.Time
	for i := range 4 {
		pn := sph.PopPacketNumber(protocol.Encryption1RTT)
		sendTime := now.Add(time.Duration(i) * time.Millisecond)
		if i == 0 {
			firstSendTime = sendTime
		}
		sph.SentPacket(sendTime, pn, protocol.InvalidPacketNumber, nil, []Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 1200, false, false)
	}

	handler := sph.(*sentPacketHandler)
	handler.lostPackets.Add(0, firstSendTime)
	handler.detectSpuriousLosses(
		&wire.AckFrame{
			AckRanges: []wire.AckRange{
				{Smallest: 4, Largest: 4},
				{Smallest: 0, Largest: 0},
			},
		},
		now.Add(10*time.Millisecond),
	)

	require.Equal(t, []int{1}, cong.spuriousLosses)
}
