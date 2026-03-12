package congestion

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestBBRv3ConnectionMigrationResetsControllerState(t *testing.T) {
	rttStats := utils.NewRTTStats()
	bbr := NewBBRV3(DefaultClock{}, rttStats, nil, initialMaxDatagramSize, false, nil)
	oldPacer := bbr.pacer

	bbr.state = BBRProbeRTT
	bbr.probeBWPhase = probeBWUp
	bbr.ackPhase = ackPhaseProbeStopping
	bbr.pacingGain = 7
	bbr.cwndGain = 9
	bbr.pacingRate = 12345
	bbr.fullBandwidthReached = true
	bbr.fullBandwidth = 55_000
	bbr.fullBandwidthCount = 3
	bbr.startupECNRounds = 2
	bbr.roundCount = 9
	bbr.roundsSinceProbe = 4
	bbr.lossRoundDelivered = 888
	bbr.lossRoundStart = true
	bbr.lossInRound = true
	bbr.ecnInRound = true
	bbr.lossInCycle = true
	bbr.ecnInCycle = true
	bbr.totalBytesSent = 123
	bbr.totalBytesAcked = 456
	bbr.totalBytesLost = 789
	bbr.totalBytesAckedCE = 321
	bbr.ecnAlpha = 0.25
	bbr.priorCwnd = 777
	bbr.idleRestart = true
	bbr.ptoRecovery = true
	bbr.sendQuantum = 11 * bbr.maxDatagramSize
	bbr.offloadBudget = 13 * bbr.maxDatagramSize
	bbr.appLimitedUntil = 9_999
	bbr.pendingAckEventValid = true
	bbr.pendingECNEventValid = true
	bbr.sentPackets[99] = bbrSentPacketState{bytes: bbr.maxDatagramSize}

	bbr.OnConnectionMigration(1400)

	require.Same(t, rttStats, bbr.rttStats)
	require.NotNil(t, bbr.pacer)
	require.NotSame(t, oldPacer, bbr.pacer)
	require.Equal(t, protocol.ByteCount(1400), bbr.maxDatagramSize)
	require.Equal(t, protocol.ByteCount(initialCongestionWindow*1400), bbr.congestionWindow)
	require.Equal(t, protocol.ByteCount(4*1400), bbr.minPipeCwnd)
	require.Equal(t, protocol.ByteCount(initialCongestionWindow*1400), bbr.initialCwnd)
	require.Equal(t, protocol.ByteCount(2*1400), bbr.sendQuantum)
	require.Equal(t, bbr.sendQuantum, bbr.offloadBudget)
	require.Equal(t, BBRStartup, bbr.state)
	require.Equal(t, probeBWDown, bbr.probeBWPhase)
	require.Equal(t, ackPhaseInit, bbr.ackPhase)
	require.Equal(t, STARTUP_PACING_GAIN, bbr.pacingGain)
	require.Equal(t, STARTUP_CWND_GAIN, bbr.cwndGain)
	require.False(t, bbr.fullBandwidthReached)
	require.Zero(t, bbr.fullBandwidth)
	require.Zero(t, bbr.fullBandwidthCount)
	require.Zero(t, bbr.startupECNRounds)
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo)
	require.Equal(t, protocol.MaxByteCount, bbr.inflightHi)
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo)
	require.Zero(t, bbr.bwLatest)
	require.Zero(t, bbr.inflightLatest)
	require.Zero(t, bbr.roundCount)
	require.Zero(t, bbr.roundsSinceProbe)
	require.Zero(t, bbr.totalBytesSent)
	require.Zero(t, bbr.totalBytesAcked)
	require.Zero(t, bbr.totalBytesLost)
	require.Zero(t, bbr.totalBytesAckedCE)
	require.Equal(t, 1.0, bbr.ecnAlpha)
	require.Zero(t, bbr.priorCwnd)
	require.False(t, bbr.idleRestart)
	require.False(t, bbr.ptoRecovery)
	require.Zero(t, bbr.appLimitedUntil)
	require.False(t, bbr.pendingAckEventValid)
	require.False(t, bbr.pendingECNEventValid)
	require.Empty(t, bbr.sentPackets)
}
