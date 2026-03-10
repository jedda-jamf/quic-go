package congestion

import (
	"math/rand"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func newTestBBRv3() *BBRv3 {
	return NewBBRV3(DefaultClock{}, utils.NewRTTStats(), nil, initialMaxDatagramSize, false, nil)
}

func TestBBRv3PacingBudget(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	require.True(t, bbr.HasPacingBudget(now))
	for i := 0; i < 20; i++ {
		bbr.OnPacketSent(now, 0, protocol.PacketNumber(i+1), initialMaxDatagramSize, true)
	}
	require.False(t, bbr.HasPacingBudget(now))
	require.True(t, bbr.HasPacingBudget(now.Add(200*time.Millisecond)))
}

func TestBBRv3StartupExitByFullBwPlateau(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRStartup
	bbr.fullBandwidth = 1_000
	bbr.bwHi[0] = 1_000
	bbr.minRTT = 10 * time.Millisecond

	rs := bbrRateSample{deliveryRate: 1_100}
	for range FULL_BW_ROUNDS {
		bbr.roundStart = true
		bbr.checkFullBwReached(rs)
	}
	require.True(t, bbr.fullBandwidthReached)

	bbr.checkDrain(bbrRateSample{bytesInFlight: 1_000_000}, monotime.Now())
	require.Equal(t, BBRDrain, bbr.state)
}

func TestBBRv3StartupExitByExcessiveLoss(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRStartup
	bbr.lossRoundStart = true
	bbr.lossEventsInRound = STARTUP_FULL_LOSS_COUNT
	bbr.bytesLostInRound = 3_000
	bbr.bwHi[0] = 1_000_000
	bbr.minRTT = 10 * time.Millisecond

	bbr.checkLossTooHighInStartup(bbrRateSample{txInFlight: 100_000, priorInFlight: 100_000})
	require.True(t, bbr.fullBandwidthReached)
	require.NotEqual(t, protocol.MaxByteCount, bbr.inflightHi)
}

func TestBBRv3StartupExitByExcessiveECN(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRStartup
	bbr.ecnEligible = true

	for range FULL_ECN_ROUNDS {
		bbr.totalBytesAcked += 10_000
		bbr.totalBytesAckedCE += 6_000
		bbr.roundStart = true
		bbr.updateECNAlpha(bbrRateSample{})
	}

	require.True(t, bbr.fullBandwidthReached)
	require.GreaterOrEqual(t, bbr.startupECNRounds, FULL_ECN_ROUNDS)
}

func TestBBRv3DrainCompletionAndProbeBWTransitions(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()
	bbr.state = BBRDrain
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 1_000_000
	bbr.minRTT = 10 * time.Millisecond

	bbr.checkDrain(bbrRateSample{bytesInFlight: 5_000}, now)
	require.Equal(t, BBRProbeBW, bbr.state)
	require.Equal(t, probeBWDown, bbr.probeBWPhase)

	bbr.probeBWPhase = probeBWCruise
	bbr.probeWait = time.Millisecond
	bbr.cycleStamp = now.Add(-2 * time.Millisecond)
	bbr.updateCyclePhase(bbrRateSample{}, now)
	require.Equal(t, probeBWRefill, bbr.probeBWPhase)

	bbr.roundStart = true
	bbr.updateCyclePhase(bbrRateSample{}, now)
	require.Equal(t, probeBWUp, bbr.probeBWPhase)

	bbr.prevProbeTooHigh = true
	bbr.inflightHi = 10_000
	bbr.updateCyclePhase(bbrRateSample{bytesInFlight: 10_000}, now)
	require.Equal(t, probeBWDown, bbr.probeBWPhase)
}

func TestBBRv3ProbeTimingWallClockAndRenoRoundTrigger(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()
	bbr.rng = rand.New(rand.NewSource(1))
	bbr.pickProbeWait()

	require.GreaterOrEqual(t, bbr.probeWait, PROBE_WAIT_BASE)
	require.Less(t, bbr.probeWait, PROBE_WAIT_BASE+PROBE_WAIT_RAND_MAX)

	bbr.cycleStamp = now.Add(-bbr.probeWait - time.Nanosecond)
	require.True(t, bbr.checkTimeToProbeBW(now))

	bbr.cycleStamp = now
	bbr.probeWait = time.Hour
	bbr.minRTT = 10 * time.Millisecond
	bbr.bwHi[0] = 2_000_000
	bbr.congestionWindow = 20_000
	bbr.roundsSinceProbe = 16
	require.True(t, bbr.isRenoCoexistenceProbeTime())
	require.True(t, bbr.checkTimeToProbeBW(now))
}

func TestBBRv3UpperAndLowerBoundAdaptation(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWUp
	bbr.inflightHi = 10_000
	bbr.congestionWindow = 20_000
	bbr.adaptUpperBounds(bbrRateSample{txInFlight: 12_000, priorInFlight: 20_000, newlyAcked: 2_400}, now)
	require.GreaterOrEqual(t, bbr.inflightHi, protocol.ByteCount(12_000))

	bbr.probeBWPhase = probeBWCruise
	bbr.lossInRound = true
	bbr.ecnInRound = false
	bbr.bwLatest = 1_000
	bbr.inflightLatest = 10_000
	bbr.bwLo = 2_000
	bbr.inflightLo = 20_000
	bbr.adaptLowerBounds(bbrRateSample{})
	require.Equal(t, protocol.ByteCount(1_400), bbr.bwLo)
	require.Equal(t, protocol.ByteCount(14_000), bbr.inflightLo)

	bbr.lossInRound = false
	bbr.ecnInRound = true
	bbr.ecnAlpha = 0.6
	bbr.inflightLo = 30_000
	bbr.adaptLowerBounds(bbrRateSample{})
	require.Equal(t, protocol.ByteCount(24_000), bbr.inflightLo)
}

func TestBBRv3ProbeRTTEnterExitAndIdleRestartSuppression(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(25*time.Millisecond, 0)
	bbr := NewBBRV3(DefaultClock{}, rttStats, nil, initialMaxDatagramSize, false, nil)
	now := monotime.Now()

	bbr.state = BBRProbeBW
	bbr.fullBandwidthReached = true
	bbr.idleRestart = false
	bbr.congestionWindow = 100 * bbr.maxDatagramSize
	bbr.probeRTTMinStamp = now.Add(-PROBE_RTT_INTERVAL - time.Millisecond)
	originalCwnd := bbr.congestionWindow

	bbr.updateMinRTT(now)
	require.Equal(t, BBRProbeRTT, bbr.state)
	require.Equal(t, originalCwnd, bbr.priorCwnd)
	require.False(t, bbr.probeRTTDoneStamp.IsZero())

	t1 := now
	bbr.probeRTTRoundDone = false
	bbr.roundStart = false
	bbr.updateMinRTT(t1.Add(PROBE_RTT_DURATION + time.Millisecond))
	require.Equal(t, BBRProbeRTT, bbr.state)

	bbr.roundStart = true
	bbr.updateMinRTT(t1.Add(PROBE_RTT_DURATION + 2*time.Millisecond))
	require.Equal(t, BBRProbeBW, bbr.state)
	require.GreaterOrEqual(t, bbr.congestionWindow, originalCwnd)

	rttStats2 := utils.NewRTTStats()
	rttStats2.UpdateRTT(20*time.Millisecond, 0)
	idleRestart := NewBBRV3(DefaultClock{}, rttStats2, nil, initialMaxDatagramSize, false, nil)
	idleRestart.state = BBRProbeBW
	idleRestart.idleRestart = true
	idleRestart.probeRTTMinStamp = now.Add(-PROBE_RTT_INTERVAL - time.Millisecond)
	idleRestart.updateMinRTT(now)
	require.NotEqual(t, BBRProbeRTT, idleRestart.state)
}

func TestBBRv3AckAggregationRaisesCwndTarget(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWCruise
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 1_000_000
	bbr.minRTT = 20 * time.Millisecond
	bbr.cwndGain = CWND_GAIN_DEFAULT

	baseTarget := bbr.targetCwnd(bbr.cwndGain)
	bbr.congestionWindow = baseTarget - 500
	bbr.extraAcked = [2]protocol.ByteCount{}
	bbr.setCwnd(bbrRateSample{newlyAcked: 1_000})
	withoutExtraAcked := bbr.congestionWindow

	bbr.congestionWindow = baseTarget - 500
	bbr.extraAcked[0] = 20_000
	bbr.setCwnd(bbrRateSample{newlyAcked: 1_000})
	withExtraAcked := bbr.congestionWindow

	require.Greater(t, withExtraAcked, withoutExtraAcked)
}

func TestBBRv3OnAckEventEndFlushesPendingAckEvent(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	bbr.OnPacketSent(now, 1_200, 1, 1_200, true)
	bbr.OnPacketAcked(1, 1_200, 1_200, now.Add(10*time.Millisecond))
	require.Equal(t, protocol.ByteCount(1_200), bbr.pendingAckedBytes)
	require.Equal(t, protocol.ByteCount(0), bbr.maxBandwidth())

	bbr.OnAckEventEnd(now.Add(10 * time.Millisecond))
	require.Equal(t, protocol.ByteCount(0), bbr.pendingAckedBytes)
	require.Greater(t, bbr.maxBandwidth(), protocol.ByteCount(0))
}

func TestBBRv3Name(t *testing.T) {
	bbr := newTestBBRv3()
	require.Equal(t, "BBRv3", bbr.Name())
}

func TestBBRv3SetRTTStats(t *testing.T) {
	bbr := newTestBBRv3()
	newStats := utils.NewRTTStats()
	bbr.SetRTTStats(newStats)
	require.Equal(t, newStats, bbr.rttStats)
}

func TestBBRv3StateString(t *testing.T) {
	require.Equal(t, "startup", BBRStartup.String())
	require.Equal(t, "drain", BBRDrain.String())
	require.Equal(t, "probe_bw", BBRProbeBW.String())
	require.Equal(t, "probe_rtt", BBRProbeRTT.String())
	require.Equal(t, "unknown", BBRState(99).String())
}

func TestBBRv3PhaseString(t *testing.T) {
	require.Equal(t, "up", probeBWUp.String())
	require.Equal(t, "down", probeBWDown.String())
	require.Equal(t, "cruise", probeBWCruise.String())
	require.Equal(t, "refill", probeBWRefill.String())
	require.Equal(t, "unknown", bbrProbeBWPhase(99).String())
}
