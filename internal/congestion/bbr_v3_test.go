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

func TestBBRv3SpuriousLossRecovery(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up in ProbeBW CRUISE state (where loss responses apply)
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWCruise
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 1_000_000
	bbr.minRTT = 20 * time.Millisecond
	bbr.congestionWindow = 100_000

	// Initialize bounds to non-MaxByteCount values
	bbr.bwLo = 800_000
	bbr.inflightLo = 80_000
	bbr.inflightHi = 120_000

	// Simulate loss detection - this saves state
	bbr.OnPacketSent(now, 0, 1, 1200, true)
	bbr.OnCongestionEvent(1, 1200, 0)

	// Verify state was saved
	require.Equal(t, BBRProbeBW, bbr.undoState)
	require.Equal(t, protocol.ByteCount(800_000), bbr.undoBwLo)
	require.Equal(t, protocol.ByteCount(80_000), bbr.undoInflightLo)
	require.Equal(t, protocol.ByteCount(120_000), bbr.undoInflightHi)

	// Now simulate the round ending with loss - this triggers bound adaptation
	bbr.roundStart = true
	bbr.lossRoundStart = true
	bbr.bwLatest = 700_000
	bbr.inflightLatest = 70_000
	bbr.adaptLowerBounds(bbrRateSample{})

	// Verify bounds were reduced (by BETA_REDUCTION = 30%)
	expectedBwLo := protocol.ByteCount(float64(800_000) * 0.70)       // 560_000
	expectedInflightLo := protocol.ByteCount(float64(80_000) * 0.70) // 56_000
	require.Equal(t, max(bbr.bwLatest, expectedBwLo), bbr.bwLo)
	require.Equal(t, max(bbr.inflightLatest, expectedInflightLo), bbr.inflightLo)

	// Now call OnSpuriousLossDetected - this should restore bounds
	bbr.OnSpuriousLossDetected(1)

	// Verify bounds were restored to saved values (using max)
	require.Equal(t, protocol.ByteCount(800_000), bbr.bwLo)
	require.Equal(t, protocol.ByteCount(80_000), bbr.inflightLo)
	require.Equal(t, protocol.ByteCount(120_000), bbr.inflightHi)
	require.False(t, bbr.lossInRound)
}

func TestBBRv3SpuriousLossRecoveryRestoresStartupState(t *testing.T) {
	bbr := newTestBBRv3()

	// Start in Startup
	bbr.state = BBRStartup
	bbr.fullBandwidthReached = false
	bbr.pacingGain = STARTUP_PACING_GAIN
	bbr.cwndGain = STARTUP_CWND_GAIN

	// Simulate loss causing exit to Drain (save state first)
	bbr.saveStateUponLoss()
	bbr.state = BBRDrain
	bbr.fullBandwidthReached = true

	// Spurious loss detected - should restore Startup state
	bbr.OnSpuriousLossDetected(1)

	require.Equal(t, BBRStartup, bbr.state)
	require.Equal(t, STARTUP_PACING_GAIN, bbr.pacingGain)
	require.Equal(t, STARTUP_CWND_GAIN, bbr.cwndGain)
	require.False(t, bbr.fullBandwidthReached)
}

func TestBBRv3SpuriousLossRecoveryRestoresUnconstrainedState(t *testing.T) {
	bbr := newTestBBRv3()

	// Fresh BBRv3 with undo values at MaxByteCount (unconstrained state saved)
	require.Equal(t, protocol.MaxByteCount, bbr.undoBwLo)
	require.Equal(t, protocol.MaxByteCount, bbr.undoInflightLo)
	require.Equal(t, protocol.MaxByteCount, bbr.undoInflightHi)

	// Simulate bounds being reduced after loss (as adaptLowerBounds would do)
	bbr.bwLo = 500_000
	bbr.inflightLo = 50_000
	bbr.inflightHi = 100_000

	// Per RFC §5.5.11.2: bwLo = max(bwLo, undo_bwLo)
	// If undo values are MaxByteCount (unconstrained), recovery should
	// restore to MaxByteCount. This is critical for recovering from
	// spurious loss that occurred when bounds were unconstrained.
	bbr.OnSpuriousLossDetected(1)

	// Bounds should be restored to MaxByteCount (unconstrained)
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo)
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo)
	require.Equal(t, protocol.MaxByteCount, bbr.inflightHi)
}

func TestBBRv3SpuriousLossRecoveryIdempotent(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up state and save it
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWCruise
	bbr.bwLo = 800_000
	bbr.inflightLo = 80_000
	bbr.inflightHi = 120_000
	bbr.saveStateUponLoss()

	// Reduce bounds (simulating loss response)
	bbr.bwLo = 500_000
	bbr.inflightLo = 50_000
	bbr.inflightHi = 90_000

	// First call restores
	bbr.OnSpuriousLossDetected(1)
	require.Equal(t, protocol.ByteCount(800_000), bbr.bwLo)
	require.Equal(t, protocol.ByteCount(80_000), bbr.inflightLo)
	require.Equal(t, protocol.ByteCount(120_000), bbr.inflightHi)

	// Second call should be idempotent (no further changes)
	bbr.OnSpuriousLossDetected(1)
	require.Equal(t, protocol.ByteCount(800_000), bbr.bwLo)
	require.Equal(t, protocol.ByteCount(80_000), bbr.inflightLo)
	require.Equal(t, protocol.ByteCount(120_000), bbr.inflightHi)
}

func TestBBRv3SpuriousLossRecoveryCwnd(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up in ProbeBW CRUISE state with known cwnd
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWCruise
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 1_000_000
	bbr.minRTT = 20 * time.Millisecond
	bbr.congestionWindow = 100_000
	bbr.bwLo = 800_000
	bbr.inflightLo = 100_000
	bbr.inflightHi = 150_000

	// Save state (simulating first loss in round)
	bbr.saveStateUponLoss()
	savedCwnd := bbr.congestionWindow

	// Simulate cwnd reduction (would happen via boundCwndForInflightModel after bounds reduced)
	bbr.inflightLo = 50_000
	bbr.congestionWindow = 50_000 // Cwnd was capped by reduced inflightLo

	require.Equal(t, protocol.ByteCount(50_000), bbr.congestionWindow)

	// Spurious loss detected - should restore both bounds AND cwnd
	bbr.OnSpuriousLossDetected(1)

	// Verify cwnd was restored
	require.Equal(t, savedCwnd, bbr.congestionWindow)
	require.Equal(t, protocol.ByteCount(100_000), bbr.congestionWindow)
}

func TestBBRv3SpuriousLossAfterRefillRestoresUnconstrained(t *testing.T) {
	// This test simulates the real-world scenario causing performance issues:
	// 1. After REFILL, bwLo/inflightLo are MaxByteCount (unconstrained)
	// 2. Loss occurs and state is saved (undo values = MaxByteCount)
	// 3. adaptLowerBounds reduces bwLo to a much lower value
	// 4. Spurious loss detected - must restore to MaxByteCount
	bbr := newTestBBRv3()

	// Simulate state after REFILL phase (bounds are unconstrained)
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWUp
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 20_000_000 // 20 MB/s = 160 Mbps
	bbr.minRTT = 40 * time.Millisecond
	bbr.bwLo = protocol.MaxByteCount
	bbr.inflightLo = protocol.MaxByteCount
	bbr.inflightHi = 1_000_000 // 1 MB

	// First loss in round - save state (captures MaxByteCount bounds)
	bbr.saveStateUponLoss()
	require.Equal(t, protocol.MaxByteCount, bbr.undoBwLo)
	require.Equal(t, protocol.MaxByteCount, bbr.undoInflightLo)

	// Simulate adaptLowerBounds reducing bounds (as happens in CRUISE after loss)
	// This is what initLowerBounds + loss reduction does
	bbr.bwLo = 12_000_000   // Reduced to 12 MB/s = 96 Mbps
	bbr.inflightLo = 600_000 // Reduced inflight

	// Verify bounds are now constrained
	require.NotEqual(t, protocol.MaxByteCount, bbr.bwLo)
	require.NotEqual(t, protocol.MaxByteCount, bbr.inflightLo)

	// Spurious loss detected - should restore to MaxByteCount (unconstrained)
	bbr.OnSpuriousLossDetected(1)

	// Critical: bounds must be restored to MaxByteCount (unconstrained)
	// This was broken before the fix - the != MaxByteCount check prevented restoration
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo, "bwLo should be restored to unconstrained")
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo, "inflightLo should be restored to unconstrained")
}
