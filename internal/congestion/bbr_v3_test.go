package congestion

import (
	"math/rand"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

// ############################################################################
// PART 1: RFC COMPLIANCE TESTS (draft-ietf-ccwg-bbr-05)
// ############################################################################
//
// PURPOSE: These tests enforce MANDATORY behavior specified by the RFC.
//
// Each test references the RFC section it enforces. Assertions include the
// RFC requirement text so violations are self-documenting.
// ############################################################################

// ============================================================================
// TEST FIXTURES AND HELPERS
// ============================================================================

func newTestBBRv3() *BBRv3 {
	return NewBBRV3(DefaultClock{}, utils.NewRTTStats(), nil, initialMaxDatagramSize, false, nil)
}

type recordingQlogger struct {
	events []qlogwriter.Event
}

func (r *recordingQlogger) RecordEvent(ev qlogwriter.Event) {
	r.events = append(r.events, ev)
}

func (r *recordingQlogger) Close() error { return nil }

// ecnAlphaFromFloat converts a float64 alpha [0,1] to scaled uint32.
func ecnAlphaFromFloat(f float64) uint32 {
	return uint32(f * ECN_ALPHA_UNIT)
}

// ecnAlphaToFloat converts a scaled uint32 alpha to float64 [0,1].
func ecnAlphaToFloat(a uint32) float64 {
	return float64(a) / float64(ECN_ALPHA_UNIT)
}

// setupProbeBWPhase configures BBR in a specific ProbeBW phase
func setupProbeBWPhase(bbr *BBRv3, phase bbrProbeBWPhase) {
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = phase
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 10_000_000
	bbr.minRTT = 40 * time.Millisecond
	bbr.congestionWindow = 100_000
}

// ============================================================================
// §4.1: DELIVERY RATE SAMPLING
// ============================================================================

// TestBBRv3PerPacketStateCapture verifies that OnPacketSent captures all
// per-packet state fields correctly per RFC §4.1.2.1.2.
func TestBBRv3PerPacketStateCapture(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up known BBR state before sending
	bbr.totalBytesAcked = 50_000
	bbr.deliveredTime = now.Add(-100 * time.Millisecond)
	bbr.firstSentTime = now.Add(-200 * time.Millisecond)
	bbr.appLimitedUntil = 100_000 // will mark packet as app-limited

	bytesInFlight := protocol.ByteCount(10_000)
	bbr.OnPacketSent(now, bytesInFlight, 1, 1200, true)

	st, ok := bbr.sentPackets[1]
	require.True(t, ok, "packet state should be tracked")

	// RFC §4.1.2.1.2: P.delivered = C.delivered at send time
	require.Equal(t, uint64(50_000), st.delivered,
		"RFC §4.1.2.1.2: P.delivered MUST equal C.delivered at send time")

	// RFC §4.1.2.1.2: P.delivered_time = C.delivered_time at send time
	require.Equal(t, now.Add(-100*time.Millisecond), st.deliveredTime,
		"RFC §4.1.2.1.2: P.delivered_time MUST equal C.delivered_time at send time")

	// RFC §4.1.2.1.2: P.first_sent_time = inherited or reset
	require.Equal(t, now.Add(-200*time.Millisecond), st.firstSentTime,
		"RFC §4.1.2.1.2: P.first_sent_time MUST be inherited from prior packet")

	// RFC §4.1.2.1.2: P.sent_time = current time
	require.Equal(t, now, st.sentTime,
		"RFC §4.1.2.1.2: P.sent_time MUST equal the time packet was sent")

	// RFC §4.1.2.1.2: P.is_app_limited = true if C.delivered < C.app_limited_until
	require.True(t, st.isAppLimited,
		"RFC §4.1.2.1.2: P.is_app_limited MUST be true when C.delivered < C.app_limited_until")

	// RFC §4.1.2.1.2: P.tx_in_flight = bytes_in_flight at send time
	require.Equal(t, bytesInFlight, st.txInFlight,
		"RFC §4.1.2.1.2: P.tx_in_flight MUST equal bytes_in_flight at send time")
}

// TestBBRv3RateSampleContract verifies that rate sample fields are
// correctly computed from per-packet state per RFC §4.1.2.3 (Upon receiving an ACK).
func TestBBRv3RateSampleContract(t *testing.T) {
	bbr := newTestBBRv3()
	sendTime := monotime.Now()

	// Initialize connection state with known values
	initialDelivered := uint64(10_000)
	bbr.totalBytesAcked = initialDelivered
	bbr.deliveredTime = sendTime
	bbr.firstSentTime = sendTime
	bbr.appLimitedUntil = 0 // Not app-limited

	// Send packet 1 at sendTime with bytesInFlight = 0
	// This resets firstSentTime to sendTime (idle restart semantics)
	bbr.OnPacketSent(sendTime, 0, 1, 1200, true)

	// Send packet 2 at sendTime + 10ms with bytesInFlight = 2400
	// bytesInFlight > bytes (2400 > 1200) ensures priorInFlight > 0,
	// so firstSentTime is inherited (not reset), creating send_elapsed > 0
	sendTime2 := sendTime.Add(10 * time.Millisecond)
	bbr.OnPacketSent(sendTime2, 2400, 2, 1200, true)

	// ACK time is 50ms after sendTime
	ackTime := sendTime.Add(50 * time.Millisecond)

	// ACK packet 1 first - this establishes the rate sample baseline
	bbr.OnPacketAcked(1, 1200, 0, ackTime)

	// ACK packet 2 - this updates pending rate sample fields (newer sent time)
	bbr.OnPacketAcked(2, 1200, 1200, ackTime)

	// VERIFY RATE SAMPLE FIELDS BEFORE OnAckEventEnd clears them
	// These pending fields become the rate sample in processPendingAckEvent

	// RFC §4.2: RS.send_elapsed = P.sent_time - P.first_sent_time
	// Packet 2: sentTime = sendTime+10ms, firstSentTime = sendTime (inherited)
	require.Equal(t, 10*time.Millisecond, bbr.pendingSendElapsed,
		"RFC §4.2: RS.send_elapsed MUST equal P.sent_time - P.first_sent_time")

	// RFC §4.2: RS.tx_in_flight = P.tx_in_flight (bytesInFlight when packet was sent)
	// Packet 2 was sent with bytesInFlight = 2400
	require.Equal(t, protocol.ByteCount(2400), bbr.pendingTxInFlight,
		"RFC §4.2: RS.tx_in_flight MUST equal bytes_in_flight at send time")

	// RFC §4.2: RS.is_app_limited = P.is_app_limited
	// appLimitedUntil = 0 (or < delivered), so not app-limited
	require.False(t, bbr.pendingIsAppLimited,
		"RFC §4.2: RS.is_app_limited MUST reflect app-limited state at send time")

	// RFC §4.2: RS.delivered = C.delivered - P.delivered
	// pendingPriorDelivered = P.delivered for the newest packet (packet 2)
	// Packet 2's P.delivered = totalBytesAcked at send time = 10_000 (unchanged)
	require.Equal(t, initialDelivered, bbr.pendingPriorDelivered,
		"RFC §4.2: pending state MUST track P.delivered from send time")

	// Now process the ACK event to compute final rate sample
	bbr.OnAckEventEnd(ackTime)

	// RFC §4.2: After ACK processing, totalBytesAcked MUST increase
	require.Equal(t, uint64(10_000+2400), bbr.totalBytesAcked,
		"RFC §4.2: totalBytesAcked MUST equal prior + newly acked bytes")

	// Verify pending fields were cleared after processing
	require.Equal(t, time.Duration(0), bbr.pendingSendElapsed,
		"pending fields MUST be cleared after OnAckEventEnd")
}

// TestBBRv3ShortIntervalSamplesKeepLatestDeliveryBookkeeping verifies that delivery
// rate samples with interval < minRTT preserve bwLatest but update inflightLatest.
func TestBBRv3ShortIntervalSamplesKeepLatestDeliveryBookkeeping(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.bwLatest = 9_000
	bbr.inflightLatest = 3_000
	bbr.totalBytesAcked = 42_000
	bbr.lossRoundDelivered = 10_000

	bbr.updateLatestDeliverySignals(bbrRateSample{
		deliveryRate:   0,
		newlyAcked:     1200,
		delivered:      7_200,
		priorDelivered: 10_000,
	})

	require.Equal(t, protocol.ByteCount(9_000), bbr.bwLatest)
	require.Equal(t, protocol.ByteCount(7_200), bbr.inflightLatest)
	require.True(t, bbr.lossRoundStart)
	require.Equal(t, uint64(42_000), bbr.lossRoundDelivered)
}

// TestBBRv3ACKLookupMissReturnsEarly verifies that ACKs for packets with no
// sampler state (lookup miss) return early without updating delivery-rate
// sampler state. This prevents fabricated state from poisoning max_bw during
// handshake when minRTT may still be zero.
func TestBBRv3ACKLookupMissReturnsEarly(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Record initial state
	initialAcked := bbr.totalBytesAcked
	initialPendingValid := bbr.pendingAckEventValid

	// ACK a packet that was never sent (lookup miss)
	bbr.OnPacketAcked(999, 1200, 5000, now)

	// totalBytesAcked should NOT be updated — we can't trust fabricated state
	require.Equal(t, initialAcked, bbr.totalBytesAcked,
		"totalBytesAcked should not change on lookup miss")

	// No pending ACK event should be created from fabricated state
	require.Equal(t, initialPendingValid, bbr.pendingAckEventValid,
		"pending ACK event should not be created from lookup miss")

	// priorInFlight should be preserved (transport-level info)
	require.Equal(t, protocol.ByteCount(5000), bbr.pendingPriorInFlight,
		"priorInFlight should be preserved from lookup miss")
}

// TestBBRv3ACKLookupMissDoesNotStealECN verifies that lookup misses do not
// consume pending ECN bytes that belong to real packets in the same ACK event.
func TestBBRv3ACKLookupMissDoesNotStealECN(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up ECN eligibility
	bbr.minRTT = 3 * time.Millisecond

	// Send a real packet
	bbr.OnPacketSent(now, 0, 1, 1200, true)

	// Receive ECN feedback
	bbr.OnECNFeedback(1000, 100, 0, 10, 0, now.Add(50*time.Millisecond))
	require.True(t, bbr.pendingECNEventValid)
	require.Greater(t, bbr.pendingECNCEBytes, protocol.ByteCount(0))

	// ACK lookup miss first (packet 999 never sent)
	bbr.OnPacketAcked(999, 1200, 5000, now.Add(50*time.Millisecond))

	// ECN bytes should NOT be consumed by the miss
	require.True(t, bbr.pendingECNEventValid,
		"ECN should not be consumed by lookup miss")

	// ACK the real packet
	bbr.OnPacketAcked(1, 1200, 3800, now.Add(50*time.Millisecond))

	// Real packet should consume the ECN bytes
	require.Greater(t, bbr.pendingCEBytes, protocol.ByteCount(0),
		"real packet should get the ECN bytes")
}

// TestBBRv3AllMissACKEventClearsECN verifies that if an ACK event contains
// only missed packets (no real sampler state), stale ECN is cleared at event end.
func TestBBRv3AllMissACKEventClearsECN(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up ECN eligibility and pending ECN
	bbr.minRTT = 3 * time.Millisecond
	bbr.OnECNFeedback(1000, 100, 0, 10, 0, now)

	require.True(t, bbr.pendingECNEventValid)

	// ACK event with only misses
	bbr.OnPacketAcked(999, 1200, 5000, now)
	bbr.OnAckEventEnd(now)

	// Stale ECN should be cleared
	require.False(t, bbr.pendingECNEventValid,
		"all-miss ACK event should clear stale ECN")
	require.Equal(t, protocol.ByteCount(0), bbr.pendingECNCEBytes,
		"pending ECN CE bytes should be cleared")
}

// ============================================================================
// §5.2: ALGORITHM LIFECYCLE (Init, Migration, Idle Restart)
// ============================================================================

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
	bbr.totalBytesSent = 123
	bbr.totalBytesAcked = 456
	bbr.totalBytesLost = 789
	bbr.totalBytesAckedCE = 321
	bbr.ecnAlpha = ecnAlphaFromFloat(0.25)
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
	require.Equal(t, uint32(ECN_ALPHA_UNIT), bbr.ecnAlpha)
	require.Zero(t, bbr.priorCwnd)
	require.False(t, bbr.idleRestart)
	require.False(t, bbr.ptoRecovery)
	require.Zero(t, bbr.appLimitedUntil)
	require.False(t, bbr.pendingAckEventValid)
	require.False(t, bbr.pendingECNEventValid)
	require.Empty(t, bbr.sentPackets)
}

// TestBBRv3IdleRestartPacingReset verifies that sending from idle
// (priorInFlight == 0 AND app-limited) resets pacing rate in ProbeBW per RFC §5.4.1.
func TestBBRv3IdleRestartPacingReset(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish steady state in ProbeBW with known bandwidth and pacing rate
	setupProbeBWPhase(bbr, probeBWCruise)
	// setupProbeBWPhase sets bwHi[0] = 10_000_000
	// Set pacing rate to something different from expected reset value
	bbr.pacingRate = 2_000_000 // 2 MB/s (different from bw-based rate)
	bbr.pacingGain = 1.0

	// Record initial pacing rate
	initialPacingRate := bbr.pacingRate

	// RFC §5.4.1: idle restart requires BOTH zero inflight AND app-limited.
	// Mark app-limited before sending from idle.
	bbr.MarkAppLimited(0) // bytesInFlight=0 when idle

	// Send from idle: bytesInFlight == packetSize means priorInFlight == 0
	// This triggers the idle restart path in OnPacketSent
	packetSize := protocol.ByteCount(1200)
	bbr.OnPacketSent(now, packetSize, 1, packetSize, true)

	// RFC §5.4: On idle restart in ProbeBW, pacing rate should be reset to bw * 1.0
	// The idleRestart flag should be set
	require.True(t, bbr.idleRestart,
		"RFC §5.4.1: idleRestart flag MUST be set when sending from idle (priorInFlight == 0 && app_limited)")

	// RFC §5.4: Pacing rate MUST be reset to maxBandwidth() * gain * margin
	// With bwHi[0] = 10_000_000, gain = 1.0, BBR_PACING_MARGIN = 0.99:
	// expectedRate = 10_000_000 * 1.0 * 0.99 = 9_900_000
	expectedPacingRate := protocol.ByteCount(float64(bbr.bwHi[0]) * 1.0 * 0.99)
	require.NotEqual(t, initialPacingRate, bbr.pacingRate,
		"RFC §5.4.1: pacing rate MUST change on idle restart (was %d)", initialPacingRate)
	require.Equal(t, expectedPacingRate, bbr.pacingRate,
		"RFC §5.4.1: pacing rate MUST be reset to maxBandwidth * gain * margin on idle restart")
}

// TestBBRv3IdleRestartPreservesCwnd verifies that cwnd is not reduced
// during idle restart per RFC §5.4.1. Per the RFC: "When restarting from
// idle...BBR leaves C.cwnd as-is" to allow immediate burst to refill the pipe.
func TestBBRv3IdleRestartPreservesCwnd(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish cwnd in ProbeBW
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.congestionWindow = 200_000
	originalCwnd := bbr.congestionWindow

	// RFC §5.4.1: idle restart requires app-limited state
	bbr.MarkAppLimited(0)

	// Send from idle (bytesInFlight == packetSize means priorInFlight == 0)
	packetSize := protocol.ByteCount(1200)
	bbr.OnPacketSent(now, packetSize, 1, packetSize, true)

	// Verify idle restart was triggered
	require.True(t, bbr.idleRestart,
		"idleRestart flag should be set when priorInFlight == 0 && app_limited")

	// RFC §5.4: Cwnd should be preserved during idle restart
	require.Equal(t, originalCwnd, bbr.congestionWindow,
		"RFC §5.4.1: cwnd MUST be preserved during idle restart")

	// Complete the cycle: ACK the packet
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnPacketAcked(1, packetSize, 0, ackTime)
	bbr.OnAckEventEnd(ackTime)

	// Cwnd should still be preserved after ACK
	require.GreaterOrEqual(t, bbr.congestionWindow, originalCwnd,
		"RFC §5.4.1: cwnd MUST NOT decrease due to idle restart")
}

// TestBBRv3IdleRestartFlagLifecycle verifies the idleRestart flag is
// set on idle send and cleared after first ACK processing per RFC §5.4.1.
// Per §5.3.4.2: idle_restart suppresses ProbeRTT entry because "the idleness
// is deemed a sufficient attempt to coordinate to drain the queue".
func TestBBRv3IdleRestartFlagLifecycle(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Initially false
	require.False(t, bbr.idleRestart,
		"idleRestart MUST start false")

	// RFC §5.4.1: idle restart requires app-limited state
	bbr.MarkAppLimited(0)

	// Send from idle: bytesInFlight == packetSize triggers priorInFlight == 0
	packetSize := protocol.ByteCount(1200)
	bbr.OnPacketSent(now, packetSize, 1, packetSize, true)

	// Flag should be set after idle send
	require.True(t, bbr.idleRestart,
		"RFC §5.4.1: idleRestart MUST be set when sending with priorInFlight == 0 && app_limited")

	// ACK the packet
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnPacketAcked(1, packetSize, 0, ackTime)
	bbr.OnAckEventEnd(ackTime)

	// Flag should be cleared after ACK processing
	require.False(t, bbr.idleRestart,
		"RFC §5.4.1: idleRestart MUST be cleared after first ACK processing")
}

// TestBBRv3ZeroInflightWithoutAppLimitedNotIdleRestart verifies that
// zero inflight WITHOUT app-limited does NOT trigger idle restart per RFC §5.4.1.
// This distinguishes true idle (no data to send) from transient zero-inflight
// (e.g., loss recovery draining the pipe).
func TestBBRv3ZeroInflightWithoutAppLimitedNotIdleRestart(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish steady state - NOT app-limited
	setupProbeBWPhase(bbr, probeBWCruise)
	require.Equal(t, uint64(0), bbr.appLimitedUntil,
		"precondition: appLimitedUntil should be 0 (not app-limited)")

	// Send from zero inflight WITHOUT being app-limited
	// This could happen after loss recovery drains the pipe
	packetSize := protocol.ByteCount(1200)
	bbr.OnPacketSent(now, packetSize, 1, packetSize, true)

	// RFC §5.4.1: idleRestart should NOT be set without app-limited
	require.False(t, bbr.idleRestart,
		"RFC §5.4.1: idleRestart MUST NOT be set when priorInFlight == 0 but NOT app_limited")
}

// TestBBRv3IdleRestartResetsAckAggregation verifies that idle restart resets
// the ACK aggregation interval per RFC §5.4.1. Stale ackEpochStart from before
// idle would skew the extra_acked calculation.
func TestBBRv3IdleRestartResetsAckAggregation(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Simulate some prior ACK aggregation state
	bbr.ackEpochStart = now.Add(-5 * time.Second) // Stale timestamp
	bbr.ackEpochAcked = 100_000                   // Accumulated bytes

	// Mark app-limited and send from idle
	bbr.MarkAppLimited(0)
	sendTime := now.Add(10 * time.Second) // Well after the stale epoch
	packetSize := protocol.ByteCount(1200)
	bbr.OnPacketSent(sendTime, packetSize, 1, packetSize, true)

	// Verify idle restart triggered
	require.True(t, bbr.idleRestart,
		"precondition: idle restart should be triggered")

	// RFC §5.4.1: ACK aggregation interval should be reset
	require.Equal(t, sendTime, bbr.ackEpochStart,
		"RFC §5.4.1: ackEpochStart MUST be reset to send time on idle restart")
	require.Equal(t, protocol.ByteCount(0), bbr.ackEpochAcked,
		"RFC §5.4.1: ackEpochAcked MUST be reset to 0 on idle restart")
}

func TestBBRv3OnRetransmissionTimeoutNoOp(t *testing.T) {
	bbr := newTestBBRv3()

	// Record initial state
	initialCwnd := bbr.congestionWindow
	initialPriorCwnd := bbr.priorCwnd
	initialPTORecovery := bbr.ptoRecovery

	// Call OnRetransmissionTimeout — should be a no-op
	bbr.OnRetransmissionTimeout(true)

	// Verify nothing changed
	require.Equal(t, initialCwnd, bbr.congestionWindow,
		"cwnd should not change on OnRetransmissionTimeout")
	require.Equal(t, initialPriorCwnd, bbr.priorCwnd,
		"priorCwnd should not change on OnRetransmissionTimeout")
	require.Equal(t, initialPTORecovery, bbr.ptoRecovery,
		"ptoRecovery should not change on OnRetransmissionTimeout")
}

// ----------------------------------------------------------------------------
// §5.5.8 and §5.6.3: SEND QUANTUM AND OFFLOAD BUDGET
// ----------------------------------------------------------------------------

// TestBBRv3SendQuantumCalculation verifies send_quantum = min(pacing_rate * 1ms, 64KB)
// with a floor of 2*MSS per RFC §5.6.3.
func TestBBRv3SendQuantumCalculation(t *testing.T) {
	tests := []struct {
		name        string
		pacingRate  protocol.ByteCount
		expected    protocol.ByteCount
		description string
	}{
		{
			name:        "Low rate (hits 2*MSS floor)",
			pacingRate:  10_000, // 10 KB/s * 1ms = 10 bytes
			expected:    2 * 1280,
			description: "sendQuantum should hit floor of 2*MSS (2560 bytes)",
		},
		{
			name:        "1 MB/s rate (hits 2*MSS floor)",
			pacingRate:  1_000_000, // 1 MB/s * 1ms = 1000 bytes
			expected:    2 * 1280,
			description: "sendQuantum should hit floor of 2*MSS (2560 bytes)",
		},
		{
			name:        "10 MB/s rate (above floor)",
			pacingRate:  10_000_000, // 10 MB/s * 1ms = 10000 bytes
			expected:    10_000,
			description: "sendQuantum should be 10000 bytes",
		},
		{
			name:        "100 MB/s rate (capped at 64KB)",
			pacingRate:  100_000_000, // 100 MB/s * 1ms = 100000 bytes
			expected:    64 * 1024,
			description: "sendQuantum should be capped at 64KB",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bbr := newTestBBRv3()
			bbr.pacingRate = tc.pacingRate
			bbr.setSendQuantum()

			require.Equal(t, tc.expected, bbr.sendQuantum, tc.description)
		})
	}
}

// TestBBRv3OffloadBudgetCalculation verifies offload_budget = send_quantum
// per RFC §5.5.8.2 (QUIC non-offloaded case).
func TestBBRv3OffloadBudgetCalculation(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.pacingRate = 1_000_000 // 1 MB/s -> sendQuantum = 1000
	bbr.setSendQuantum()

	// Per RFC §5.5.8.2: QUIC (non-offloaded) uses offload_budget = send_quantum
	require.Equal(t, bbr.sendQuantum, bbr.offloadBudget,
		"offload_budget should equal send_quantum for QUIC")
}

// TestBBRv3QuantizationBudgetBindingTerms verifies that quantizationBudget
// correctly returns max(inflight, offload_budget, minPipeCwnd) per RFC §5.6.4.2.
func TestBBRv3QuantizationBudgetBindingTerms(t *testing.T) {
	tests := []struct {
		name          string
		inflight      protocol.ByteCount
		pacingRate    protocol.ByteCount // affects sendQuantum -> offload_budget
		expectedFloor string             // which term should win
	}{
		{
			name:          "large inflight wins",
			inflight:      100_000,
			pacingRate:    1_000_000, // sendQuantum ~1000, offload_budget ~1000
			expectedFloor: "inflight",
		},
		{
			name:          "large offload_budget wins",
			inflight:      1_000,
			pacingRate:    100_000_000, // sendQuantum = 64KB (capped), offload_budget = 64KB
			expectedFloor: "offload_budget",
		},
		{
			name:          "minPipeCwnd wins",
			inflight:      1_000,
			pacingRate:    10_000, // sendQuantum ~10, offload_budget ~10
			expectedFloor: "minPipeCwnd",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bbr := newTestBBRv3()
			bbr.pacingRate = tc.pacingRate
			bbr.setSendQuantum()

			result := bbr.quantizationBudget(tc.inflight)

			switch tc.expectedFloor {
			case "inflight":
				require.Equal(t, tc.inflight, result,
					"RFC §5.6.4.2: inflight MUST be returned when it is the maximum")
			case "offload_budget":
				require.Equal(t, bbr.offloadBudget, result,
					"RFC §5.6.4.2: offload_budget MUST be returned when it is the maximum")
			case "minPipeCwnd":
				require.Equal(t, bbr.minPipeCwnd, result,
					"RFC §5.6.4.2: minPipeCwnd MUST be returned when it is the maximum")
			}

			// All results must be at least minPipeCwnd
			require.GreaterOrEqual(t, result, bbr.minPipeCwnd,
				"RFC §5.6.4.2: result MUST be at least minPipeCwnd")
		})
	}
}

// TestBBRv3CwndQuantizationFloor verifies cwnd respects quantization floor
// even with very small BDP.
func TestBBRv3CwndQuantizationFloor(t *testing.T) {
	bbr := newTestBBRv3()

	// Very small BDP scenario: 10 KB/s * 10ms = 100 bytes
	bbr.bwHi[0] = 10_000
	bbr.minRTT = 10 * time.Millisecond
	bbr.fullBandwidthReached = true
	bbr.cwndGain = CWND_GAIN_DEFAULT

	// Even with tiny BDP, cwnd should not go below minPipeCwnd
	target := bbr.targetCwnd(CWND_GAIN_DEFAULT)
	require.GreaterOrEqual(t, target, bbr.minPipeCwnd,
		"cwnd target should respect minPipeCwnd floor")
}

// ############################################################################
// PART 2: IMPLEMENTATION STRATEGY TESTS
// ############################################################################
//
// PURPOSE: These tests enforce CHOSEN behavior where the RFC grants discretion.
//
// These are NOT optional tests - they enforce our implementation contracts.
// They differ from Part 1 only in that the RFC permits alternative approaches.
// ############################################################################

// ============================================================================
// ECN RESPONSE (tcp_bbr.c-aligned)
//
// RFC §3.7 (ECN): "This experimental version of BBR does not specify a
// specific response to Classic [RFC3168], Alternative Backoff with ECN
// (ABE) [RFC8511] or L4S [RFC9330] style ECN."
//
// IMPLEMENTATION CHOICE: We follow Google's tcp_bbr.c v3 approach:
//   - Track ECN marking ratio via EWMA with gain = 1/16 (ECN_ALPHA_GAIN)
//   - Reduce inflightLo by (ecn_alpha * ECN_FACTOR) where ECN_FACTOR = 1/3
//   - ECN only eligible on low-RTT paths (minRTT <= ECN_MAX_RTT = 5ms)
//
// These tests are NOT RFC compliance tests - they enforce our chosen
// tcp_bbr.c-aligned implementation strategy where the RFC grants discretion.
// ============================================================================

// TestBBRv3ECNAlphaCalculation verifies the EWMA formula for ecnAlpha.
// IMPLEMENTATION: tcp_bbr.c bbr_update_ecn_alpha() uses alpha = (1-g)*alpha + g*(CE/acked), g=1/16.
// Note: RFC §3.7 does not mandate this formula - this is our chosen implementation.
func TestBBRv3ECNAlphaCalculation(t *testing.T) {
	tests := []struct {
		name          string
		initialAlpha  float64
		ceBytes       uint64
		ackedBytes    uint64
		expectedAlpha float64
		tolerance     float64
	}{
		{
			name:          "decay with 0% CE",
			initialAlpha:  1.0,
			ceBytes:       0,
			ackedBytes:    1000,
			expectedAlpha: 0.9375, // (1 - 1/16) * 1.0 + (1/16) * 0
			tolerance:     0.001,
		},
		{
			name:          "rise with 50% CE",
			initialAlpha:  0.0,
			ceBytes:       500,
			ackedBytes:    1000,
			expectedAlpha: 0.03125, // (1 - 1/16) * 0 + (1/16) * 0.5
			tolerance:     0.001,
		},
		{
			name:          "stable at 50%",
			initialAlpha:  0.5,
			ceBytes:       500,
			ackedBytes:    1000,
			expectedAlpha: 0.5, // converged
			tolerance:     0.001,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bbr := newTestBBRv3()
			bbr.ecnEligible = true
			bbr.minRTT = 3 * time.Millisecond // Enable ECN
			bbr.ecnAlpha = ecnAlphaFromFloat(tc.initialAlpha)
			bbr.alphaLastDelivered = 0
			bbr.alphaLastDeliveredCE = 0
			bbr.totalBytesAcked = tc.ackedBytes
			bbr.totalBytesAckedCE = tc.ceBytes

			// Trigger alpha update
			bbr.roundStart = true
			bbr.updateECNAlpha(bbrRateSample{})

			require.InDelta(t, tc.expectedAlpha, ecnAlphaToFloat(bbr.ecnAlpha), tc.tolerance,
				"ecnAlpha should match expected value")
		})
	}
}

// TestBBRv3ECNAlphaBounds verifies ecnAlpha stays in [0, 1] range.
// IMPLEMENTATION: tcp_bbr.c clamps ecn_alpha to [0, BBR_UNIT].
func TestBBRv3ECNAlphaBounds(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.ecnEligible = true
	bbr.minRTT = 3 * time.Millisecond

	// 100% CE marking over multiple rounds
	for i := 0; i < 100; i++ {
		bbr.alphaLastDelivered = bbr.totalBytesAcked
		bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE
		bbr.totalBytesAcked += 1000
		bbr.totalBytesAckedCE += 1000
		bbr.roundStart = true
		bbr.updateECNAlpha(bbrRateSample{})
	}
	require.LessOrEqual(t, ecnAlphaToFloat(bbr.ecnAlpha), 1.0,
		"ecnAlpha should not exceed 1.0")
	require.GreaterOrEqual(t, ecnAlphaToFloat(bbr.ecnAlpha), 0.9,
		"ecnAlpha should approach 1.0 with 100% CE")

	// 0% CE marking
	bbr.ecnAlpha = ecnAlphaFromFloat(0.5)
	for i := 0; i < 100; i++ {
		bbr.alphaLastDelivered = bbr.totalBytesAcked
		bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE
		bbr.totalBytesAcked += 1000
		// No CE bytes added
		bbr.roundStart = true
		bbr.updateECNAlpha(bbrRateSample{})
	}
	require.GreaterOrEqual(t, ecnAlphaToFloat(bbr.ecnAlpha), 0.0,
		"ecnAlpha should not go below 0.0")
	require.LessOrEqual(t, ecnAlphaToFloat(bbr.ecnAlpha), 0.1,
		"ecnAlpha should approach 0.0 with 0% CE")
}

// TestBBRv3ECNAlphaConvergence verifies alpha converges to marking rate.
// IMPLEMENTATION: tcp_bbr.c EWMA with g=1/16 converges to steady-state CE ratio.
func TestBBRv3ECNAlphaConvergence(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.ecnEligible = true
	bbr.minRTT = 3 * time.Millisecond
	bbr.ecnAlpha = 0

	// Sustained 50% CE marking
	for i := 0; i < 200; i++ {
		bbr.alphaLastDelivered = bbr.totalBytesAcked
		bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE
		bbr.totalBytesAcked += 1000
		bbr.totalBytesAckedCE += 500
		bbr.roundStart = true
		bbr.updateECNAlpha(bbrRateSample{})
	}

	require.InDelta(t, 0.5, ecnAlphaToFloat(bbr.ecnAlpha), 0.05,
		"ecnAlpha should converge to ~0.5 with sustained 50% CE")
}

// TestBBRv3ECNAlphaReducesInflightLo verifies ECN alpha affects inflightLo reduction.
// IMPLEMENTATION: tcp_bbr.c uses inflightLo *= (1 - ecnAlpha * ECN_FACTOR) where ECN_FACTOR=1/3.
// Note: RFC §3.7 does not mandate this formula - this is our chosen implementation.
func TestBBRv3ECNAlphaReducesInflightLo(t *testing.T) {
	bbr := newTestBBRv3()
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.ecnEligible = true
	bbr.ecnAlpha = ecnAlphaFromFloat(0.5)
	bbr.inflightLo = 100_000
	bbr.inflightLatest = 50_000
	bbr.ecnInRound = true
	bbr.lossInRound = false
	bbr.lossRoundStart = true

	bbr.adaptLowerBounds(bbrRateSample{})

	// Expected: inflightLo *= (1 - 0.5 * ECN_FACTOR)
	// ECN_FACTOR = 1/3, so inflightLo *= (1 - 0.5 * 1/3) = (1 - 1/6) = 5/6
	// 100_000 * 5/6 = 83_333
	// But also max with inflightLatest = 50_000, so result is 83_333
	ecnFactor := 1.0 / 3.0
	expected := protocol.ByteCount(float64(100_000) * (1.0 - 0.5*ecnFactor))
	expected = max(expected, bbr.inflightLatest)
	require.Equal(t, expected, bbr.inflightLo,
		"inflightLo should be reduced by ecnAlpha * ECN_FACTOR")
}

// TestBBRv3ECNEventPath verifies that ECN feedback flows through the
// production event path: OnECNFeedback → OnPacketAcked → OnAckEventEnd.
// IMPLEMENTATION: Verifies tcp_bbr.c-style ECN integration works end-to-end.
func TestBBRv3ECNEventPath(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish steady state with ECN eligible
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.minRTT = 3 * time.Millisecond // Enable ECN eligibility (must be <= ECN_MAX_RTT=5ms)
	bbr.ecnEligible = true
	bbr.ecnAlpha = 0
	bbr.inflightLo = 100_000

	// Set up round boundary so round_start will be triggered in updateRoundStart
	// Packets capture C.delivered at send time; round starts when priorDelivered >= nextRoundDelivered
	bbr.totalBytesAcked = 10_000
	bbr.nextRoundDelivered = 5_000

	// Set lossRoundDelivered high so lossRoundStart stays false in updateLatestDeliverySignals
	// This prevents ecnInRound from being reset after it's set in updateCongestionSignals
	bbr.lossRoundDelivered = 100_000

	// Record baseline
	initialTotalCE := bbr.totalBytesAckedCE

	// Send packets - they capture totalBytesAcked (10000) as their delivered field
	for i := 1; i <= 5; i++ {
		bbr.OnPacketSent(now, protocol.ByteCount(i*1200), protocol.PacketNumber(i), 1200, true)
	}

	// Provide ECN feedback through production path
	// Simulate 60% CE marking: 3 CE marks out of 5 ECN-capable packets
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnECNFeedback(
		5*1200,  // ackedBytes
		2,       // ect0Total (2 packets without CE)
		0,       // ect1Total
		3,       // ceTotal (3 packets with CE)
		0,       // priorInFlight
		ackTime,
	)

	// ACK the packets
	for i := 1; i <= 5; i++ {
		bbr.OnPacketAcked(protocol.PacketNumber(i), 1200, 0, ackTime)
	}

	// Process the ACK event - this triggers the full model update pipeline
	bbr.OnAckEventEnd(ackTime)

	// Verify ECN was processed through the event path:
	// 1. totalBytesAckedCE should increase (processPendingAckEvent line 1029)
	require.Greater(t, bbr.totalBytesAckedCE, initialTotalCE,
		"totalBytesAckedCE MUST increase when CE bytes delivered through event path")

	// 2. ecnInRound should be set (updateCongestionSignals line 1216)
	require.True(t, bbr.ecnInRound,
		"ecnInRound MUST be set when CE bytes delivered through event path")

	// 3. ecnAlpha should have moved from 0 toward the CE ratio
	// With 60% CE (3/5), after one EWMA update with g=1/16:
	// alpha = (15/16)*0 + (1/16)*0.6 = 0.0375
	require.Greater(t, bbr.ecnAlpha, uint32(0),
		"ecnAlpha MUST increase when CE marks received through event path")
}

// TestBBRv3ProbeBWCruiseLossReducesBounds verifies loss in CRUISE reduces
// bwLo and inflightLo by Beta (30%) per RFC §5.5.10.1.
func TestBBRv3ProbeBWCruiseLossReducesBounds(t *testing.T) {
	bbr := newTestBBRv3()
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.bwLo = 1_000_000
	bbr.inflightLo = 100_000
	bbr.bwLatest = 500_000
	bbr.inflightLatest = 50_000
	bbr.lossInRound = true
	bbr.ecnInRound = false
	bbr.lossRoundStart = true

	bbr.adaptLowerBounds(bbrRateSample{})

	// bwLo = max(bwLatest, bwLo * 0.7) = max(500_000, 700_000) = 700_000
	require.Equal(t, protocol.ByteCount(700_000), bbr.bwLo,
		"bwLo should be reduced by 30%% (Beta)")

	// inflightLo = max(inflightLatest, inflightLo * 0.7) = max(50_000, 70_000) = 70_000
	require.Equal(t, protocol.ByteCount(70_000), bbr.inflightLo,
		"inflightLo should be reduced by 30%% (Beta)")
}

// TestBBRv3ProbeBWCruiseECNReducesInflightLo verifies ECN in CRUISE reduces
// only inflightLo (not bwLo) per RFC §5.5.10.2.
func TestBBRv3ProbeBWCruiseECNReducesInflightLo(t *testing.T) {
	bbr := newTestBBRv3()
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.bwLo = 1_000_000
	bbr.inflightLo = 100_000
	bbr.inflightLatest = 50_000
	bbr.ecnAlpha = ecnAlphaFromFloat(0.5)
	bbr.ecnInRound = true
	bbr.lossInRound = false
	bbr.lossRoundStart = true

	initialBwLo := bbr.bwLo
	bbr.adaptLowerBounds(bbrRateSample{})

	// bwLo should NOT change (ECN doesn't affect bwLo)
	require.Equal(t, initialBwLo, bbr.bwLo,
		"bwLo should not change on ECN (only loss affects bwLo)")

	// inflightLo should be reduced
	require.Less(t, bbr.inflightLo, protocol.ByteCount(100_000),
		"inflightLo should be reduced on ECN")
}

// TestBBRv3ProbeBWRefillClearsLowerBounds verifies entering REFILL resets
// bwLo and inflightLo to MaxByteCount per RFC §5.3.3.5.3.
func TestBBRv3ProbeBWRefillClearsLowerBounds(t *testing.T) {
	bbr := newTestBBRv3()
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.bwLo = 500_000
	bbr.inflightLo = 50_000

	// Transition to REFILL
	bbr.startProbeBWRefill(monotime.Now(), 0)

	require.Equal(t, protocol.MaxByteCount, bbr.bwLo,
		"bwLo should be reset to MaxByteCount in REFILL")
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo,
		"inflightLo should be reset to MaxByteCount in REFILL")
}

// TestBBRv3LowerBoundsConstrainCwnd verifies inflightLo caps cwnd
// per RFC §5.6.4.3.
func TestBBRv3LowerBoundsConstrainCwnd(t *testing.T) {
	bbr := newTestBBRv3()
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.bwHi[0] = 10_000_000
	bbr.minRTT = 40 * time.Millisecond
	bbr.inflightLo = 50_000 // Low constraint
	bbr.congestionWindow = 200_000

	// Apply inflight model bound
	bbr.boundCwndForInflightModel()

	// Cwnd should be capped at inflightLo + some headroom
	require.LessOrEqual(t, bbr.congestionWindow, bbr.inflightLo+bbr.maxDatagramSize,
		"cwnd should be bounded by inflightLo")
}

// ============================================================================
// §5.6: CONTROL PARAMETERS (Gains, Pacing, Cwnd)
// ============================================================================

// TestBBRv3GainTableRFCCompliance verifies all state/phase gain values
// match RFC draft-ietf-ccwg-bbr-05 §5.6.1.
func TestBBRv3GainTableRFCCompliance(t *testing.T) {
	gainTests := []struct {
		name       string
		rfcSection string
		state      BBRState
		phase      bbrProbeBWPhase
		pacingGain float64
		cwndGain   float64
	}{
		{"Startup", "§5.3.1", BBRStartup, 0, STARTUP_PACING_GAIN, STARTUP_CWND_GAIN},
		{"Drain", "§5.3.2", BBRDrain, 0, DRAIN_PACING_GAIN, STARTUP_CWND_GAIN},
		{"ProbeBW_DOWN", "§5.3.3.4", BBRProbeBW, probeBWDown, PROBE_BW_DOWN_GAIN, CWND_GAIN_DEFAULT},
		{"ProbeBW_CRUISE", "§5.3.3.5", BBRProbeBW, probeBWCruise, PROBE_BW_BASE_GAIN, CWND_GAIN_DEFAULT},
		{"ProbeBW_REFILL", "§5.3.3.5.3", BBRProbeBW, probeBWRefill, PROBE_BW_BASE_GAIN, CWND_GAIN_DEFAULT},
		{"ProbeBW_UP", "§5.3.3.6", BBRProbeBW, probeBWUp, PROBE_BW_UP_GAIN, PROBE_BW_UP_CWND_GAIN},
		{"ProbeRTT", "§5.3.4", BBRProbeRTT, 0, 1.0, PROBE_RTT_CWND_GAIN},
	}

	for _, tc := range gainTests {
		t.Run(tc.name, func(t *testing.T) {
			bbr := newTestBBRv3()
			bbr.state = tc.state
			if tc.state == BBRProbeBW {
				bbr.probeBWPhase = tc.phase
			}
			bbr.updateGains()

			require.InDelta(t, tc.pacingGain, bbr.pacingGain, 0.001,
				"RFC %s: %s pacing_gain mismatch", tc.rfcSection, tc.name)
			require.InDelta(t, tc.cwndGain, bbr.cwndGain, 0.001,
				"RFC %s: %s cwnd_gain mismatch", tc.rfcSection, tc.name)
		})
	}
}

// TestBBRv3StateTransitionSetsCorrectGains verifies state entry functions
// set correct gains (not just updateGains in isolation).
func TestBBRv3StateTransitionSetsCorrectGains(t *testing.T) {
	t.Run("enterDrain", func(t *testing.T) {
		bbr := newTestBBRv3()
		now := monotime.Now()
		bbr.state = BBRStartup
		bbr.fullBandwidthReached = true
		bbr.bwHi[0] = 10_000_000
		bbr.minRTT = 40 * time.Millisecond
		bbr.roundStart = true

		// Trigger Drain entry via checkDrain
		bbr.checkDrain(bbrRateSample{bytesInFlight: 10_000_000}, now)
		require.Equal(t, BBRDrain, bbr.state)

		// updateGains is called after state transition in updateModel
		bbr.updateGains()

		require.InDelta(t, DRAIN_PACING_GAIN, bbr.pacingGain, 0.001,
			"Drain pacing_gain should be DRAIN_PACING_GAIN")
		require.InDelta(t, STARTUP_CWND_GAIN, bbr.cwndGain, 0.001,
			"Drain cwnd_gain should be STARTUP_CWND_GAIN")
	})

	t.Run("enterProbeRTT", func(t *testing.T) {
		rttStats := utils.NewRTTStats()
		rttStats.UpdateRTT(40*time.Millisecond, 0)
		bbr := NewBBRV3(DefaultClock{}, rttStats, nil, initialMaxDatagramSize, false, nil)
		setupProbeBWPhase(bbr, probeBWCruise)

		// Trigger ProbeRTT entry via updateMinRTT (expired timer)
		now := monotime.Now()
		bbr.probeRTTMinStamp = now.Add(-PROBE_RTT_INTERVAL - time.Millisecond)
		bbr.idleRestart = false
		bbr.pendingNewestSentTime = now.Add(-40 * time.Millisecond)
		bbr.updateMinRTT(now)
		require.Equal(t, BBRProbeRTT, bbr.state)

		// updateGains is called after state transition in updateModel
		bbr.updateGains()

		require.InDelta(t, 1.0, bbr.pacingGain, 0.001,
			"ProbeRTT pacing_gain should be 1.0")
		require.InDelta(t, PROBE_RTT_CWND_GAIN, bbr.cwndGain, 0.001,
			"ProbeRTT cwnd_gain should be PROBE_RTT_CWND_GAIN")
	})
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

func TestBBRv3PTORecoveryUsesInflightAndPreservesPriorCwnd(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRProbeBW
	bbr.congestionWindow = 20 * bbr.maxDatagramSize
	initialCwnd := bbr.congestionWindow

	bbr.OnPTO(8 * bbr.maxDatagramSize)
	require.True(t, bbr.ptoRecovery)
	require.Equal(t, initialCwnd, bbr.priorCwnd)
	require.Equal(t, 9*bbr.maxDatagramSize, bbr.congestionWindow)
	require.Equal(t, BBRProbeBW, bbr.undoState)

	bbr.OnPTO(2 * bbr.maxDatagramSize)
	require.Equal(t, initialCwnd, bbr.priorCwnd)
	require.Equal(t, 3*bbr.maxDatagramSize, bbr.congestionWindow)
}

func TestBBRv3PacerMultiplierCompensation(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up a known pacing rate
	bbr.pacingRate = 1_000_000 // 1 MB/s

	// The helper should return 4/5 of the pacing rate to neutralize pacer's 5/4 multiplier
	compensated := bbr.bandwidthEstimateForPacer()

	// 1_000_000 * 4/5 = 800_000 bytes/s
	// bandwidthEstimateForPacer returns Bandwidth (bytes/s * BytesPerSecond)
	expected := Bandwidth(800_000) * BytesPerSecond
	require.Equal(t, expected, compensated, "should pre-divide by 5/4 to neutralize pacer multiplier")
}

func TestBBRv3PacerHelperEquality(t *testing.T) {
	bbr := newTestBBRv3()

	// Normal path: pacingRate is set
	bbr.pacingRate = 1_000_000
	compensated := bbr.bandwidthEstimateForPacer()
	original := bbr.BandwidthEstimate()

	// compensated * 5/4 should approximately equal original
	// (within 1 byte/s for integer rounding)
	reconstructed := Bandwidth(uint64(compensated) * 5 / 4)
	diff := int64(original) - int64(reconstructed)
	if diff < 0 {
		diff = -diff
	}
	require.LessOrEqual(t, diff, int64(BytesPerSecond), "compensated * 5/4 should ≈ BandwidthEstimate()")
}

func TestBBRv3PacerFallbackCompensation(t *testing.T) {
	bbr := newTestBBRv3()

	// Fallback path: pacingRate is zero, should use nominalBandwidth
	bbr.pacingRate = 0
	bbr.congestionWindow = 100_000
	// With 100ms default RTT: nominal = 100_000 / 0.1s = 1_000_000 bytes/s

	compensated := bbr.bandwidthEstimateForPacer()

	// Fallback should ALSO apply 4/5 compensation
	// nominal * 4/5 = 1_000_000 * 4/5 = 800_000
	expected := Bandwidth(800_000) * BytesPerSecond
	require.Equal(t, expected, compensated, "fallback path should also apply 4/5 compensation")
}

func TestBBRv3PacerLowRateEdgeCase(t *testing.T) {
	bbr := newTestBBRv3()

	// Low rate edge case: rate=7 bytes/s
	// 7 * 4 / 5 = 28 / 5 = 5 (integer division)
	bbr.pacingRate = 7

	compensated := bbr.bandwidthEstimateForPacer()

	// Should be at least 1 (the max(rate, 1) guard)
	require.GreaterOrEqual(t, uint64(compensated), uint64(BytesPerSecond),
		"low rate should still produce valid bandwidth")

	// Verify the exact calculation: 7 * 4 / 5 = 5
	expected := Bandwidth(5) * BytesPerSecond
	require.Equal(t, expected, compensated)
}

func TestBBRv3FullChainPacingEquivalence(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set a known pacing rate: 1 MB/s
	bbr.pacingRate = 1_000_000

	// Verify the helper returns the compensated value
	compensated := bbr.bandwidthEstimateForPacer()
	require.Equal(t, Bandwidth(800_000)*BytesPerSecond, compensated,
		"helper should return 4/5 of pacing rate")

	// Verify BandwidthEstimate returns the full pacing rate
	full := bbr.BandwidthEstimate()
	require.Equal(t, Bandwidth(1_000_000)*BytesPerSecond, full,
		"BandwidthEstimate should return full pacing rate")

	// The effective pacing rate after pacer's 5/4 multiplier:
	// 800,000 * 5/4 = 1,000,000 bytes/s (matches bbr.pacingRate)
	// This confirms the compensation neutralizes the pacer multiplier.

	// Send enough packets to exhaust burst budget and verify pacing kicks in
	// First, drain the initial burst budget by sending packets
	for i := 0; i < 20; i++ {
		bbr.OnPacketSent(now, 0, protocol.PacketNumber(i+1), 1500, true)
	}

	// Now the pacer should have no budget left
	require.False(t, bbr.HasPacingBudget(now),
		"pacer budget should be exhausted after burst")

	// After some time, budget should replenish at the compensated rate
	// At 1MB/s effective rate: 1.5ms for one 1500-byte packet
	require.True(t, bbr.HasPacingBudget(now.Add(2*time.Millisecond)),
		"pacer should have budget after waiting for packet time")
}

func TestBBRv3InitialPacingRateGuardrail(t *testing.T) {
	// Create BBRv3 through normal path (utils.NewRTTStats initializes to 100ms)
	rttStats := utils.NewRTTStats()
	bbr := NewBBRV3(DefaultClock{}, rttStats, nil, initialMaxDatagramSize, false, nil)

	// Initial pacing rate should be based on 100ms RTT, not 1ms fallback
	// initialCwnd = 32 * 1280 = 40960 bytes (initialCongestionWindow * InitialPacketSize)
	// At 100ms RTT: nominal = 40960 / 0.1s = 409600 bytes/s
	// With STARTUP_PACING_GAIN = 2.77: rate = 409600 * 2.77 = 1134592 bytes/s

	// The 1ms fallback would give: 40960 / 0.001s * 2.77 = 113,459,200 bytes/s
	// So if rate > 10,000,000, we're probably using the 1ms fallback

	require.Less(t, bbr.pacingRate, protocol.ByteCount(10_000_000),
		"initial pacing rate should use 100ms default RTT, not 1ms fallback")
	require.Greater(t, bbr.pacingRate, protocol.ByteCount(500_000),
		"initial pacing rate should be reasonable for 100ms RTT")
}

// TestBBRv3C1ExactPacingInterval verifies that the pacing interval exactly matches
// maxDatagramSize / pacingRate, not maxDatagramSize / (pacingRate * 5/4). The C1 fix
// pre-divides the rate by 5/4 so that after the pacer applies its 5/4 multiplier,
// the effective rate equals BBR's intended pacing rate.
func TestBBRv3C1ExactPacingInterval(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set a precise pacing rate: 1,000,000 bytes/s (1 MB/s)
	bbr.pacingRate = 1_000_000

	// Exhaust burst budget
	for i := 0; i < 20; i++ {
		bbr.OnPacketSent(now, 0, protocol.PacketNumber(i+1), 1500, true)
	}

	// The pacer calculates interval based on maxDatagramSize (1280 bytes).
	// At 1 MB/s, a 1280-byte packet should take exactly 1.28ms
	// packetSize / pacingRate = 1280 / 1_000_000 = 0.00128s = 1.28ms
	//
	// WITHOUT C1 fix: pacer would use rate * 5/4 = 1,250,000 bytes/s
	// → interval = 1280 / 1_250_000 = 1.024ms (too fast)
	//
	// WITH C1 fix: BBR returns rate * 4/5 = 800,000, pacer applies * 5/4
	// → effective = 800,000 * 5/4 = 1,000,000 bytes/s
	// → interval = 1280 / 1_000_000 = 1.28ms (correct)

	packetSize := bbr.maxDatagramSize // 1280 bytes
	expectedInterval := time.Duration(float64(packetSize) / float64(bbr.pacingRate) * float64(time.Second))

	// Set lastSentTime and zero the budget to force interval calculation
	bbr.pacer.budgetAtLastSent = 0
	bbr.pacer.lastSentTime = now

	// TimeUntilSend should return now + expectedInterval (within timer granularity)
	nextSend := bbr.TimeUntilSend(0)
	actualInterval := nextSend.Sub(now)

	// Allow for MinPacingDelay floor and integer rounding (±1μs)
	minExpected := max(expectedInterval, protocol.MinPacingDelay) - time.Microsecond
	maxExpected := max(expectedInterval, protocol.MinPacingDelay) + time.Microsecond

	require.GreaterOrEqual(t, actualInterval, minExpected,
		"pacing interval should be at least expectedInterval (1.28ms)")
	require.LessOrEqual(t, actualInterval, maxExpected,
		"pacing interval should be at most expectedInterval (not faster due to 5/4)")

	// Verify the interval is NOT the uncorrected 1.024ms (what it would be without C1)
	uncorrectedInterval := time.Duration(float64(packetSize) / (float64(bbr.pacingRate) * 1.25) * float64(time.Second))
	// With C1 fix: 1.28ms, without: 1.024ms - difference is 0.256ms
	require.Greater(t, actualInterval, uncorrectedInterval+100*time.Microsecond,
		"interval should be slower than uncorrected rate * 5/4 by at least 100μs")
}

// ----------------------------------------------------------------------------
// H1a: PN-SPACE COLLISION DETECTION
// ----------------------------------------------------------------------------

// TestBBRv3CollisionDetectionOnSend verifies that when a second packet is sent
// with the same raw packet number (PN-space collision during handshake), the
// collision is detected, the PN is marked in collisionPNs, and the original
// entry is removed from sentPackets.
func TestBBRv3CollisionDetectionOnSend(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Send Initial[0] - stored at key 0
	bbr.OnPacketSent(now, 0, 0, 1200, true)
	require.Contains(t, bbr.sentPackets, protocol.PacketNumber(0))

	// Send Handshake[0] - COLLISION: same raw PN, different space
	bbr.OnPacketSent(now.Add(time.Millisecond), 1200, 0, 1200, true)

	// Collision should be detected and recorded
	require.NotNil(t, bbr.collisionPNs)
	require.Contains(t, bbr.collisionPNs, protocol.PacketNumber(0))
	// The sentPackets entry should be removed to prevent corrupt state
	require.NotContains(t, bbr.sentPackets, protocol.PacketNumber(0))
}

// TestBBRv3SubsequentSendsToCollidedPN verifies that once a PN has collided,
// all subsequent packets with that PN (from any space) are silently ignored.
func TestBBRv3SubsequentSendsToCollidedPN(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Trigger collision on PN 0
	bbr.OnPacketSent(now, 0, 0, 1200, true)
	bbr.OnPacketSent(now.Add(time.Millisecond), 1200, 0, 1200, true)

	// Now send 1-RTT[0] - should be silently ignored
	bbr.OnPacketSent(now.Add(2*time.Millisecond), 2400, 0, 1200, true)
	require.NotContains(t, bbr.sentPackets, protocol.PacketNumber(0))
}

// TestBBRv3LossOnCollidedPNSkipsLossModel verifies that loss events for
// collided PNs do not corrupt the loss model (totalBytesLost, etc).
func TestBBRv3LossOnCollidedPNSkipsLossModel(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Trigger collision on PN 0
	bbr.OnPacketSent(now, 0, 0, 1200, true)
	bbr.OnPacketSent(now.Add(time.Millisecond), 1200, 0, 1200, true)

	// Record initial loss state
	initialLost := bbr.totalBytesLost

	// Report loss for collided PN - should be skipped
	bbr.OnCongestionEvent(0, 1200, 0)

	// Loss model should NOT be updated
	require.Equal(t, initialLost, bbr.totalBytesLost)
}

// TestBBRv3ACKOnCollidedPNLeavesModelUntouched verifies that ACKing a collided
// PN does not update any sampler or model state: totalBytesAcked, pendingAckedBytes,
// bwLatest, bwHi, max_bw filter, or ECN state must all remain unchanged.
func TestBBRv3ACKOnCollidedPNLeavesModelUntouched(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish baseline state with a real packet flow first
	bbr.OnPacketSent(now, 0, 5, 1200, true)
	bbr.OnPacketAcked(5, 1200, 0, now.Add(10*time.Millisecond))
	bbr.OnAckEventEnd(now.Add(10 * time.Millisecond))

	// Set up minRTT for ECN eligibility
	bbr.minRTT = 10 * time.Millisecond

	// Trigger collision on PN 0
	bbr.OnPacketSent(now.Add(20*time.Millisecond), 0, 0, 1200, true)
	bbr.OnPacketSent(now.Add(21*time.Millisecond), 1200, 0, 1200, true)
	require.Contains(t, bbr.collisionPNs, protocol.PacketNumber(0))

	// Snapshot all model state before ACK
	snapshotAcked := bbr.totalBytesAcked
	snapshotPendingAcked := bbr.pendingAckedBytes
	snapshotBwLatest := bbr.bwLatest
	snapshotBwHi := bbr.bwHi
	snapshotMaxBwSlot0 := bbr.bwHi[0]
	snapshotMaxBwSlot1 := bbr.bwHi[1]
	snapshotPendingCE := bbr.pendingCEBytes

	// Set up pending ECN for this event
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnECNFeedback(2000, 200, 0, 20, 0, ackTime)
	snapshotECNValid := bbr.pendingECNEventValid
	snapshotECNCEBytes := bbr.pendingECNCEBytes

	// ACK the collided PN
	bbr.OnPacketAcked(0, 1200, 1200, ackTime)

	// All sampler state must remain unchanged
	require.Equal(t, snapshotAcked, bbr.totalBytesAcked,
		"totalBytesAcked should not change on collided ACK")
	require.Equal(t, snapshotPendingAcked, bbr.pendingAckedBytes,
		"pendingAckedBytes should not change on collided ACK")
	require.Equal(t, snapshotBwLatest, bbr.bwLatest,
		"bwLatest should not change on collided ACK")
	require.Equal(t, snapshotBwHi, bbr.bwHi,
		"bwHi should not change on collided ACK")
	require.Equal(t, snapshotMaxBwSlot0, bbr.bwHi[0],
		"max_bw filter slot 0 should not change on collided ACK")
	require.Equal(t, snapshotMaxBwSlot1, bbr.bwHi[1],
		"max_bw filter slot 1 should not change on collided ACK")
	require.Equal(t, snapshotPendingCE, bbr.pendingCEBytes,
		"pendingCEBytes should not change on collided ACK")

	// ECN state should NOT be consumed by collided packet
	require.Equal(t, snapshotECNValid, bbr.pendingECNEventValid,
		"pendingECNEventValid should not change on collided ACK")
	require.Equal(t, snapshotECNCEBytes, bbr.pendingECNCEBytes,
		"pendingECNCEBytes should not be consumed on collided ACK")

	// Event end should clear stale ECN since no real packet was processed
	bbr.OnAckEventEnd(ackTime)
	require.False(t, bbr.pendingECNEventValid,
		"all-collided ACK event should clear stale ECN at end")
}

// TestBBRv3CollidedACKNoDeliveryRateSample is a regression test ensuring that
// ACKing a collided PN does not generate a delivery rate sample. The bug that
// prompted H1a allowed fabricated bbrSentPacketState to flow through the sampler,
// poisoning max_bw when minRTT=0 during handshake.
func TestBBRv3CollidedACKNoDeliveryRateSample(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Trigger collision on PN 0
	bbr.OnPacketSent(now, 0, 0, 1200, true)
	bbr.OnPacketSent(now.Add(time.Millisecond), 1200, 0, 1200, true)
	require.Contains(t, bbr.collisionPNs, protocol.PacketNumber(0))

	// Verify pending ACK event bucket is empty before
	require.False(t, bbr.pendingAckEventValid,
		"no pending ACK event should exist before ACK")

	// ACK the collided PN
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnPacketAcked(0, 1200, 0, ackTime)

	// The pending ACK event bucket must remain empty - no sample should be created
	require.False(t, bbr.pendingAckEventValid,
		"pending ACK event should NOT be created for collided PN")
	require.Equal(t, protocol.ByteCount(0), bbr.pendingAckedBytes,
		"pendingAckedBytes should remain zero for collided PN")
	require.True(t, bbr.pendingNewestSentTime.IsZero(),
		"pendingNewestSentTime should remain zero for collided PN")

	// Process the event end to verify no model update occurs
	snapshotBwLatest := bbr.bwLatest
	snapshotBwHi0 := bbr.bwHi[0]
	bbr.OnAckEventEnd(ackTime)

	// Model should be unchanged since no valid sample was generated
	require.Equal(t, snapshotBwLatest, bbr.bwLatest,
		"bwLatest should not change after event end")
	require.Equal(t, snapshotBwHi0, bbr.bwHi[0],
		"max_bw filter should not change after event end")
}

// TestBBRv3CollisionBlindSpotQuantification documents the expected sample loss
// due to PN-space collision during a typical QUIC handshake. This is a KNOWN
// LIMITATION, not a bug — see docs/bbrv3-implementation-guide.md §3.1.
//
// The collision mitigation marks raw PNs as "poisoned" forever. During handshake:
// - Initial[0], Handshake[0], and 1-RTT[0] all collide on raw PN 0
// - Initial[1], Handshake[1], and 1-RTT[1] all collide on raw PN 1
// - etc.
//
// This test quantifies the blind spot so future work does not mistake it for
// full correctness. The fix requires upstream changes to provide a monotonic
// congestion-packet ID (see Section 5.2 of the implementation guide).
func TestBBRv3CollisionBlindSpotQuantification(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Simulate a typical QUIC handshake packet sequence:
	// - Initial: PNs 0-2 (Client Hello, retransmits)
	// - Handshake: PNs 0-1 (Finished, retransmits)
	// - 1-RTT: PNs 0-N (application data)
	//
	// Collision scope: PNs 0-2 will be poisoned (overlap between spaces)

	// Phase 1: Initial space packets (PNs 0, 1, 2)
	bbr.OnPacketSent(now, 0, 0, 1200, true)
	bbr.OnPacketSent(now.Add(1*time.Millisecond), 1200, 1, 1200, true)
	bbr.OnPacketSent(now.Add(2*time.Millisecond), 2400, 2, 1200, true)

	require.Len(t, bbr.sentPackets, 3, "Initial space: all 3 packets tracked")
	require.Nil(t, bbr.collisionPNs, "No collisions yet")

	// Phase 2: Handshake space packets (PNs 0, 1) — COLLIDE with Initial
	bbr.OnPacketSent(now.Add(10*time.Millisecond), 3600, 0, 1200, true)
	bbr.OnPacketSent(now.Add(11*time.Millisecond), 4800, 1, 1200, true)

	require.Len(t, bbr.collisionPNs, 2, "PNs 0 and 1 should be poisoned")
	require.Contains(t, bbr.collisionPNs, protocol.PacketNumber(0))
	require.Contains(t, bbr.collisionPNs, protocol.PacketNumber(1))
	// PN 2 is still tracked (no Handshake[2] sent yet)
	require.Contains(t, bbr.sentPackets, protocol.PacketNumber(2))

	// Phase 3: 1-RTT space packets (PNs 0, 1, 2, 3, 4, 5...)
	// PNs 0-1 are already poisoned. PN 2 will collide. PNs 3+ will be tracked.
	bbr.OnPacketSent(now.Add(50*time.Millisecond), 6000, 0, 1200, true)  // Poisoned
	bbr.OnPacketSent(now.Add(51*time.Millisecond), 6000, 1, 1200, true)  // Poisoned
	bbr.OnPacketSent(now.Add(52*time.Millisecond), 6000, 2, 1200, true)  // NEW collision
	bbr.OnPacketSent(now.Add(53*time.Millisecond), 7200, 3, 1200, true)  // Tracked
	bbr.OnPacketSent(now.Add(54*time.Millisecond), 8400, 4, 1200, true)  // Tracked
	bbr.OnPacketSent(now.Add(55*time.Millisecond), 9600, 5, 1200, true)  // Tracked

	// Final collision count: PNs 0, 1, 2 are poisoned
	require.Len(t, bbr.collisionPNs, 3, "PNs 0, 1, 2 should be poisoned")

	// Document the blind spot: 3 1-RTT packets are invisible to BBR
	// In a typical handshake, this means the first ~3 application data packets
	// cannot contribute delivery rate samples.
	invisiblePackets := len(bbr.collisionPNs)
	require.Equal(t, 3, invisiblePackets,
		"KNOWN LIMITATION: %d early 1-RTT packets are invisible due to PN collision", invisiblePackets)

	// Verify non-poisoned PNs (3, 4, 5) ARE tracked and can generate samples
	require.Contains(t, bbr.sentPackets, protocol.PacketNumber(3))
	require.Contains(t, bbr.sentPackets, protocol.PacketNumber(4))
	require.Contains(t, bbr.sentPackets, protocol.PacketNumber(5))

	// Verify ACKs for poisoned PNs do NOT contribute samples
	snapshotAcked := bbr.totalBytesAcked
	bbr.OnPacketAcked(0, 1200, 9600, now.Add(100*time.Millisecond))
	bbr.OnPacketAcked(1, 1200, 9600, now.Add(100*time.Millisecond))
	bbr.OnPacketAcked(2, 1200, 9600, now.Add(100*time.Millisecond))
	bbr.OnAckEventEnd(now.Add(100 * time.Millisecond))
	require.Equal(t, snapshotAcked, bbr.totalBytesAcked,
		"ACKs for poisoned PNs should not contribute to totalBytesAcked")

	// Verify ACKs for non-poisoned PNs DO contribute samples
	bbr.OnPacketAcked(3, 1200, 9600, now.Add(110*time.Millisecond))
	bbr.OnAckEventEnd(now.Add(110 * time.Millisecond))
	require.Greater(t, bbr.totalBytesAcked, snapshotAcked,
		"ACKs for non-poisoned PNs should contribute to totalBytesAcked")
}

// TestBBRv3NonCollidedPacketsUnaffected verifies that packets with non-collided
// PNs continue to work normally for both send tracking and ACK processing.
func TestBBRv3NonCollidedPacketsUnaffected(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Trigger collision on PN 0
	bbr.OnPacketSent(now, 0, 0, 1200, true)
	bbr.OnPacketSent(now.Add(time.Millisecond), 1200, 0, 1200, true)

	// Send a normal packet with PN 1 - should work normally
	bbr.OnPacketSent(now.Add(2*time.Millisecond), 2400, 1, 1200, true)
	require.Contains(t, bbr.sentPackets, protocol.PacketNumber(1))

	// ACK the non-collided packet
	initialAcked := bbr.totalBytesAcked
	bbr.OnPacketAcked(1, 1200, 3600, now.Add(50*time.Millisecond))
	bbr.OnAckEventEnd(now.Add(50 * time.Millisecond))

	// totalBytesAcked should be updated
	require.Greater(t, bbr.totalBytesAcked, initialAcked)
	// Packet should be removed from tracking after ACK
	require.NotContains(t, bbr.sentPackets, protocol.PacketNumber(1))
}

// TestBBRv3SaveCwndPinsRoundScopedPredicate pins the round-scoped lossInRound
// predicate used by saveCwnd. Draft-ietf-ccwg-bbr-05 §5.6.4.4 uses
// !InLossRecovery() which spans the entire recovery episode, while this
// implementation uses !lossInRound which resets each round. The difference
// allows faster cwnd restoration during long recovery episodes.
func TestBBRv3SaveCwndPinsRoundScopedPredicate(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up state: in ProbeBW, with loss in round
	bbr.state = BBRProbeBW
	bbr.lossInRound = true
	bbr.congestionWindow = 100_000
	bbr.priorCwnd = 50_000 // Lower than current cwnd

	// saveCwnd with lossInRound=true should preserve max(priorCwnd, cwnd)
	bbr.saveCwnd()
	require.Equal(t, protocol.ByteCount(100_000), bbr.priorCwnd,
		"with lossInRound, priorCwnd = max(priorCwnd, cwnd)")

	// Reset lossInRound (simulating round boundary)
	bbr.lossInRound = false
	bbr.congestionWindow = 80_000

	// saveCwnd with lossInRound=false should capture current cwnd
	bbr.saveCwnd()
	require.Equal(t, protocol.ByteCount(80_000), bbr.priorCwnd,
		"without lossInRound, priorCwnd = cwnd (round-scoped predicate)")
}

// TestBBRv3MaxInflightExtraAckedInsideQuantization verifies that maxInflight() adds
// extra_acked BEFORE applying quantizationBudget(), not after. Per RFC
// draft-ietf-ccwg-bbr-05 §5.6.4.2, the order is:
//
//	inflight_cap = BBRBDPMultiple(BBR.cwnd_gain)  // BDP * gain
//	inflight_cap += BBR.extra_acked               // add extra_acked
//	BBR.max_inflight = BBRQuantizationBudget(inflight_cap)  // THEN quantize
//
// The bug was adding extra_acked AFTER quantization, which means the
// quantization floor doesn't account for the aggregation headroom.
func TestBBRv3MaxInflightExtraAckedInsideQuantization(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up a high-BDP scenario where extra_acked dominates quantization floors.
	// With 50ms RTT and 1 MB/s, BDP = 1,000,000 * 0.050 = 50,000 bytes
	// This is well above minPipeCwnd and offloadBudget, so quantization
	// should not materially affect the result.
	bbr.minRTT = 50 * time.Millisecond
	bbr.bwHi[0] = 1_000_000 // 1 MB/s
	bbr.fullBandwidthReached = true
	bbr.cwndGain = CWND_GAIN_DEFAULT // 2.0
	bbr.extraAcked[0] = 20_000       // Significant extra_acked

	// Per §5.6.4.2:
	//   inflight_cap = BDP * cwnd_gain = 50,000 * 2.0 = 100,000
	//   inflight_cap += extra_acked = 100,000 + 20,000 = 120,000
	//   max_inflight = quantize(120,000) >= 120,000

	maxInf := bbr.maxInflight()

	// Calculate expected values
	expectedBDP := protocol.ByteCount(uint64(1_000_000) * uint64(50*time.Millisecond) / uint64(time.Second))
	expectedInflight := protocol.ByteCount(float64(expectedBDP) * CWND_GAIN_DEFAULT)
	expectedWithExtra := expectedInflight + 20_000

	// Sanity checks on intermediate values
	require.Equal(t, expectedBDP, protocol.ByteCount(50_000), "BDP sanity check")
	require.Equal(t, expectedInflight, protocol.ByteCount(100_000), "BDP*gain sanity check")
	require.Equal(t, expectedWithExtra, protocol.ByteCount(120_000), "BDP*gain+extra sanity check")

	// With extra_acked added INSIDE quantization (correct order),
	// the result should be at least BDP*gain + extra_acked.
	// The quantization floor can only increase this value.
	require.GreaterOrEqual(t, maxInf, expectedWithExtra,
		"maxInflight should include extra_acked before quantization")

	// Since BDP*gain + extra_acked (120,000) is well above quantization floors
	// (minPipeCwnd ~5120, offloadBudget ~2560), the result should equal the sum.
	require.Equal(t, maxInf, expectedWithExtra,
		"maxInflight should equal BDP*gain + extra_acked when above quantization floor")
}

// TestBBRv3MaxInflightExtraAckedOrdering verifies the RFC-mandated order:
// inflightFromBWGain (which applies its own minPipeCwnd floor) + extra_acked,
// then quantizationBudget. The key is that extra_acked is added to the BDP-based
// value BEFORE the quantizationBudget call, not after.
func TestBBRv3MaxInflightExtraAckedOrdering(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up scenario with high bandwidth so maxExtraAcked cap doesn't limit us.
	// Use high BDP so minPipeCwnd floor in inflightFromBWGain doesn't bind.
	bbr.minRTT = 50 * time.Millisecond
	bbr.bwHi[0] = 2_000_000 // 2 MB/s -> BDP = 100,000 bytes at 50ms
	bbr.fullBandwidthReached = true
	bbr.cwndGain = CWND_GAIN_DEFAULT // 2.0
	bbr.extraAcked[0] = 100_000      // Large extra_acked (within 200KB cap at 2MB/s)

	// BDP = 2,000,000 * 0.050 = 100,000 bytes
	// inflight = 100,000 * 2.0 = 200,000 bytes (well above minPipeCwnd)
	// + extra_acked = 200,000 + 100,000 = 300,000
	// quantize(300,000) = 300,000 (above all floors)

	maxInf := bbr.maxInflight()

	// Calculate expected values
	bdp := protocol.ByteCount(uint64(2_000_000) * uint64(50*time.Millisecond) / uint64(time.Second))
	inflight := protocol.ByteCount(float64(bdp) * CWND_GAIN_DEFAULT)

	require.Equal(t, bdp, protocol.ByteCount(100_000), "BDP sanity check")
	require.Equal(t, inflight, protocol.ByteCount(200_000), "inflight sanity check")

	// maxExtraAcked cap = 2MB/s * 100ms = 200KB, so 100KB is within cap
	require.Equal(t, bbr.maxExtraAcked(), protocol.ByteCount(100_000),
		"extra_acked should not be capped")

	// With correct RFC ordering: inflightFromBWGain + extra_acked, then quantize
	expected := inflight + 100_000 // 300,000
	require.Equal(t, maxInf, expected,
		"maxInflight should equal BDP*gain + extra_acked when above all floors")
}

// ============================================================================
// §5.3.1: STARTUP
// ============================================================================

func TestBBRv3InitialQlogTelemetry(t *testing.T) {
	rec := &recordingQlogger{}
	_ = NewBBRV3(DefaultClock{}, utils.NewRTTStats(), nil, initialMaxDatagramSize, false, rec)

	require.Len(t, rec.events, 4)
	require.IsType(t, qlog.CongestionStateUpdated{}, rec.events[0])
	require.IsType(t, qlog.BBRv3StateUpdated{}, rec.events[1])
	require.IsType(t, qlog.BBRv3ModelUpdated{}, rec.events[2])
	require.IsType(t, qlog.BBRv3ControlUpdated{}, rec.events[3])

	model := rec.events[2].(qlog.BBRv3ModelUpdated)
	control := rec.events[3].(qlog.BBRv3ControlUpdated)
	require.Equal(t, "init", model.Trigger)
	require.Equal(t, "init", control.Trigger)
}

func TestBBRv3StartupRoundQlogTelemetry(t *testing.T) {
	bbr := newTestBBRv3()
	rec := &recordingQlogger{}
	bbr.qlogger = rec

	bbr.state = BBRStartup
	bbr.roundStart = true
	bbr.roundCount = 7
	bbr.lossInRound = true
	bbr.bytesLostInRound = 1200
	bbr.fullBandwidth = 900_000
	bbr.fullBandwidthCount = 2
	bbr.pacingRate = 2_400_000
	bbr.congestionWindow = 2_200_000
	bbr.minRTT = 150 * time.Millisecond

	rs := bbrRateSample{
		delivered:     120_000,
		deliveryRate:  1_100_000,
		bytesInFlight: 1_600_000,
		sendElapsed:   125 * time.Millisecond,
		ackElapsed:    150 * time.Millisecond,
		interval:      150 * time.Millisecond,
	}

	bbr.maybeQlogRoundUpdate(rs)

	require.Len(t, rec.events, 3)
	require.IsType(t, qlog.BBRv3RoundUpdated{}, rec.events[0])
	require.IsType(t, qlog.BBRv3ModelUpdated{}, rec.events[1])
	require.IsType(t, qlog.BBRv3ControlUpdated{}, rec.events[2])

	round := rec.events[0].(qlog.BBRv3RoundUpdated)
	model := rec.events[1].(qlog.BBRv3ModelUpdated)
	control := rec.events[2].(qlog.BBRv3ControlUpdated)

	require.Equal(t, "startup", round.State)
	require.True(t, round.RoundStart)
	require.EqualValues(t, 1_100_000, round.DeliveryRate)
	require.True(t, round.DeliveryRateValid)
	require.EqualValues(t, 900_000, round.FullBW)
	require.EqualValues(t, 2, round.FullBWCount)
	require.Equal(t, "startup_round", model.Trigger)
	require.Equal(t, "startup_round", control.Trigger)
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

// TestBBRv3CheckFullBwReachedIntraRoundGrowthResets verifies that intra-round
// high-rate samples reset the full bandwidth baseline (Google-style behavior).
// This prevents false-positive "filled pipe" detection when the round-boundary
// ACK has an unrepresentatively low delivery rate.
func TestBBRv3CheckFullBwReachedIntraRoundGrowthResets(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRStartup
	bbr.fullBandwidth = 1_000
	bbr.bwHi[0] = 1_000
	bbr.minRTT = 10 * time.Millisecond

	// Round-start sample shows no growth (1100 < 1000 * 1.25 = 1250)
	plateau := bbrRateSample{deliveryRate: 1_100}
	// Intra-round sample shows growth (1300 >= 1000 * 1.25 = 1250)
	intraRoundSpike := bbrRateSample{deliveryRate: 1_300}

	// Round 1: plateau sample increments count
	bbr.roundStart = true
	bbr.checkFullBwReached(plateau)
	require.Equal(t, 1, bbr.fullBandwidthCount)
	require.Equal(t, protocol.ByteCount(1_000), bbr.fullBandwidth)

	// Intra-round spike resets count (Google-style: growth check on every ACK)
	bbr.roundStart = false
	bbr.checkFullBwReached(intraRoundSpike)
	require.Equal(t, 0, bbr.fullBandwidthCount,
		"intra-round growth sample must reset the counter")
	require.Equal(t, protocol.ByteCount(1_300), bbr.fullBandwidth,
		"intra-round growth sample must advance the baseline")

	// Subsequent rounds: with higher baseline (1300), plateau (1100) shows no growth
	// Need 3 consecutive no-growth rounds to trigger
	for round := 0; round < FULL_BW_ROUNDS; round++ {
		bbr.roundStart = true
		bbr.checkFullBwReached(plateau)
		require.Equal(t, round+1, bbr.fullBandwidthCount)
	}
	require.True(t, bbr.fullBandwidthReached)
}

// TestBBRv3CheckFullBwReachedCountOnlyAtRoundStart verifies that the no-growth
// counter only increments at round boundaries, even though growth detection
// runs on every ACK.
func TestBBRv3CheckFullBwReachedCountOnlyAtRoundStart(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRStartup
	bbr.fullBandwidth = 1_000
	bbr.bwHi[0] = 1_000
	bbr.minRTT = 10 * time.Millisecond

	// No-growth sample (1100 < 1000 * 1.25 = 1250)
	noGrowth := bbrRateSample{deliveryRate: 1_100}

	// Intra-round no-growth samples should NOT increment counter
	bbr.roundStart = false
	bbr.checkFullBwReached(noGrowth)
	require.Equal(t, 0, bbr.fullBandwidthCount,
		"non-round-start no-growth samples must not increment counter")

	// Round-start no-growth sample SHOULD increment counter
	bbr.roundStart = true
	bbr.checkFullBwReached(noGrowth)
	require.Equal(t, 1, bbr.fullBandwidthCount,
		"round-start no-growth samples must increment counter")
}

// TestBBRv3StartupExitsWithSuppressedRoundStartSamples verifies that the plateau
// counter advances even when round-start samples are suppressed (deliveryRate=0)
// due to interval < min_rtt. This prevents Startup from stalling on high-RTT paths
// where every round-start sample is suppressed.
//
// Background: The delivery rate sampler sets deliveryRate=0 when the sample
// interval is less than min_rtt (to avoid noisy estimates). At high RTT, this
// can affect round-start samples. The previous code had a guard that returned
// early on deliveryRate==0, which prevented the plateau counter from advancing.
//
// The fix removes the deliveryRate==0 guard. Suppressed samples (rate 0) still
// cannot exceed the 1.25x growth threshold, so they don't reset the baseline,
// and the plateau counter correctly advances at round boundaries.
//
// Ref: tcp_bbr.c line 1935 (bbr_check_full_bw_reached does not guard on rate==0)
// Fixes: F4 High-RTT Startup stall
func TestBBRv3StartupExitsWithSuppressedRoundStartSamples(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRStartup
	bbr.minRTT = 100 * time.Millisecond
	bbr.bwHi[0] = 100_000_000
	bbr.fullBandwidth = 100_000_000 // Baseline from first valid sample

	// Simulate 3 rounds where round-start samples are suppressed (rate=0)
	// but no growth is occurring. Counter should still advance at each round.
	for round := 0; round < FULL_BW_ROUNDS; round++ {
		bbr.roundStart = true
		// Suppressed round-start sample: rate=0 because interval < min_rtt
		rs := bbrRateSample{
			deliveryRate: 0, // Suppressed due to short interval
			interval:     50 * time.Millisecond,
		}
		bbr.checkFullBwReached(rs)
		require.Equal(t, round+1, bbr.fullBandwidthCount,
			"plateau counter should advance on suppressed sample (round %d)", round)
	}

	require.True(t, bbr.fullBandwidthReached,
		"should have reached full bandwidth after %d rounds with suppressed samples",
		FULL_BW_ROUNDS)
	require.True(t, bbr.fullBandwidthNow,
		"fullBandwidthNow should be set when plateau count reaches threshold")
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

// TestBBRv3StartupEstimatorsStateGated verifies that Startup-specific estimators
// (high-loss exit, bandwidth plateau) only run in BBRStartup state. If ProbeRTT
// is entered before fullBandwidthReached (via probe_rtt_interval expiry), these
// estimators must not fire — ProbeRTT's reduced cwnd would cause spurious triggers.
func TestBBRv3StartupEstimatorsStateGated(t *testing.T) {
	t.Run("checkLossTooHighInStartup_not_in_ProbeRTT", func(t *testing.T) {
		bbr := newTestBBRv3()
		// Set up conditions that WOULD trigger high-loss exit in Startup
		bbr.state = BBRProbeRTT // But we're in ProbeRTT, not Startup
		bbr.fullBandwidthReached = false
		bbr.lossRoundStart = true
		bbr.lossEventsInRound = STARTUP_FULL_LOSS_COUNT
		bbr.bytesLostInRound = 30_000
		bbr.bwHi[0] = 1_000_000
		bbr.minRTT = 10 * time.Millisecond

		bbr.checkLossTooHighInStartup(bbrRateSample{txInFlight: 100_000, priorInFlight: 100_000})

		require.False(t, bbr.fullBandwidthReached,
			"high-loss exit MUST NOT trigger in ProbeRTT state")
		require.Equal(t, protocol.MaxByteCount, bbr.inflightHi,
			"inflightHi MUST NOT be capped by ProbeRTT loss")
	})

	t.Run("checkFullBwReached_not_in_ProbeRTT", func(t *testing.T) {
		bbr := newTestBBRv3()
		// Set up conditions that WOULD trigger bandwidth plateau in Startup
		bbr.state = BBRProbeRTT // But we're in ProbeRTT, not Startup
		bbr.fullBandwidth = 1_000
		bbr.bwHi[0] = 1_000
		bbr.minRTT = 10 * time.Millisecond

		// Simulate FULL_BW_ROUNDS of plateau samples
		rs := bbrRateSample{deliveryRate: 1_100}
		for range FULL_BW_ROUNDS {
			bbr.roundStart = true
			bbr.checkFullBwReached(rs)
		}

		require.False(t, bbr.fullBandwidthReached,
			"bandwidth plateau MUST NOT trigger in ProbeRTT state")
		require.Equal(t, 0, bbr.fullBandwidthCount,
			"fullBandwidthCount MUST NOT accumulate in ProbeRTT state")
	})

	t.Run("checkFullBwReached_not_in_ProbeBW", func(t *testing.T) {
		bbr := newTestBBRv3()
		// ProbeBW_UP has its own plateau detection in updateCyclePhase
		bbr.state = BBRProbeBW
		bbr.probeBWPhase = probeBWUp
		bbr.fullBandwidth = 1_000
		bbr.bwHi[0] = 1_000
		bbr.minRTT = 10 * time.Millisecond

		rs := bbrRateSample{deliveryRate: 1_100}
		for range FULL_BW_ROUNDS {
			bbr.roundStart = true
			bbr.checkFullBwReached(rs)
		}

		require.False(t, bbr.fullBandwidthNow,
			"Startup's checkFullBwReached MUST NOT run in ProbeBW state")
	})
}

// TestBBRv3GuardrailAckAdvancesFirstSendTime verifies RFC §4.1.2.3:
// after ACKing the newest packet in an ACK event, future packets must inherit
// that packet's send time as the new first_send_time. Without this, send_elapsed
// grows from connection start and delivery-rate samples are increasingly
// underestimated over time.
func TestBBRv3GuardrailAckAdvancesFirstSendTime(t *testing.T) {
	bbr := newTestBBRv3()
	t0 := monotime.Now()

	// Keep one packet in flight across the ACK event so OnPacketSent can't fall
	// back to the "bytesInFlight == 0" path to refresh firstSentTime.
	bbr.OnPacketSent(t0, 1200, 1, 1200, true)
	bbr.OnPacketSent(t0.Add(10*time.Millisecond), 2400, 2, 1200, true)
	bbr.OnPacketSent(t0.Add(20*time.Millisecond), 3600, 3, 1200, true)

	ack1 := t0.Add(100 * time.Millisecond)
	bbr.OnAckEventStart(ack1, 3600)
	bbr.OnPacketAcked(1, 1200, 3600, ack1)
	bbr.OnPacketAcked(2, 1200, 2400, ack1)
	bbr.OnAckEventEnd(ack1)

	require.Equal(t, t0.Add(10*time.Millisecond), bbr.firstSentTime,
		"ACK processing should advance firstSentTime to the newest acked packet's send time")

	// Send a new packet while packet 3 is still in flight; it must inherit the
	// updated firstSentTime from packet 2's send time.
	send4 := t0.Add(101 * time.Millisecond)
	bbr.OnPacketSent(send4, 2400, 4, 1200, true)
	require.Equal(t, t0.Add(10*time.Millisecond), bbr.sentPackets[4].firstSentTime,
		"newly sent packets should inherit the refreshed firstSentTime")

	// When packet 4 is later ACKed, its send_elapsed should be measured from the
	// refreshed firstSentTime, not from connection start.
	ack2 := t0.Add(200 * time.Millisecond)
	bbr.OnAckEventStart(ack2, 2400)
	bbr.OnPacketAcked(3, 1200, 2400, ack2)
	bbr.OnPacketAcked(4, 1200, 1200, ack2)
	require.Equal(t, 91*time.Millisecond, bbr.pendingSendElapsed,
		"send_elapsed for later packets should use the refreshed firstSentTime")
}

func TestBBRv3GuardrailNewestPacketTieBreakUsesPacketNumber(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Send two packets at the exact same send time so RFC §4.1.2.3 requires
	// using packet_id to decide which delivered packet is "newest".
	bbr.OnPacketSent(now, 1200, 1, 1200, true)
	bbr.OnPacketSent(now, 2400, 2, 1200, true)

	// Force distinct per-packet sampler snapshots so we can see which one wins.
	st1 := bbr.sentPackets[1]
	st1.delivered = 111
	st1.deliveredTime = now.Add(-20 * time.Millisecond)
	st1.firstSentTime = now.Add(-30 * time.Millisecond)
	st1.isAppLimited = true
	bbr.sentPackets[1] = st1

	st2 := bbr.sentPackets[2]
	st2.delivered = 222
	st2.deliveredTime = now.Add(-10 * time.Millisecond)
	st2.firstSentTime = now.Add(-15 * time.Millisecond)
	st2.isAppLimited = false
	bbr.sentPackets[2] = st2

	ackTime := now.Add(40 * time.Millisecond)
	bbr.OnPacketAcked(1, 1200, 2400, ackTime)
	bbr.OnPacketAcked(2, 1200, 1200, ackTime)

	require.Equal(t, uint64(222), bbr.pendingPriorDelivered,
		"ACK-event sample should use the highest packet number when send times tie")
	require.Equal(t, now.Add(-10*time.Millisecond), bbr.pendingPriorTime,
		"ACK-event sample should use the newest delivered packet's delivered_time")
	require.Equal(t, 15*time.Millisecond, bbr.pendingSendElapsed,
		"ACK-event sample should use the newest delivered packet's send_elapsed")
	require.False(t, bbr.pendingIsAppLimited,
		"RS.is_app_limited should come from the newest delivered packet when send times tie")
}

// ============================================================================
// §5.3.2: DRAIN
// ============================================================================

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

func TestBBRv3DrainFallbackUsesDrainStartRound(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	bbr.state = BBRStartup
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 100_000_000
	bbr.minRTT = 40 * time.Millisecond
	bbr.roundCount = 7

	highInflight := protocol.ByteCount(10_000_000)

	bbr.roundStart = true
	bbr.checkDrain(bbrRateSample{bytesInFlight: highInflight}, now)
	require.Equal(t, BBRDrain, bbr.state)
	require.Equal(t, uint64(7), bbr.drainStartRound)

	for _, round := range []uint64{8, 9, 10} {
		bbr.roundCount = round
		bbr.roundStart = true
		bbr.checkDrain(bbrRateSample{bytesInFlight: highInflight}, now)
		require.Equal(t, BBRDrain, bbr.state,
			"Drain must persist until round_count exceeds drain_start_round + 3")
	}

	bbr.roundCount = 11
	bbr.roundStart = true
	bbr.checkDrain(bbrRateSample{bytesInFlight: highInflight}, now)
	require.Equal(t, BBRProbeBW, bbr.state)
}

// ============================================================================
// §5.3.3: PROBEBW
// ============================================================================

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
	bbr.ecnAlpha = ecnAlphaFromFloat(0.6)
	bbr.inflightLo = 30_000
	bbr.adaptLowerBounds(bbrRateSample{})
	require.Equal(t, protocol.ByteCount(24_000), bbr.inflightLo)
}

// ============================================================================
// §5.3.4: PROBERTT
// ============================================================================

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

	// H2: updateMinRTT now uses per-event RTT from pendingNewestSentTime
	bbr.pendingNewestSentTime = now.Add(-25 * time.Millisecond)
	bbr.updateMinRTT(now)
	require.Equal(t, BBRProbeRTT, bbr.state)
	require.Equal(t, originalCwnd, bbr.priorCwnd)
	require.False(t, bbr.probeRTTDoneStamp.IsZero())

	t1 := now
	bbr.probeRTTRoundDone = false
	bbr.roundStart = false
	bbr.pendingNewestSentTime = t1.Add(PROBE_RTT_DURATION + time.Millisecond - 25*time.Millisecond)
	bbr.updateMinRTT(t1.Add(PROBE_RTT_DURATION + time.Millisecond))
	require.Equal(t, BBRProbeRTT, bbr.state)

	bbr.roundStart = true
	bbr.pendingNewestSentTime = t1.Add(PROBE_RTT_DURATION + 2*time.Millisecond - 25*time.Millisecond)
	bbr.updateMinRTT(t1.Add(PROBE_RTT_DURATION + 2*time.Millisecond))
	require.Equal(t, BBRProbeBW, bbr.state)
	require.GreaterOrEqual(t, bbr.congestionWindow, originalCwnd)

	rttStats2 := utils.NewRTTStats()
	rttStats2.UpdateRTT(20*time.Millisecond, 0)
	idleRestart := NewBBRV3(DefaultClock{}, rttStats2, nil, initialMaxDatagramSize, false, nil)
	idleRestart.state = BBRProbeBW
	idleRestart.idleRestart = true
	idleRestart.probeRTTMinStamp = now.Add(-PROBE_RTT_INTERVAL - time.Millisecond)
	// H2: updateMinRTT now uses per-event RTT from pendingNewestSentTime
	idleRestart.pendingNewestSentTime = now.Add(-20 * time.Millisecond)
	idleRestart.updateMinRTT(now)
	require.NotEqual(t, BBRProbeRTT, idleRestart.state)
}

func TestBBRv3GuardrailProbeRTTUsesAckEventInflightAfterLoss(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(25*time.Millisecond, 0)
	bbr := NewBBRV3(DefaultClock{}, rttStats, nil, initialMaxDatagramSize, false, nil)
	now := monotime.Now()

	bbr.state = BBRProbeRTT
	bbr.totalBytesAcked = 50_000
	bbr.pendingPriorInFlight = 10 * bbr.maxDatagramSize
	bbr.pendingAckedBytes = 2 * bbr.maxDatagramSize
	bbr.ackEventTime = now
	bbr.ackEventBytesInFlight = 6 * bbr.maxDatagramSize
	// H2: updateMinRTT now uses per-event RTT from pendingNewestSentTime
	bbr.pendingNewestSentTime = now.Add(-25 * time.Millisecond)

	bbr.updateMinRTT(now)

	require.Equal(t, now.Add(PROBE_RTT_DURATION), bbr.probeRTTDoneStamp)
	require.Equal(t, bbr.totalBytesAcked+uint64(4*bbr.maxDatagramSize), bbr.appLimitedUntil)
}

// ============================================================================
// §5.5: MODEL UPDATES (AckAggregation, ECN, Loss Bounds)
// ============================================================================

// TestBBRv3LowerBoundsEventPath verifies that loss triggers lower bounds
// adaptation through the production event path, not direct method calls.
func TestBBRv3LowerBoundsEventPath(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish steady state in ProbeBW CRUISE with known bounds
	// CRUISE is NOT a probing phase, so adaptLowerBounds will run
	setupProbeBWPhase(bbr, probeBWCruise)

	// Set initial bounds - these will be adapted on loss
	initialBwLo := protocol.ByteCount(1_000_000)
	initialInflightLo := protocol.ByteCount(100_000)
	bbr.bwLo = initialBwLo
	bbr.inflightLo = initialInflightLo

	// Set latest values - these floor the adaptation per RFC §5.5.10:
	// bwLo = max(bwLatest, bwLo * BETA), inflightLo = max(inflightLatest, inflightLo * BETA)
	bbr.bwLatest = 800_000
	bbr.inflightLatest = 80_000

	// Initialize delivered counters for round tracking
	bbr.totalBytesAcked = 10_000
	bbr.lossRoundDelivered = 0 // Will trigger lossRoundStart when priorDelivered >= this

	// Send packets - these establish the round boundary
	for i := 1; i <= 5; i++ {
		bbr.OnPacketSent(now, protocol.ByteCount(i*1200), protocol.PacketNumber(i), 1200, true)
	}

	// Trigger loss through OnCongestionEvent (production path)
	bbr.OnCongestionEvent(1, 1200, 0)
	require.True(t, bbr.lossInRound, "lossInRound MUST be set after OnCongestionEvent")

	// ACK remaining packets to complete the round
	// The ACK processing will trigger lossRoundStart when priorDelivered >= lossRoundDelivered
	ackTime := now.Add(50 * time.Millisecond)
	for i := 2; i <= 5; i++ {
		bbr.OnPacketAcked(protocol.PacketNumber(i), 1200, protocol.ByteCount((i-1)*1200), ackTime)
	}

	// Process ACK event - this triggers updateLatestDeliverySignals -> updateCongestionSignals -> adaptLowerBounds
	bbr.OnAckEventEnd(ackTime)

	// RFC §5.5.10: After loss round, bounds are adapted using BETA = 0.70 (1 - 0.30):
	// bwLo = max(bwLatest, bwLo * 0.70) = max(800_000, 700_000) = 800_000
	// inflightLo = max(inflightLatest, inflightLo * 0.70) = max(80_000, 70_000) = 80_000
	expectedBwLo := protocol.ByteCount(800_000)         // max(bwLatest, bwLo*0.70)
	expectedInflightLo := protocol.ByteCount(80_000)   // max(inflightLatest, inflightLo*0.70)

	require.Less(t, bbr.bwLo, initialBwLo,
		"RFC §5.5.10: bwLo MUST be reduced after loss round (was %d, now %d)", initialBwLo, bbr.bwLo)
	require.Equal(t, expectedBwLo, bbr.bwLo,
		"RFC §5.5.10: bwLo MUST equal max(bwLatest, bwLo * BETA)")

	require.Less(t, bbr.inflightLo, initialInflightLo,
		"RFC §5.5.10: inflightLo MUST be reduced after loss round (was %d, now %d)", initialInflightLo, bbr.inflightLo)
	require.Equal(t, expectedInflightLo, bbr.inflightLo,
		"RFC §5.5.10: inflightLo MUST equal max(inflightLatest, inflightLo * BETA)")
}

// TestBBRv3LossModelPerPacketState verifies that OnPacketSent captures
// P.lost (totalBytesLost) for loss-round detection per RFC §5.5.10.
func TestBBRv3LossModelPerPacketState(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up known loss state before sending
	bbr.totalBytesLost = 5_000

	bbr.OnPacketSent(now, 10_000, 1, 1200, true)

	st, ok := bbr.sentPackets[1]
	require.True(t, ok, "packet state should be tracked")

	// RFC §5.5.10: P.lost captures C.lost at send time for loss-round detection
	require.Equal(t, uint64(5_000), st.totalBytesLost,
		"RFC §5.5.10: P.lost MUST equal C.lost at send time for loss-round detection")
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

func TestBBRv3ProbeRTTCwndUsesBoundedBandwidth(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.minRTT = 40 * time.Millisecond
	bbr.bwHi[0] = 10_000_000
	bbr.bwLo = 2_000_000

	expected := max(bbr.inflightFromBWGain(bbr.boundedBandwidth(), PROBE_RTT_CWND_GAIN), bbr.minPipeCwnd)
	require.Equal(t, expected, bbr.probeRTTCwnd())
}

func TestBBRv3CwndLimitedSticksAcrossRoundBoundary(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()
	bbr.congestionWindow = 10 * bbr.maxDatagramSize

	// Mark the just-completed round as cwnd-limited from the send path.
	bbr.OnPacketSent(now, 10*bbr.maxDatagramSize, 1, bbr.maxDatagramSize, true)
	require.True(t, bbr.cwndLimitedInRound)

	// Crossing a round boundary should preserve the signal for ACK-time decisions
	// even when the instantaneous inflight on the boundary ACK is low.
	bbr.nextRoundDelivered = 0
	bbr.updateRoundStart(bbrRateSample{priorDelivered: 0})

	require.True(t, bbr.cwndLimitedPrevRound)
	require.False(t, bbr.cwndLimitedInRound)
	require.True(t, bbr.isRoundCwndLimited(0),
		"cwnd-limited state should remain visible for the just-completed round")
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

// ----------------------------------------------------------------------------
// M1a: ECN GUARD AT ZERO minRTT
// ----------------------------------------------------------------------------

// TestBBRv3ECNGuardAtZeroMinRTT verifies that ECN feedback is not processed
// before minRTT is established. When minRTT == 0 (no RTT sample yet), ECN
// counters can arrive before QUIC validation completes. The guard ensures
// ecnEligible remains false and pendingECNCEBytes is not stored until we
// have a real minRTT measurement.
func TestBBRv3ECNGuardAtZeroMinRTT(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// minRTT is zero (no RTT sample yet)
	require.Equal(t, time.Duration(0), bbr.minRTT)

	// Receive ECN feedback before minRTT is established
	bbr.OnECNFeedback(1000, 100, 0, 10, 0, now)

	// ecnEligible should still be false — can't trust ECN before minRTT
	require.False(t, bbr.ecnEligible,
		"ECN should not be eligible before minRTT is established")

	// pendingECNCEBytes should NOT be stored
	require.Equal(t, protocol.ByteCount(0), bbr.pendingECNCEBytes,
		"CE bytes should not be stored before ECN eligibility")
}

// TestBBRv3ECNEligibilityTransition verifies the correct transition from
// ECN-ineligible (minRTT == 0) to ECN-eligible (minRTT > 0 and within
// ECN_MAX_RTT threshold). The first ECN feedback before minRTT is ignored,
// but subsequent feedback after minRTT is established should be processed.
func TestBBRv3ECNEligibilityTransition(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Phase 1: ECN feedback before minRTT
	bbr.OnECNFeedback(1000, 100, 0, 10, 0, now)
	require.False(t, bbr.ecnEligible)
	require.Equal(t, protocol.ByteCount(0), bbr.pendingECNCEBytes)

	// Establish minRTT
	bbr.minRTT = 3 * time.Millisecond // Within ECN_MAX_RTT (5ms)

	// Phase 2: ECN feedback after minRTT — should be eligible now
	bbr.OnECNFeedback(1000, 200, 0, 20, 0, now.Add(time.Millisecond))
	require.True(t, bbr.ecnEligible,
		"ECN should become eligible after minRTT is established")
	require.Greater(t, bbr.pendingECNCEBytes, protocol.ByteCount(0),
		"CE bytes should be stored after eligibility")
}

// TestBBRv3ECNAlphaBaselineSeedOnEligibility verifies that when ECN eligibility
// transitions from false to true, the alpha baseline (alphaLastDelivered,
// alphaLastDeliveredCE) is seeded from current totals. Without this, the first
// CE ratio would be diluted by historical bytes delivered before ECN was trustworthy.
func TestBBRv3ECNAlphaBaselineSeedOnEligibility(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Phase 1: Accumulate delivery counters while ECN is ineligible
	// (minRTT == 0, so ECN feedback is ignored)
	bbr.totalBytesAcked = 100_000
	bbr.totalBytesAckedCE = 5_000 // 5% CE if measured from start

	// Alpha baseline should still be zero (not yet seeded)
	require.Equal(t, uint64(0), bbr.alphaLastDelivered)
	require.Equal(t, uint64(0), bbr.alphaLastDeliveredCE)

	// Phase 2: minRTT becomes valid, ECN feedback triggers eligibility
	bbr.minRTT = 3 * time.Millisecond // Within ECN_MAX_RTT
	bbr.OnECNFeedback(1000, 100, 0, 10, 0, now)

	// Now eligible
	require.True(t, bbr.ecnEligible)

	// Alpha baseline should be seeded from current totals
	require.Equal(t, bbr.totalBytesAcked, bbr.alphaLastDelivered,
		"alphaLastDelivered MUST be seeded from totalBytesAcked on eligibility transition")
	require.Equal(t, bbr.totalBytesAckedCE, bbr.alphaLastDeliveredCE,
		"alphaLastDeliveredCE MUST be seeded from totalBytesAckedCE on eligibility transition")

	// Phase 3: Subsequent delivery with high CE rate
	bbr.totalBytesAcked += 10_000
	bbr.totalBytesAckedCE += 5_000 // 50% CE in this interval

	// Trigger updateECNAlpha via round start
	bbr.roundStart = true
	bbr.updateECNAlpha(bbrRateSample{})

	// The CE ratio should be ~50% (5000/10000), NOT ~9% (10000/110000)
	// With g=1/16 bit-shift EWMA: alpha = alpha - (alpha >> 4) + (ceRatio >> 4)
	// Starting from alpha=1.0: alpha = 1.0 - 0.0625 + 0.03125 ≈ 0.97
	expectedAlpha := 1.0 - (1.0 / 16.0) + (0.5 / 16.0)
	require.InDelta(t, expectedAlpha, ecnAlphaToFloat(bbr.ecnAlpha), 0.01,
		"ECN alpha should reflect only post-eligibility CE ratio, not lifetime")
}

// TestBBRv3ECNGuardHighMinRTT verifies that ECN feedback is rejected when
// minRTT exceeds ECN_MAX_RTT (5ms). Low-latency ECN signals are only
// meaningful on paths with sub-5ms RTT per tcp_bbr.c:bbr_ecn_max_rtt_us.
func TestBBRv3ECNGuardHighMinRTT(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set minRTT above ECN_MAX_RTT threshold
	bbr.minRTT = 10 * time.Millisecond // Above ECN_MAX_RTT (5ms)

	// Receive ECN feedback
	bbr.OnECNFeedback(1000, 100, 0, 10, 0, now)

	// ecnEligible should remain false - RTT too high for ECN
	require.False(t, bbr.ecnEligible,
		"ECN should not be eligible when minRTT > ECN_MAX_RTT")
	require.Equal(t, protocol.ByteCount(0), bbr.pendingECNCEBytes,
		"CE bytes should not be stored when minRTT > ECN_MAX_RTT")
}

// ----------------------------------------------------------------------------
// H2: PER-EVENT RTT FOR updateMinRTT
// ----------------------------------------------------------------------------

// TestBBRv3UpdateMinRTTUsesPerEventRTT verifies that updateMinRTT uses the
// per-event RTT calculated from pendingNewestSentTime (the newest packet's
// send time in the ACK event), not the potentially stale rttStats.LatestRTT().
// Per draft-ietf-ccwg-bbr-05 §5.3.4.3, BBRUpdateMinRTT should use the RTT
// from the current ACK event.
func TestBBRv3UpdateMinRTTUsesPerEventRTT(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Send a packet
	bbr.OnPacketSent(now, 0, 1, 1200, true)

	// ACK it 50ms later
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnPacketAcked(1, 1200, 0, ackTime)
	bbr.OnAckEventEnd(ackTime)

	// minRTT should be ~50ms (the actual RTT of this packet)
	require.InDelta(t, 50*time.Millisecond, bbr.minRTT, float64(5*time.Millisecond),
		"minRTT should be based on per-event RTT calculation")
}

// TestBBRv3UpdateMinRTTEmptyEventGuard verifies that updateMinRTT correctly
// handles empty ACK events (where pendingNewestSentTime is zero) by early
// returning without modifying minRTT. This prevents invalid RTT samples
// from corrupting the min_rtt filter.
func TestBBRv3UpdateMinRTTEmptyEventGuard(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set an initial minRTT
	bbr.minRTT = 100 * time.Millisecond
	initialMinRTT := bbr.minRTT

	// Call updateMinRTT with zero pendingNewestSentTime (no packets in event)
	bbr.pendingNewestSentTime = 0
	bbr.updateMinRTT(now)

	// minRTT should be unchanged - empty event should early return
	require.Equal(t, initialMinRTT, bbr.minRTT,
		"empty event should not update minRTT")
}

// ----------------------------------------------------------------------------
// M2: EXTRA_ACKED ROTATION WINDOW
// ----------------------------------------------------------------------------

// TestBBRv3ExtraAckedRetentionWindow verifies that the extra_acked filter
// rotates slots every 5 rounds (EXTRA_ACKED_WIN_RTS), so old samples are
// evicted within ~10 rounds. This matches tcp_bbr.c bbr_extra_acked_win_rtts=5
// with 2 slots, approximating the RFC's BBRExtraAckedFilterLen=10.
func TestBBRv3ExtraAckedRetentionWindow(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Must be in ProbeBW (not Startup) to use the 5-round rotation
	bbr.state = BBRProbeBW
	bbr.fullBandwidthReached = true

	// Record a large sample in slot 0
	bbr.extraAcked[0] = 10000
	bbr.extraAckedWinIdx = 0
	bbr.extraAckedWinRTTs = 0

	// After 5 rounds: rotates to slot 1, zeros slot 1, slot 0 still has 10000
	// After 10 rounds: rotates to slot 0, zeros slot 0, slot 1 may have small values
	// So we need 10+ rounds to evict the original sample from slot 0

	// Simulate rounds - use minimal ACKs to avoid accumulating extra_acked
	for round := 0; round < 11; round++ {
		bbr.roundStart = true
		// Reset ack epoch to prevent extra_acked accumulation
		bbr.ackEpochAcked = 0
		bbr.ackEpochStart = now.Add(time.Duration(round) * 100 * time.Millisecond)
		rs := bbrRateSample{newlyAcked: 1} // minimal ACK
		bbr.updateAckAggregation(rs, now.Add(time.Duration(round)*100*time.Millisecond))
		bbr.roundStart = false
	}

	// With 5-round rotation, after 11 rounds (> 2*5), both slots should have
	// been rotated and the original 10000 value evicted
	require.Less(t, bbr.maxExtraAcked(), protocol.ByteCount(10000),
		"original sample should be rotated out within 10 rounds")
}

// ----------------------------------------------------------------------------
// M5: ACK_EPOCH_ACKED THRESHOLD SCALING
// ----------------------------------------------------------------------------

// TestBBRv3AckEpochAckedThresholdScaling verifies that the ack_epoch_acked
// threshold is scaled by MTU (maxDatagramSize). Linux's BBR_ACK_EPOCH_ACKED_MAX
// = (1<<20) - 1 is a 20-bit *packet* count. quic-go's ackEpochAcked is a byte
// count, so applying the same constant as bytes causes epoch resets ~700x too
// early on high-BDP paths (1500-byte MTU vs 1-byte packets).
func TestBBRv3AckEpochAckedThresholdScaling(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set a known MTU
	bbr.maxDatagramSize = 1500
	bbr.fullBandwidthReached = true
	// Use low bandwidth so expected bytes << actual acked bytes (triggers aggregation)
	bbr.bwHi[0] = 100_000 // 100 KB/s

	// The MTU-scaled threshold is (1<<20) * 1500 = 1,572,864,000 bytes (~1.5 GB)
	// The old unscaled threshold was (1<<20) = 1,048,576 bytes (~1 MB)
	//
	// We'll accumulate 2 MiB (past the old threshold) and verify no reset occurred.
	// To avoid "ackEpochAcked <= expected" resets, we use low bandwidth so
	// acked bytes accumulate faster than the expected BDP.

	totalAcked := protocol.ByteCount(0)
	for i := 0; i < 2000; i++ {
		rs := bbrRateSample{newlyAcked: 1200}
		// Use short intervals so expected stays small relative to acked
		bbr.updateAckAggregation(rs, now.Add(time.Duration(i)*time.Millisecond))
		totalAcked += 1200
	}

	// Total acked = 2000 * 1200 = 2,400,000 bytes (~2.4 MB)
	// This is well past the old 1 MB threshold but below the new ~1.5 GB threshold.
	// With the fix, ackEpochAcked should accumulate past 1 MB without reset.
	require.Greater(t, bbr.ackEpochAcked, protocol.ByteCount(1<<20),
		"ack_epoch_acked should not reset at 1MB with MTU-scaled threshold")
}

// TestBBRv3AckEpochUnderflowGuard verifies that updateAckAggregation handles
// edge cases gracefully, including zero maxDatagramSize (which shouldn't happen
// but we should be defensive).
func TestBBRv3AckEpochUnderflowGuard(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Edge case: maxDatagramSize is 0 (shouldn't happen but be defensive)
	bbr.maxDatagramSize = 0

	// Should not panic
	rs := bbrRateSample{newlyAcked: 1000}
	require.NotPanics(t, func() {
		bbr.updateAckAggregation(rs, now)
	}, "should handle zero maxDatagramSize gracefully")
}

// TestBBRv3SpuriousLossNoopWithoutEpisode verifies that OnSpuriousLossDetected
// is a no-op when no loss episode is active. Per RFC §5.5.11 episode-level
// semantics, spurious loss detection only applies to packets in an active episode.
func TestBBRv3SpuriousLossNoopWithoutEpisode(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up known model state
	bbr.bwLo = 500_000
	bbr.inflightLo = 50_000
	bbr.inflightHi = 100_000
	bbr.congestionWindow = 80_000
	bbr.lossInRound = true

	// Save state as if loss just occurred
	bbr.undoBwLo = 800_000
	bbr.undoInflightLo = 80_000
	bbr.undoInflightHi = 150_000
	bbr.undoCwnd = 120_000

	// NO active episode - OnSpuriousLossDetected should be a no-op
	require.False(t, bbr.lossEpisodeActive, "no episode should be active")

	// Call OnSpuriousLossDetected for a packet not in any episode
	bbr.OnSpuriousLossDetected(1, 1)

	// Episode-level semantics: bounds should NOT be restored without active episode
	require.Equal(t, protocol.ByteCount(500_000), bbr.bwLo,
		"bwLo should NOT be restored without active episode")
	require.Equal(t, protocol.ByteCount(50_000), bbr.inflightLo,
		"inflightLo should NOT be restored without active episode")
	require.Equal(t, protocol.ByteCount(100_000), bbr.inflightHi,
		"inflightHi should NOT be restored without active episode")
	require.True(t, bbr.lossInRound,
		"lossInRound should NOT be cleared without active episode")
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
	expectedBwLo := protocol.ByteCount(float64(800_000) * 0.70)      // 560_000
	expectedInflightLo := protocol.ByteCount(float64(80_000) * 0.70) // 56_000
	require.Equal(t, max(bbr.bwLatest, expectedBwLo), bbr.bwLo)
	require.Equal(t, max(bbr.inflightLatest, expectedInflightLo), bbr.inflightLo)

	// Now call OnSpuriousLossDetected - this should restore bounds
	bbr.OnSpuriousLossDetected(1, 1)

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

	// Set up active episode with one packet (100% spurious meets >50% threshold)
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{1: 1200}
	bbr.lossEpisodeTotalBytes = 1200
	bbr.lossEpisodeSpuriousBytes = 0

	// Spurious loss detected - should restore Startup state
	bbr.OnSpuriousLossDetected(1, 1)

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

	// Set up active episode with one packet (100% spurious meets >50% threshold)
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{1: 1200}
	bbr.lossEpisodeTotalBytes = 1200
	bbr.lossEpisodeSpuriousBytes = 0

	// Per RFC §5.5.11.2: bwLo = max(bwLo, undo_bwLo)
	// If undo values are MaxByteCount (unconstrained), recovery should
	// restore to MaxByteCount. This is critical for recovering from
	// spurious loss that occurred when bounds were unconstrained.
	bbr.OnSpuriousLossDetected(1, 1)

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

	// Set up active episode with one packet (100% spurious meets >50% threshold)
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{1: 1200}
	bbr.lossEpisodeTotalBytes = 1200
	bbr.lossEpisodeSpuriousBytes = 0

	// First call restores (and clears episode)
	bbr.OnSpuriousLossDetected(1, 1)
	require.Equal(t, protocol.ByteCount(800_000), bbr.bwLo)
	require.Equal(t, protocol.ByteCount(80_000), bbr.inflightLo)
	require.Equal(t, protocol.ByteCount(120_000), bbr.inflightHi)
	require.False(t, bbr.lossEpisodeActive, "episode should be cleared after restoration")

	// Second call should be idempotent (no episode active, so no-op)
	bbr.OnSpuriousLossDetected(1, 1)
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

	// Set up active episode with one packet (100% spurious meets >50% threshold)
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{1: 1200}
	bbr.lossEpisodeTotalBytes = 1200
	bbr.lossEpisodeSpuriousBytes = 0

	// Spurious loss detected - should restore both bounds AND cwnd
	bbr.OnSpuriousLossDetected(1, 1)

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
	bbr.bwLo = 12_000_000    // Reduced to 12 MB/s = 96 Mbps
	bbr.inflightLo = 600_000 // Reduced inflight

	// Verify bounds are now constrained
	require.NotEqual(t, protocol.MaxByteCount, bbr.bwLo)
	require.NotEqual(t, protocol.MaxByteCount, bbr.inflightLo)

	// Set up active episode with one packet (100% spurious meets >50% threshold)
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{1: 1200}
	bbr.lossEpisodeTotalBytes = 1200
	bbr.lossEpisodeSpuriousBytes = 0

	// Spurious loss detected - should restore to MaxByteCount (unconstrained)
	bbr.OnSpuriousLossDetected(1, 1)

	// Critical: bounds must be restored to MaxByteCount (unconstrained)
	// This was broken before the fix - the != MaxByteCount check prevented restoration
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo, "bwLo should be restored to unconstrained")
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo, "inflightLo should be restored to unconstrained")
}

// TestBBRv3SpuriousRecoveryRequiresMajority verifies RFC §5.5.11 episode-level
// semantics: spurious loss recovery only triggers when >50% of episode bytes
// are determined to be spurious.
func TestBBRv3SpuriousRecoveryRequiresMajority(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up in ProbeBW CRUISE state with known bounds
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWCruise
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 1_000_000
	bbr.minRTT = 20 * time.Millisecond
	bbr.congestionWindow = 100_000

	// Initialize bounds (pre-loss state)
	bbr.bwLo = 800_000
	bbr.inflightLo = 80_000
	bbr.inflightHi = 120_000

	// Send 4 packets of 1000 bytes each (total episode = 4000 bytes)
	for i := protocol.PacketNumber(1); i <= 4; i++ {
		bbr.OnPacketSent(now, protocol.ByteCount(i-1)*1000, i, 1000, true)
		now = now.Add(time.Millisecond)
	}

	// Lose all 4 packets - triggers OnCongestionEvent and saves state
	for i := protocol.PacketNumber(1); i <= 4; i++ {
		bbr.OnCongestionEvent(i, 1000, 0)
	}

	// Verify loss was recorded
	require.True(t, bbr.lossInRound, "lossInRound should be set")

	// Trigger adaptLowerBounds by simulating loss round end
	// This promotes pending losses to active episode and applies cuts
	bbr.roundStart = true
	bbr.lossRoundStart = true
	bbr.bwLatest = 700_000
	bbr.inflightLatest = 70_000
	bbr.adaptLowerBounds(bbrRateSample{})

	// Verify episode is active with 4000 total bytes
	require.True(t, bbr.lossEpisodeActive, "loss episode should be active after cuts applied")
	require.Equal(t, protocol.ByteCount(4000), bbr.lossEpisodeTotalBytes,
		"episode should track 4000 total bytes lost")

	// Bounds should now be reduced
	reducedBwLo := bbr.bwLo
	reducedInflightLo := bbr.inflightLo
	require.Less(t, reducedBwLo, protocol.ByteCount(800_000), "bwLo should be reduced")
	require.Less(t, reducedInflightLo, protocol.ByteCount(80_000), "inflightLo should be reduced")

	// Mark only 1 packet (1000 bytes) as spurious - this is 25%, not majority
	bbr.OnSpuriousLossDetected(1, 1)

	// Bounds should NOT be restored yet (only 25% spurious, need >50%)
	require.Equal(t, reducedBwLo, bbr.bwLo,
		"bwLo should NOT be restored when <50%% of episode is spurious")
	require.Equal(t, reducedInflightLo, bbr.inflightLo,
		"inflightLo should NOT be restored when <50%% of episode is spurious")
	require.Equal(t, protocol.ByteCount(1000), bbr.lossEpisodeSpuriousBytes,
		"spurious bytes should be accumulated")
	require.True(t, bbr.lossEpisodeActive, "episode should still be active")

	// Mark second packet (1000 bytes) as spurious - now 50%, still not majority
	bbr.OnSpuriousLossDetected(2, 2)

	// 2000/4000 = 50% is NOT >50%, so still no restoration
	require.Equal(t, reducedBwLo, bbr.bwLo,
		"bwLo should NOT be restored at exactly 50%% (need >50%%)")
	require.Equal(t, protocol.ByteCount(2000), bbr.lossEpisodeSpuriousBytes)

	// Mark third packet (1000 bytes) as spurious - now 75%, this is majority
	bbr.OnSpuriousLossDetected(3, 3)

	// 3000/4000 = 75% > 50%, so restoration SHOULD happen now
	// Using 2x comparison: 2*3000 = 6000 > 4000, so majority threshold met
	require.Equal(t, protocol.ByteCount(800_000), bbr.bwLo,
		"bwLo should be restored when >50%% of episode is spurious")
	require.Equal(t, protocol.ByteCount(80_000), bbr.inflightLo,
		"inflightLo should be restored when >50%% of episode is spurious")
	require.False(t, bbr.lossEpisodeActive,
		"episode should be cleared after restoration")
	require.False(t, bbr.lossInRound,
		"lossInRound should be cleared after spurious recovery")
}

func TestBBRv3SpuriousLossRecoveryRequiresMajority(t *testing.T) {
	// Verifies that recovery triggers ONLY when >50% of bytes are spurious.
	// This prevents single-packet majorities in multi-packet episodes.
	bbr := newTestBBRv3()

	// Set up constrained bounds
	bbr.bwLo = 500_000
	bbr.inflightLo = 50_000
	bbr.inflightHi = 100_000
	bbr.lossInRound = true

	// Episode with 2 packets of 1200 bytes each = 2400 total
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{
		1: 1200,
		2: 1200,
	}
	bbr.lossEpisodeTotalBytes = 2400
	bbr.lossEpisodeSpuriousBytes = 0

	// Mark packet 1 as spurious: 1200/2400 = 50% exactly
	// This should NOT trigger recovery (need >50%, not >=50%)
	bbr.OnSpuriousLossDetected(1, 1, 1200)

	require.True(t, bbr.lossEpisodeActive, "50% spurious should not trigger recovery")
	require.Equal(t, protocol.ByteCount(500_000), bbr.bwLo, "bwLo should be unchanged at 50%")
	require.Equal(t, protocol.ByteCount(50_000), bbr.inflightLo, "inflightLo should be unchanged at 50%")
	require.True(t, bbr.lossInRound, "lossInRound should still be set")

	// Now mark packet 2 as spurious: 2400/2400 = 100%
	// This SHOULD trigger recovery (>50%)
	bbr.OnSpuriousLossDetected(2, 2, 1200)

	require.False(t, bbr.lossEpisodeActive, "100% spurious should trigger recovery")
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo, "bwLo should be restored")
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo, "inflightLo should be restored")
	require.False(t, bbr.lossInRound, "lossInRound should be cleared")
}

func TestBBRv3SpuriousLossRecoveryAt51Percent(t *testing.T) {
	// Boundary test: 51% spurious should trigger recovery
	bbr := newTestBBRv3()

	bbr.bwLo = 500_000
	bbr.inflightLo = 50_000
	bbr.lossInRound = true

	// Episode with asymmetric packets: 1000 + 960 = 1960 total bytes
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{
		1: 1000,
		2: 960,
	}
	bbr.lossEpisodeTotalBytes = 1960
	bbr.lossEpisodeSpuriousBytes = 0

	// Mark packet 1 as spurious: 1000/1960 = 51.02%
	// This SHOULD trigger recovery (>50%)
	bbr.OnSpuriousLossDetected(1, 1, 1000)

	require.False(t, bbr.lossEpisodeActive, "51% spurious should trigger recovery")
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo, "bwLo should be restored at 51%")
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo, "inflightLo should be restored at 51%")
}

// ############################################################################
// PART 3: REGRESSION TESTS
// ############################################################################
//
// PURPOSE: Pin bug fixes and edge cases discovered through testing/production.
//
// Each test should reference the issue/commit that motivated it.
// ############################################################################

// TestBBRv3GuardrailStartupReachesFullBwWithoutAppLimited verifies Issue 1:
// Bulk-transfer Startup must reach fullBandwidthReached without samples being
// perpetually marked as app-limited due to cwnd growing faster than pacing allows.
func TestBBRv3GuardrailStartupReachesFullBwWithoutAppLimited(t *testing.T) {
	bbr := newTestBBRv3()
	rtt := 40 * time.Millisecond

	bbr.state = BBRStartup
	bbr.minRTT = rtt
	bbr.bwHi[0] = 1 // Initialize to non-zero for bandwidth tracking

	// Key assertion: with proper app-limited semantics (bubble-based),
	// samples from a bulk transfer should NOT be marked app-limited.
	// MarkAppLimited() is only called when send was allowed but no data available.
	// Since we're simulating a bulk transfer with data to send, appLimitedUntil = 0.
	require.Equal(t, uint64(0), bbr.appLimitedUntil,
		"appLimitedUntil should be 0 at start (no app-limited bubble)")

	// Simulate plateau rounds directly via checkFullBwReached
	// This tests the core logic without the full model update path complexity
	plateauRate := protocol.ByteCount(10_000_000) // 10 MB/s

	// Set fullBandwidth to the plateau rate so subsequent samples show < 25% growth
	bbr.fullBandwidth = plateauRate
	bbr.bwHi[0] = plateauRate

	// Now run through FULL_BW_ROUNDS with stable rate (< 25% growth)
	// Each sample shows small growth (< 1.25x), so counter increments
	for round := 0; round < FULL_BW_ROUNDS+1; round++ {
		// Create a rate sample that is NOT app-limited
		// Growth is only 1% per round, well below 25% threshold
		rs := bbrRateSample{
			deliveryRate: plateauRate + protocol.ByteCount(round*100_000), // 1% growth
			isAppLimited: false,                                           // Key: with fix, bulk-transfer samples are NOT app-limited
		}

		bbr.roundStart = true
		bbr.checkFullBwReached(rs)

		if round >= FULL_BW_ROUNDS-1 {
			// After 3 rounds of < 25% growth, fullBandwidthReached should be true
			require.True(t, bbr.fullBandwidthReached,
				"fullBandwidthReached should be true after %d plateau rounds", round+1)
		}
	}

	// Also verify: if samples WERE app-limited, fullBandwidthReached would stay false
	bbr2 := newTestBBRv3()
	bbr2.state = BBRStartup
	bbr2.fullBandwidth = plateauRate / 2
	bbr2.bwHi[0] = plateauRate

	for round := 0; round < FULL_BW_ROUNDS+1; round++ {
		rs := bbrRateSample{
			deliveryRate: plateauRate + protocol.ByteCount(round*100_000),
			isAppLimited: true, // App-limited samples are skipped
		}
		bbr2.roundStart = true
		bbr2.checkFullBwReached(rs)
	}
	require.False(t, bbr2.fullBandwidthReached,
		"fullBandwidthReached should stay false with app-limited samples")
}

// TestBBRv3GuardrailProbeRTTExitsToProbeBW verifies Issue 1 (part 2):
// After fullBandwidthReached, ProbeRTT must exit to ProbeBW, not back to Startup.
func TestBBRv3GuardrailProbeRTTExitsToProbeBW(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up: in ProbeBW with fullBandwidthReached = true
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWCruise
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 10_000_000
	bbr.minRTT = 40 * time.Millisecond
	bbr.congestionWindow = 100_000

	// Trigger ProbeRTT entry (timer expired)
	bbr.probeRTTMinStamp = now.Add(-PROBE_RTT_INTERVAL - time.Millisecond)
	bbr.idleRestart = false
	// H2: updateMinRTT now uses per-event RTT from pendingNewestSentTime
	bbr.pendingNewestSentTime = now.Add(-40 * time.Millisecond)
	bbr.updateMinRTT(now)
	require.Equal(t, BBRProbeRTT, bbr.state, "should enter ProbeRTT")

	// Complete ProbeRTT (duration elapsed + round completed)
	bbr.probeRTTDoneStamp = now
	bbr.probeRTTRoundDone = true
	bbr.roundStart = true
	exitTime := now.Add(PROBE_RTT_DURATION + time.Millisecond)
	bbr.pendingNewestSentTime = exitTime.Add(-40 * time.Millisecond)
	bbr.updateMinRTT(exitTime)

	// Must exit to ProbeBW, not Startup
	require.Equal(t, BBRProbeBW, bbr.state,
		"ProbeRTT should exit to ProbeBW when fullBandwidthReached is true")
	require.True(t, bbr.fullBandwidthReached,
		"fullBandwidthReached should remain true after ProbeRTT")
}

func TestBBRv3GuardrailProbeRTTExitDoesNotRotateMaxBwFilter(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	bbr.state = BBRProbeRTT
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 10_000_000
	bbr.bwHi[1] = 50_000

	bbr.exitProbeRTT(now)

	require.Equal(t, BBRProbeBW, bbr.state)
	require.Equal(t, probeBWCruise, bbr.probeBWPhase)
	require.Equal(t, ackPhaseInit, bbr.ackPhase)
	require.Equal(t, protocol.ByteCount(10_000_000), bbr.maxBandwidth())

	bbr.roundStart = true
	bbr.adaptUpperBounds(bbrRateSample{isAppLimited: false}, now.Add(time.Millisecond))

	require.Equal(t, protocol.ByteCount(10_000_000), bbr.maxBandwidth(),
		"the first post-ProbeRTT low sample must not rotate away the prior cycle's max_bw")
}

// TestBBRv3GuardrailProbeRTTRefreshesAppLimitedBubble verifies the ProbeRTT
// RFC requirement to mark the connection app-limited on every ACK while
// handling ProbeRTT, not just once on entry.
func TestBBRv3GuardrailProbeRTTRefreshesAppLimitedBubble(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(25*time.Millisecond, 0)
	bbr := NewBBRV3(DefaultClock{}, rttStats, nil, initialMaxDatagramSize, false, nil)
	now := monotime.Now()

	bbr.state = BBRProbeRTT
	bbr.totalBytesAcked = 50_000
	bbr.appLimitedUntil = 0 // Simulate the ProbeRTT bubble having expired on a prior ACK.
	bbr.pendingPriorInFlight = 12 * bbr.maxDatagramSize
	bbr.pendingAckedBytes = 4 * bbr.maxDatagramSize
	// H2: updateMinRTT now uses per-event RTT from pendingNewestSentTime
	bbr.pendingNewestSentTime = now.Add(-25 * time.Millisecond)

	expectedBubble := bbr.totalBytesAcked + uint64(8*bbr.maxDatagramSize)
	bbr.updateMinRTT(now)

	require.Equal(t, expectedBubble, bbr.appLimitedUntil,
		"ProbeRTT ACK handling should refresh the app-limited bubble to delivered+inflight")

	packetNumber := protocol.PacketNumber(1)
	bytesInFlight := 9 * bbr.maxDatagramSize
	bbr.OnPacketSent(now, bytesInFlight, packetNumber, bbr.maxDatagramSize, true)

	st, ok := bbr.sentPackets[packetNumber]
	require.True(t, ok, "sent packet state should be tracked")
	require.True(t, st.isAppLimited,
		"packets sent after a ProbeRTT ACK should remain app-limited until the bubble drains")
}

// TestBBRv3GuardrailProbeBWUpInflightHiGrowsMSS verifies Issue 2:
// ProbeBW_UP must grow inflightHi by MSS-sized steps, not byte-sized steps.
func TestBBRv3GuardrailProbeBWUpInflightHiGrowsMSS(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up in ProbeBW_UP phase
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWUp
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 10_000_000 // 10 MB/s
	bbr.minRTT = 40 * time.Millisecond
	bbr.congestionWindow = 400_000 // ~400KB (~312 packets)
	bbr.inflightHi = 400_000
	bbr.bwProbeUpRounds = 0
	bbr.bwProbeUpAcks = 0
	bbr.raiseInflightHiSlope() // Initialize bwProbeUpCnt

	// After raiseInflightHiSlope with rounds=0:
	// cwndPkts = 400000/1280 = 312, growthThisRound = 1
	// bwProbeUpCnt = 312 (packets to ACK before adding 1 packet)
	initialInflightHi := bbr.inflightHi
	initialCnt := bbr.bwProbeUpCnt

	// We need to ACK bwProbeUpCnt packets to trigger 1 MSS growth
	// ACK the full cwnd worth of data
	rs := bbrRateSample{
		priorInFlight: bbr.congestionWindow,
		newlyAcked:    bbr.congestionWindow, // ACK full cwnd (~312 packets)
	}

	bbr.probeInflightHiUpward(rs)

	growth := bbr.inflightHi - initialInflightHi

	// With fix: after ACKing cwndPkts, we should have added at least 1 MSS
	// ackedPkts = 312, bwProbeUpCnt = 312, delta = 312/312 = 1
	// inflightHi += 1 * MSS = 1280 bytes
	require.GreaterOrEqual(t, growth, bbr.maxDatagramSize,
		"inflightHi should grow by at least 1 MSS (acked %d pkts, cnt was %d), got %d bytes",
		bbr.congestionWindow/bbr.maxDatagramSize, initialCnt, growth)
}

// TestBBRv3GuardrailProbeBWUpSeedsFromCurrentSample verifies Issue 9:
// ProbeBW_UP should seed the full-bandwidth detector from the current ACK's
// delivery-rate sample, not stale bwLatest from earlier cycles.
func TestBBRv3GuardrailProbeBWUpSeedsFromCurrentSample(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWRefill
	bbr.fullBandwidthReached = true
	bbr.bwLatest = 5_000_000
	bbr.fullBandwidth = 1_000_000

	rs := bbrRateSample{deliveryRate: 15_000_000}
	bbr.roundStart = true
	bbr.updateCyclePhase(rs, now)

	require.Equal(t, probeBWUp, bbr.probeBWPhase, "REFILL should transition to UP on round start")
	require.Equal(t, rs.deliveryRate, bbr.fullBandwidth,
		"ProbeBW_UP should seed fullBandwidth from the current delivery-rate sample")
}

// TestBBRv3GuardrailDeliveryRateMinRTTGuard verifies Issue 3:
// Delivery rate samples with interval < min_rtt should be rejected entirely.
// Per RFC §4.1.2.3, such samples must not influence ANY model state.
func TestBBRv3GuardrailDeliveryRateMinRTTGuard(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish a min_rtt baseline
	bbr.minRTT = 40 * time.Millisecond
	bbr.state = BBRStartup
	bbr.roundCount = 1 // Ensure we have "real" minRTT

	// Record initial state
	initialBwLatest := bbr.bwLatest
	initialMaxBw := bbr.maxBandwidth()

	// Send a packet
	bbr.OnPacketSent(now, 0, 1, 1200, true)

	// ACK arrives very quickly (interval < min_rtt) - unreliable sample
	fastAckTime := now.Add(5 * time.Millisecond) // Only 5ms, way less than 40ms min_rtt
	bbr.OnPacketAcked(1, 1200, 1200, fastAckTime)

	// Before OnAckEventEnd, verify the sample would have short interval
	interval := maxDuration(bbr.pendingSendElapsed, fastAckTime.Sub(bbr.pendingPriorTime))
	require.Less(t, interval, bbr.minRTT,
		"test setup: sample interval (%v) should be less than min_rtt (%v)", interval, bbr.minRTT)
	require.Greater(t, interval, time.Duration(0),
		"test setup: sample interval should be positive")

	// Process the ACK event
	bbr.OnAckEventEnd(fastAckTime)

	// CRITICAL: Invalid samples must NOT affect model state
	// Per RFC §4.1.2.3, the entire delivery_rate should be suppressed
	require.Equal(t, initialBwLatest, bbr.bwLatest,
		"bwLatest should not be updated from invalid sample (interval < min_rtt)")
	require.Equal(t, initialMaxBw, bbr.maxBandwidth(),
		"maxBandwidth should not be updated from invalid sample (interval < min_rtt)")
}

// TestBBRv3GuardrailDrainExitsAfter3Rounds verifies Issue 4:
// Drain must exit after 3 rounds even if inflight never drops below inflated BDP.
func TestBBRv3GuardrailDrainExitsAfter3Rounds(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up in Drain with an inflated bandwidth estimate
	bbr.state = BBRDrain
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 100_000_000 // 100 MB/s (way overestimated)
	bbr.minRTT = 40 * time.Millisecond
	// BDP = 100MB/s * 40ms = 4MB, but actual inflight is only 500KB
	actualInflight := protocol.ByteCount(500_000)
	inflatedBDP := bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0)
	require.Greater(t, inflatedBDP, actualInflight,
		"test setup: BDP should be inflated above actual inflight")

	// Track initial round
	initialRound := bbr.roundCount

	// Simulate 4 rounds passing - Drain should exit after 3
	for i := 0; i < 4; i++ {
		bbr.roundStart = true
		bbr.roundCount++
		rs := bbrRateSample{bytesInFlight: actualInflight}
		bbr.checkDrain(rs, now)

		if i >= 3 {
			// BUG: Current code stays in Drain forever because inflight < inflated_BDP
			// EXPECTED: Should exit to ProbeBW after 3 rounds
			require.Equal(t, BBRProbeBW, bbr.state,
				"Drain should exit to ProbeBW after 3 rounds (round %d)", bbr.roundCount-initialRound)
		}
	}
}

// TestBBRv3GuardrailProbeBWUpCwndGain verifies Issue 5:
// ProbeBW_UP must use cwnd_gain = 2.25, not 2.0.
func TestBBRv3GuardrailProbeBWUpCwndGain(t *testing.T) {
	bbr := newTestBBRv3()

	// Set up in ProbeBW_UP phase
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWUp
	bbr.fullBandwidthReached = true

	bbr.updateGains()

	// BUG: Current code sets cwndGain = 2.0 for all ProbeBW phases
	// EXPECTED: ProbeBW_UP should have cwndGain = 2.25 per RFC §5.6.1
	require.Equal(t, 2.25, bbr.cwndGain,
		"ProbeBW_UP cwndGain should be 2.25, got %v", bbr.cwndGain)
}

// TestBBRv3GuardrailExtraAckedWindowInStartup verifies Issue 8:
// Startup should use a 1-RTT extra_acked window, not 5-RTT.
func TestBBRv3GuardrailExtraAckedWindowInStartup(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	bbr.state = BBRStartup
	bbr.fullBandwidthReached = false
	bbr.extraAckedWinRTTs = 0
	bbr.extraAckedWinIdx = 0
	bbr.extraAcked = [2]protocol.ByteCount{10_000, 5_000}
	bbr.ackEpochStart = now.Add(-time.Millisecond)
	bbr.bwHi[0] = 10_000_000

	initialIdx := bbr.extraAckedWinIdx

	// Simulate 1 round in Startup - should rotate window (1-RTT window)
	bbr.roundStart = true
	bbr.updateAckAggregation(bbrRateSample{newlyAcked: 1000}, now)

	// With 1-RTT window in Startup: after 1 round, the window should have rotated
	// extraAckedWinRTTs went 0->1, triggered rotation (>=1), then reset to 0
	// extraAckedWinIdx should have flipped from 0 to 1
	require.NotEqual(t, initialIdx, bbr.extraAckedWinIdx,
		"window index should rotate after 1 RTT in Startup")
	// After rotation, the slot was cleared to 0, then updated with new sample
	// The important thing is that the OLD values (10_000, 5_000) were rotated out

	// Verify that in non-Startup state, it takes 5 RTTs to rotate
	// (per tcp_bbr.c bbr_extra_acked_win_rtts=5, changed from 10)
	bbr.state = BBRProbeBW
	bbr.fullBandwidthReached = true
	rotatedIdx := bbr.extraAckedWinIdx

	// Simulate 4 more rounds (should NOT rotate with 5-RTT window)
	for i := 0; i < 4; i++ {
		bbr.roundStart = true
		bbr.updateAckAggregation(bbrRateSample{newlyAcked: 1000}, now)
	}
	require.Equal(t, rotatedIdx, bbr.extraAckedWinIdx,
		"window should not rotate before 5 RTTs in ProbeBW")

	// One more round (5th) should trigger rotation
	bbr.roundStart = true
	bbr.updateAckAggregation(bbrRateSample{newlyAcked: 1000}, now)
	require.NotEqual(t, rotatedIdx, bbr.extraAckedWinIdx,
		"window should rotate after 5 RTTs in ProbeBW")
}

// TestBBRv3GuardrailZeroInflightFromAckEventStart verifies P1 fix:
// Zero bytesInFlight from OnAckEventStart is valid (all data was lost),
// and must not fall back to pre-loss reconstruction.
func TestBBRv3GuardrailZeroInflightFromAckEventStart(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up in ProbeBW_DOWN where checkTimeToCruise() will use bytesInFlight
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWDown
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 10_000_000 // 10 MB/s
	bbr.minRTT = 10 * time.Millisecond
	bbr.inflightHi = 100_000  // 100KB
	bbr.cycleStamp = now      // Recent probe start
	bbr.probeWait = time.Hour // Prevent checkTimeToProbeBW from triggering REFILL

	// BDP = 10MB/s * 10ms = 100KB
	bdp := bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0)

	// Send packet with HIGH priorInFlight that would be used in reconstruction
	// If bug: reconstructed = 120000 - 1200 = 118800 (above BDP, won't cruise)
	// If fix: captured = 0, then 0 - 1200 clamped to 0 (below BDP, will cruise)
	highPriorInflight := protocol.ByteCount(120_000)
	require.Greater(t, highPriorInflight, bdp,
		"test setup: reconstructed inflight (%d) should exceed BDP (%d)", highPriorInflight, bdp)

	bbr.OnPacketSent(now, highPriorInflight, 1, 1200, true)

	// Simulate OnAckEventStart with bytesInFlight=0 (all other data was lost)
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnAckEventStart(ackTime, 0) // Zero is valid capture, not "hook absent"

	// ACK the packet - this sets pendingPriorInFlight = highPriorInflight
	bbr.OnPacketAcked(1, 1200, highPriorInflight, ackTime)

	// Verify setup: reconstruction would give wrong value
	reconstructed := bbr.pendingPriorInFlight - bbr.pendingAckedBytes
	require.Greater(t, reconstructed, bdp,
		"test setup: reconstruction (%d) > BDP (%d), so cruise would NOT trigger with bug",
		reconstructed, bdp)

	// Process ACK event
	bbr.OnAckEventEnd(ackTime)

	// BEHAVIORAL ASSERTION: With correct zero-inflight, checkTimeToCruise()
	// should have triggered because 0 <= inflightWithHeadroom and 0 <= BDP.
	// With the bug (reconstruction), it would NOT have triggered because
	// 118800 > inflightWithHeadroom and 118800 > BDP.
	require.Equal(t, probeBWCruise, bbr.probeBWPhase,
		"should transition to CRUISE when inflight=0 (fix applied); "+
			"if still in DOWN, the bug caused reconstruction to ~%d instead of 0", reconstructed)
}

func TestBBRv3SustainedLossStability(t *testing.T) {
	// This test requires a closed-loop path model where ACKs are fed at a rate
	// driven by the controller's own cwnd/pacing decisions. The existing test
	// harness uses event-path testing (inject specific events, check state).
	//
	// Test parameters (when implemented):
	// - Offered rate: 1 Gbps (125 MB/s)
	// - RTT: 50ms
	// - BDP: 6.25 MB (125 MB/s × 0.05s)
	// - Rounds: 200
	// - Loss rate: 3% of tx_in_flight per sample
	//
	// Assertions:
	// - maxBandwidth() >= 62.5 MB/s (0.5x offered)
	// - cwnd >= 3.125 MB (0.5x BDP)
	// - bwLo >= 10 MB/s (does not collapse to near-zero)
	//
	// Current behavior: unknown pending closed-loop harness implementation.
	// This test documents the requirement and will be enabled when the harness exists.
	t.Skip("Requires closed-loop path model harness (not yet implemented)")
}
