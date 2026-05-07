package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

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

// =============================================================================
// H1a: PN-SPACE COLLISION DETECTION TESTS
// =============================================================================

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

// =============================================================================
// M1a: ECN GUARD AT ZERO minRTT TESTS
// =============================================================================

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

// =============================================================================
// H2: PER-EVENT RTT FOR updateMinRTT TESTS
// =============================================================================

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

// =============================================================================
// M2: EXTRA_ACKED ROTATION WINDOW TESTS
// =============================================================================

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

// =============================================================================
// M3: EXTRA_ACKED INSIDE QUANTIZATION BUDGET TESTS
// =============================================================================

// TestBBRv3ExtraAckedInsideQuantization verifies that maxInflight() adds
// extra_acked BEFORE applying quantizationBudget(), not after. Per RFC
// draft-ietf-ccwg-bbr-05 §5.6.4.2, the order is:
//
//	inflight_cap = BBRBDPMultiple(BBR.cwnd_gain)  // BDP * gain
//	inflight_cap += BBR.extra_acked               // add extra_acked
//	BBR.max_inflight = BBRQuantizationBudget(inflight_cap)  // THEN quantize
//
// The bug was adding extra_acked AFTER quantization, which means the
// quantization floor doesn't account for the aggregation headroom.
func TestBBRv3ExtraAckedInsideQuantization(t *testing.T) {
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

// =============================================================================
// M5: ACK_EPOCH_ACKED THRESHOLD SCALING TESTS
// =============================================================================

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

// =============================================================================
// L7: saveCwnd DIVERGENCE PIN TEST
// =============================================================================

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
