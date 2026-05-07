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
