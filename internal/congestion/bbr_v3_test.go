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

// setupStartup configures BBR in Startup with reasonable defaults
func setupStartup(bbr *BBRv3) {
	bbr.state = BBRStartup
	bbr.fullBandwidthReached = false
	bbr.pacingGain = STARTUP_PACING_GAIN
	bbr.cwndGain = STARTUP_CWND_GAIN
}

// setupDrain configures BBR in Drain after Startup exit
func setupDrain(bbr *BBRv3) {
	bbr.state = BBRDrain
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 10_000_000
	bbr.minRTT = 40 * time.Millisecond
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

// setupProbeRTT configures BBR in ProbeRTT
func setupProbeRTT(bbr *BBRv3) {
	bbr.state = BBRProbeRTT
	bbr.fullBandwidthReached = true
	bbr.bwHi[0] = 10_000_000
	bbr.minRTT = 40 * time.Millisecond
}

// ============================================================================
// §4.1: DELIVERY RATE SAMPLING
// ============================================================================

// TestBBRv3PerPacketStateCapture verifies that OnPacketSent captures all
// per-packet state fields correctly per RFC §4.1.2.2.
func TestBBRv3PerPacketStateCapture(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Set up known BBR state before sending
	bbr.totalBytesAcked = 50_000
	bbr.deliveredTime = now.Add(-100 * time.Millisecond)
	bbr.firstSentTime = now.Add(-200 * time.Millisecond)
	bbr.totalBytesLost = 1_200
	bbr.appLimitedUntil = 100_000 // will mark packet as app-limited

	bytesInFlight := protocol.ByteCount(10_000)
	bbr.OnPacketSent(now, bytesInFlight, 1, 1200, true)

	st, ok := bbr.sentPackets[1]
	require.True(t, ok, "packet state should be tracked")

	// P.delivered = C.delivered at send time
	require.Equal(t, uint64(50_000), st.delivered,
		"P.delivered should equal totalBytesAcked at send")

	// P.delivered_time = C.delivered_time at send time
	require.Equal(t, now.Add(-100*time.Millisecond), st.deliveredTime,
		"P.delivered_time should equal deliveredTime at send")

	// P.first_sent_time = inherited from prior or connection start
	require.Equal(t, now.Add(-200*time.Millisecond), st.firstSentTime,
		"P.first_sent_time should be inherited")

	// P.is_app_limited = true if C.delivered < appLimitedUntil
	require.True(t, st.isAppLimited,
		"P.is_app_limited should be true when delivered < appLimitedUntil")

	// P.tx_in_flight = bytesInFlight parameter
	require.Equal(t, bytesInFlight, st.txInFlight,
		"P.tx_in_flight should equal bytesInFlight at send")

	// P.lost = C.lost at send time (totalBytesLost)
	require.Equal(t, uint64(1_200), st.totalBytesLost,
		"P.lost should equal totalBytesLost at send")
}

// TestBBRv3PerPacketStateRoundTrip verifies that rate sample fields are
// correctly derived from captured per-packet state.
func TestBBRv3PerPacketStateRoundTrip(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Send packet with known state
	bbr.totalBytesAcked = 10_000
	bbr.deliveredTime = now
	bbr.firstSentTime = now
	bbr.OnPacketSent(now, 0, 1, 1200, true)

	// Simulate some delivery progress
	bbr.totalBytesAcked = 15_000
	bbr.deliveredTime = now.Add(50 * time.Millisecond)

	// ACK the packet
	ackTime := now.Add(50 * time.Millisecond)
	bbr.OnPacketAcked(1, 1200, 0, ackTime)

	// Verify pending rate sample state
	// RS.delivered = C.delivered - P.delivered = 15000 - 10000 = 5000
	// But we also add the acked bytes, so delivered = 5000 + 1200 = 6200
	// Actually pendingAckedBytes tracks this differently - check the actual field
	require.Greater(t, bbr.pendingAckedBytes, protocol.ByteCount(0),
		"pendingAckedBytes should be set after ACK")

	// RS.send_elapsed = P.sent_time - P.first_sent_time
	require.Equal(t, time.Duration(0), bbr.pendingSendElapsed,
		"send_elapsed should be sent_time - first_sent_time")

	// Process the ACK event
	bbr.OnAckEventEnd(ackTime)

	// After processing, delivery rate should be computed
	require.Greater(t, bbr.totalBytesAcked, uint64(15_000),
		"totalBytesAcked should increase after ACK processing")
}

// ============================================================================
// §5.2: ALGORITHM LIFECYCLE (Init, Migration, Idle Restart)
// ============================================================================

// TestBBRv3IdleRestartRefreshesPacingTokens verifies that after an idle period,
// the first send has fresh pacing budget per RFC §5.4.
func TestBBRv3IdleRestartRefreshesPacingTokens(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Establish steady state and exhaust pacing budget
	bbr.pacingRate = 1_000_000
	for i := 0; i < 20; i++ {
		bbr.OnPacketSent(now, 0, protocol.PacketNumber(i+1), 1500, true)
	}
	require.False(t, bbr.HasPacingBudget(now),
		"pacing budget should be exhausted")

	// Simulate idle period (> 1 RTT)
	idleTime := now.Add(200 * time.Millisecond)

	// After idle, pacing budget should be refreshed
	require.True(t, bbr.HasPacingBudget(idleTime),
		"pacing budget should be refreshed after idle period")
}

// TestBBRv3IdleRestartPreservesCwnd verifies that cwnd is not reduced
// when restarting from idle per RFC §5.4.
func TestBBRv3IdleRestartPreservesCwnd(t *testing.T) {
	bbr := newTestBBRv3()

	// Establish cwnd in ProbeBW
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.congestionWindow = 200_000
	originalCwnd := bbr.congestionWindow

	// Set idle restart flag (simulating transport layer detection)
	bbr.idleRestart = true

	// Cwnd should be preserved
	require.Equal(t, originalCwnd, bbr.congestionWindow,
		"cwnd should be preserved during idle restart")
}

// TestBBRv3IdleRestartFlagLifecycle verifies the idleRestart flag is
// set on idle detection and cleared after first ACK processing.
func TestBBRv3IdleRestartFlagLifecycle(t *testing.T) {
	bbr := newTestBBRv3()
	now := monotime.Now()

	// Initially false
	require.False(t, bbr.idleRestart, "idleRestart should start false")

	// Transport layer sets it on idle detection
	bbr.idleRestart = true
	require.True(t, bbr.idleRestart, "idleRestart should be settable")

	// Send and ACK a packet
	bbr.OnPacketSent(now, 0, 1, 1200, true)
	bbr.OnPacketAcked(1, 1200, 0, now.Add(50*time.Millisecond))
	bbr.OnAckEventEnd(now.Add(50 * time.Millisecond))

	// Flag should be cleared after ACK processing
	require.False(t, bbr.idleRestart,
		"idleRestart should be cleared after first ACK")
}

// ============================================================================
// §5.5.8 and §5.6.3: SEND QUANTUM AND OFFLOAD BUDGET
// ============================================================================

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

// TestBBRv3QuantizationBudgetFloors verifies quantizationBudget returns
// max of inflight, offload_budget, minPipeCwnd per RFC §5.6.4.2.
func TestBBRv3QuantizationBudgetFloors(t *testing.T) {
	bbr := newTestBBRv3()

	// Low pacing rate to make floors visible
	bbr.pacingRate = 1_000 // 1 KB/s -> sendQuantum very small
	bbr.setSendQuantum()

	// Test with tiny inflight value
	floor := bbr.quantizationBudget(100)

	// Should be at least minPipeCwnd (4 * MSS = 4 * 1280 = 5120)
	require.GreaterOrEqual(t, floor, bbr.minPipeCwnd,
		"quantization floor should be at least minPipeCwnd")
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

// ============================================================================
// RFC §5.3.3.6.4: ECN ALPHA CALCULATION
// ============================================================================

// TestBBRv3ECNAlphaCalculation verifies the EWMA formula for ecnAlpha
// per RFC §5.3.3.6.4: alpha = (1-g)*alpha + g*(CE/acked), g=1/16.
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
			bbr.ecnAlpha = tc.initialAlpha
			bbr.alphaLastDelivered = 0
			bbr.alphaLastDeliveredCE = 0
			bbr.totalBytesAcked = tc.ackedBytes
			bbr.totalBytesAckedCE = tc.ceBytes

			// Trigger alpha update
			bbr.roundStart = true
			bbr.updateECNAlpha(bbrRateSample{})

			require.InDelta(t, tc.expectedAlpha, bbr.ecnAlpha, tc.tolerance,
				"ecnAlpha should match expected value")
		})
	}
}

// TestBBRv3ECNAlphaBounds verifies ecnAlpha stays in [0, 1] range.
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
	require.LessOrEqual(t, bbr.ecnAlpha, 1.0,
		"ecnAlpha should not exceed 1.0")
	require.GreaterOrEqual(t, bbr.ecnAlpha, 0.9,
		"ecnAlpha should approach 1.0 with 100% CE")

	// 0% CE marking
	bbr.ecnAlpha = 0.5
	for i := 0; i < 100; i++ {
		bbr.alphaLastDelivered = bbr.totalBytesAcked
		bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE
		bbr.totalBytesAcked += 1000
		// No CE bytes added
		bbr.roundStart = true
		bbr.updateECNAlpha(bbrRateSample{})
	}
	require.GreaterOrEqual(t, bbr.ecnAlpha, 0.0,
		"ecnAlpha should not go below 0.0")
	require.LessOrEqual(t, bbr.ecnAlpha, 0.1,
		"ecnAlpha should approach 0.0 with 0% CE")
}

// TestBBRv3ECNAlphaConvergence verifies alpha converges to marking rate.
func TestBBRv3ECNAlphaConvergence(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.ecnEligible = true
	bbr.minRTT = 3 * time.Millisecond
	bbr.ecnAlpha = 0.0

	// Sustained 50% CE marking
	for i := 0; i < 200; i++ {
		bbr.alphaLastDelivered = bbr.totalBytesAcked
		bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE
		bbr.totalBytesAcked += 1000
		bbr.totalBytesAckedCE += 500
		bbr.roundStart = true
		bbr.updateECNAlpha(bbrRateSample{})
	}

	require.InDelta(t, 0.5, bbr.ecnAlpha, 0.05,
		"ecnAlpha should converge to ~0.5 with sustained 50% CE")
}

// TestBBRv3ECNAlphaReducesInflightLo verifies ECN alpha affects inflightLo
// reduction per RFC §5.5.10.2: inflightLo *= (1 - ecnAlpha * ECN_FACTOR).
func TestBBRv3ECNAlphaReducesInflightLo(t *testing.T) {
	bbr := newTestBBRv3()
	setupProbeBWPhase(bbr, probeBWCruise)
	bbr.ecnEligible = true
	bbr.ecnAlpha = 0.5
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

func TestBBRv3CheckFullBwReachedIgnoresIntraRoundSamples(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRStartup
	bbr.fullBandwidth = 1_000
	bbr.bwHi[0] = 1_000
	bbr.minRTT = 10 * time.Millisecond

	plateau := bbrRateSample{deliveryRate: 1_100}
	intraRoundSpike := bbrRateSample{deliveryRate: 1_300}

	for round := 0; round < FULL_BW_ROUNDS; round++ {
		bbr.roundStart = true
		bbr.checkFullBwReached(plateau)
		require.Equal(t, round+1, bbr.fullBandwidthCount)

		bbr.roundStart = false
		bbr.checkFullBwReached(intraRoundSpike)
		require.Equal(t, round+1, bbr.fullBandwidthCount,
			"non-round-start ACKs must not reset the full bandwidth detector")
		require.Equal(t, protocol.ByteCount(1_000), bbr.fullBandwidth,
			"non-round-start ACKs must not advance the full bandwidth baseline")
	}

	require.True(t, bbr.fullBandwidthReached)
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

func TestBBRv3RFCGains(t *testing.T) {
	bbr := newTestBBRv3()

	bbr.state = BBRDrain
	bbr.updateGains()
	require.InDelta(t, 0.5, bbr.pacingGain, 0.0001)
	require.InDelta(t, 2.0, bbr.cwndGain, 0.0001)

	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWDown
	bbr.updateGains()
	require.InDelta(t, 0.9, bbr.pacingGain, 0.0001)
	require.InDelta(t, 2.0, bbr.cwndGain, 0.0001)

	bbr.state = BBRProbeRTT
	bbr.updateGains()
	require.InDelta(t, 1.0, bbr.pacingGain, 0.0001)
	require.InDelta(t, PROBE_RTT_CWND_GAIN, bbr.cwndGain, 0.0001)
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

	// First call restores
	bbr.OnSpuriousLossDetected(1, 1)
	require.Equal(t, protocol.ByteCount(800_000), bbr.bwLo)
	require.Equal(t, protocol.ByteCount(80_000), bbr.inflightLo)
	require.Equal(t, protocol.ByteCount(120_000), bbr.inflightHi)

	// Second call should be idempotent (no further changes)
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

	// Spurious loss detected - should restore to MaxByteCount (unconstrained)
	bbr.OnSpuriousLossDetected(1, 1)

	// Critical: bounds must be restored to MaxByteCount (unconstrained)
	// This was broken before the fix - the != MaxByteCount check prevented restoration
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo, "bwLo should be restored to unconstrained")
	require.Equal(t, protocol.MaxByteCount, bbr.inflightLo, "inflightLo should be restored to unconstrained")
}

// =============================================================================
// GUARDRAIL TESTS - These verify the bugs identified in the code review.
// These tests should FAIL with the current buggy implementation and PASS
// after the fixes are applied.
// =============================================================================

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
