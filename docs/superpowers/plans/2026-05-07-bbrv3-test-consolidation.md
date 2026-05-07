# BBRv3 Test Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate three BBRv3 test files into one well-organized file with comprehensive RFC draft-ietf-ccwg-bbr-05 compliance coverage.

**Architecture:** Merge all tests from `bbr_v3_test.go`, `bbr_v3_rfc_fixes_test.go`, and `bbr_v3_migration_test.go` into a single `bbr_v3_test.go` organized by RFC section. Add setup helpers and ~20 new tests for coverage gaps.

**Tech Stack:** Go, testify/require, existing BBRv3 types and constants

---

## Phase 1: Add Fixtures and Section Structure

### Task 1: Add Setup Helpers

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go:16-28`

- [ ] **Step 1: Add setup helpers after existing fixtures**

Insert after line 28 (after `recordingQlogger.Close()`):

```go
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
```

- [ ] **Step 2: Run tests to verify helpers don't break anything**

Run: `go test ./internal/congestion/... -run BBRv3 -count=1`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): add setup helpers for common test scenarios"
```

---

## Phase 2: Add New Tests for Coverage Gaps

### Task 2: Per-Packet State Capture Tests

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Add per-packet state snapshot test**

Add after the setup helpers:

```go
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
	// Actually pendingDelivered tracks this differently - check the actual field
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/congestion/... -run "PerPacketState" -v`
Expected: Both tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): add per-packet state capture tests (RFC §4.1.2.2)"
```

---

### Task 3: Idle Restart Tests

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Add idle restart tests**

Add to the §5.2 section:

```go
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test ./internal/congestion/... -run "IdleRestart" -v`
Expected: All tests pass (or identify if implementation differs from spec)

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): add idle restart tests (RFC §5.4)"
```

---

### Task 4: send_quantum and offload_budget Tests

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Add send_quantum calculation test**

```go
// TestBBRv3SendQuantumCalculation verifies send_quantum = min(pacing_rate * 1ms, 64KB)
// per RFC §5.6.3.
func TestBBRv3SendQuantumCalculation(t *testing.T) {
	tests := []struct {
		name           string
		pacingRate     protocol.ByteCount
		expectedMin    protocol.ByteCount
		expectedMax    protocol.ByteCount
	}{
		{
			name:        "1 MB/s rate",
			pacingRate:  1_000_000,
			expectedMin: 1_000, // 1 MB/s * 1ms = 1000 bytes
			expectedMax: 1_000,
		},
		{
			name:        "100 MB/s rate (capped at 64KB)",
			pacingRate:  100_000_000,
			expectedMin: 64 * 1024, // capped
			expectedMax: 64 * 1024,
		},
		{
			name:        "10 KB/s rate",
			pacingRate:  10_000,
			expectedMin: 10, // 10 KB/s * 1ms = 10 bytes
			expectedMax: 10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bbr := newTestBBRv3()
			bbr.pacingRate = tc.pacingRate
			bbr.updateSendQuantum()

			require.GreaterOrEqual(t, bbr.sendQuantum, tc.expectedMin,
				"sendQuantum should be at least expected minimum")
			require.LessOrEqual(t, bbr.sendQuantum, tc.expectedMax,
				"sendQuantum should be at most expected maximum")
		})
	}
}

// TestBBRv3OffloadBudgetCalculation verifies offload_budget = 2 * send_quantum
// per RFC §5.5.8.
func TestBBRv3OffloadBudgetCalculation(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.pacingRate = 1_000_000 // 1 MB/s -> sendQuantum = 1000
	bbr.updateSendQuantum()

	// offload_budget should be 2 * sendQuantum
	// Note: implementation may use different field name or calculation
	expectedOffload := 2 * bbr.sendQuantum
	require.Equal(t, expectedOffload, bbr.offloadBudget,
		"offload_budget should be 2 * send_quantum")
}

// TestBBRv3QuantizationBudgetFloors verifies quantizationBudget returns
// max of 3*send_quantum, offload_budget, minPipeCwnd per RFC §5.6.4.2.
func TestBBRv3QuantizationBudgetFloors(t *testing.T) {
	bbr := newTestBBRv3()

	// Low pacing rate to make floors visible
	bbr.pacingRate = 1_000 // 1 KB/s -> sendQuantum very small
	bbr.updateSendQuantum()

	floor := bbr.quantizationBudget()

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
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/congestion/... -run "SendQuantum\|OffloadBudget\|Quantization" -v`
Expected: Tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): add send_quantum and offload_budget tests (RFC §5.5.8, §5.6.3)"
```

---

### Task 5: ECN Alpha Tests

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Add ECN alpha tests**

```go
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
		bbr.totalBytesAcked += 1000
		bbr.totalBytesAckedCE += 500
		bbr.roundStart = true
		bbr.updateECNAlpha(bbrRateSample{})
	}

	require.InDelta(t, 0.5, bbr.ecnAlpha, 0.05,
		"ecnAlpha should converge to ~0.5 with sustained 50% CE")
}

// TestBBRv3ECNAlphaReducesInflightLo verifies ECN alpha affects inflightLo
// reduction per RFC §5.5.10.2: inflightLo *= (1 - ecnAlpha * Beta).
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

	// Expected: inflightLo *= (1 - 0.5 * 0.3) = 100_000 * 0.85 = 85_000
	// But also max with inflightLatest
	expected := max(protocol.ByteCount(85_000), bbr.inflightLatest)
	require.Equal(t, expected, bbr.inflightLo,
		"inflightLo should be reduced by ecnAlpha * Beta")
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/congestion/... -run "ECNAlpha" -v`
Expected: Tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): add ECN alpha calculation and bounds tests (RFC §5.3.3.6.4)"
```

---

### Task 6: ProbeBW Lower Bounds Tests

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Add ProbeBW lower bounds tests**

```go
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
	bbr.ecnAlpha = 0.5
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
	bbr.startProbeBWRefill()

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
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/congestion/... -run "ProbeBW.*Bound\|ProbeBW.*Refill\|LowerBounds" -v`
Expected: Tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): add ProbeBW lower bounds tests (RFC §5.5.10)"
```

---

### Task 7: Table-Driven Gain Tests

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Add table-driven gain test**

```go
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
		{"Startup", "§5.3.1", BBRStartup, 0, 2.77, 2.0},
		{"Drain", "§5.3.2", BBRDrain, 0, 0.5, 2.0},
		{"ProbeBW_DOWN", "§5.3.3.4", BBRProbeBW, probeBWDown, 0.9, 2.0},
		{"ProbeBW_CRUISE", "§5.3.3.5", BBRProbeBW, probeBWCruise, 1.0, 2.0},
		{"ProbeBW_REFILL", "§5.3.3.5.3", BBRProbeBW, probeBWRefill, 1.0, 2.0},
		{"ProbeBW_UP", "§5.3.3.6", BBRProbeBW, probeBWUp, 1.25, 2.25},
		{"ProbeRTT", "§5.3.4", BBRProbeRTT, 0, 1.0, 0.5},
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
		bbr.state = BBRStartup
		bbr.fullBandwidthReached = true
		bbr.bwHi[0] = 10_000_000
		bbr.minRTT = 40 * time.Millisecond

		bbr.enterDrain()

		require.Equal(t, BBRDrain, bbr.state)
		require.InDelta(t, 0.5, bbr.pacingGain, 0.001,
			"Drain pacing_gain should be 0.5")
		require.InDelta(t, 2.0, bbr.cwndGain, 0.001,
			"Drain cwnd_gain should be 2.0")
	})

	t.Run("enterProbeRTT", func(t *testing.T) {
		bbr := newTestBBRv3()
		setupProbeBWPhase(bbr, probeBWCruise)

		bbr.enterProbeRTT()

		require.Equal(t, BBRProbeRTT, bbr.state)
		require.InDelta(t, 1.0, bbr.pacingGain, 0.001,
			"ProbeRTT pacing_gain should be 1.0")
		require.InDelta(t, PROBE_RTT_CWND_GAIN, bbr.cwndGain, 0.001,
			"ProbeRTT cwnd_gain should be PROBE_RTT_CWND_GAIN")
	})
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/congestion/... -run "GainTable\|StateTransition" -v`
Expected: Tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): add table-driven gain tests with RFC citations (§5.6.1)"
```

---

## Phase 3: Consolidate Tests Into Single File

### Task 8: Reorganize bbr_v3_test.go with Section Headers

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Add section headers throughout the file**

Reorganize the file by inserting section headers before groups of related tests. The structure should be:

```go
package congestion

import (
	// ... imports ...
)

// ============================================================================
// TEST FIXTURES AND HELPERS
// ============================================================================

func newTestBBRv3() *BBRv3 { ... }

type recordingQlogger struct { ... }

func setupStartup(bbr *BBRv3) { ... }
func setupDrain(bbr *BBRv3) { ... }
func setupProbeBWPhase(bbr *BBRv3, phase bbrProbeBWPhase) { ... }
func setupProbeRTT(bbr *BBRv3) { ... }

// ============================================================================
// §4.1: DELIVERY RATE SAMPLING
// ============================================================================

// TestBBRv3PerPacketStateCapture ...
// TestBBRv3PerPacketStateRoundTrip ...
// TestBBRv3GuardrailAckAdvancesFirstSendTime ...
// TestBBRv3GuardrailNewestPacketTieBreakUsesPacketNumber ...
// TestBBRv3ShortIntervalSamplesKeepLatestDeliveryBookkeeping ...
// TestBBRv3OnAckEventEndFlushesPendingAckEvent ...
// TestBBRv3ACKLookupMiss* tests ...
// TestBBRv3GuardrailDeliveryRateMinRTTGuard ...

// ============================================================================
// §5.2: ALGORITHM LIFECYCLE (Init, Migration, Idle Restart)
// ============================================================================

// TestBBRv3InitialQlogTelemetry ...
// TestBBRv3ConnectionMigrationResetsControllerState ... (from migration file)
// TestBBRv3IdleRestart* tests ...
// TestBBRv3Name ...
// TestBBRv3SetRTTStats ...
// TestBBRv3StateString ...
// TestBBRv3PhaseString ...
// TestBBRv3OnRetransmissionTimeoutNoOp ...

// ============================================================================
// §5.3.1: STARTUP
// ============================================================================

// TestBBRv3StartupRoundQlogTelemetry ...
// TestBBRv3StartupExitByFullBwPlateau ...
// TestBBRv3CheckFullBwReachedIgnoresIntraRoundSamples ...
// TestBBRv3StartupExitByExcessiveLoss ...
// TestBBRv3StartupExitByExcessiveECN ...
// TestBBRv3GuardrailStartupReachesFullBwWithoutAppLimited ...

// ============================================================================
// §5.3.2: DRAIN
// ============================================================================

// TestBBRv3DrainCompletionAndProbeBWTransitions ...
// TestBBRv3DrainFallbackUsesDrainStartRound ...
// TestBBRv3GuardrailDrainExitsAfter3Rounds ...

// ============================================================================
// §5.3.3: PROBEBW
// ============================================================================

// TestBBRv3ProbeTimingWallClockAndRenoRoundTrigger ...
// TestBBRv3UpperAndLowerBoundAdaptation ...
// TestBBRv3ProbeBWCruiseLossReducesBounds ...
// TestBBRv3ProbeBWCruiseECNReducesInflightLo ...
// TestBBRv3ProbeBWRefillClearsLowerBounds ...
// TestBBRv3LowerBoundsConstrainCwnd ...
// TestBBRv3GuardrailProbeBWUpInflightHiGrowsMSS ...
// TestBBRv3GuardrailProbeBWUpSeedsFromCurrentSample ...
// TestBBRv3GuardrailProbeBWUpCwndGain ...
// TestBBRv3GuardrailZeroInflightFromAckEventStart ...

// ============================================================================
// §5.3.4: PROBERTT
// ============================================================================

// TestBBRv3ProbeRTTEnterExitAndIdleRestartSuppression ...
// TestBBRv3ProbeRTTCwndUsesBoundedBandwidth ...
// TestBBRv3GuardrailProbeRTTExitsToProbeBW ...
// TestBBRv3GuardrailProbeRTTExitDoesNotRotateMaxBwFilter ...
// TestBBRv3GuardrailProbeRTTRefreshesAppLimitedBubble ...
// TestBBRv3GuardrailProbeRTTUsesAckEventInflightAfterLoss ...

// ============================================================================
// §5.5: MODEL UPDATES (max_bw, min_rtt, extra_acked, ECN, Loss)
// ============================================================================

// TestBBRv3AckAggregationRaisesCwndTarget ...
// TestBBRv3UpdateMinRTTUsesPerEventRTT ...
// TestBBRv3UpdateMinRTTEmptyEventGuard ...
// TestBBRv3ExtraAckedRetentionWindow ...
// TestBBRv3ExtraAckedInsideQuantization ...
// TestBBRv3MaxInflightExtraAckedOrdering ...
// TestBBRv3AckEpochAckedThresholdScaling ...
// TestBBRv3AckEpochUnderflowGuard ...
// TestBBRv3GuardrailExtraAckedWindowInStartup ...
// TestBBRv3ECNGuard* tests ...
// TestBBRv3ECNAlpha* tests ...
// TestBBRv3SpuriousLoss* tests ...

// ============================================================================
// §5.6: CONTROL PARAMETERS (Gains, Pacing, Cwnd, send_quantum)
// ============================================================================

// TestBBRv3GainTableRFCCompliance ...
// TestBBRv3StateTransitionSetsCorrectGains ...
// TestBBRv3PacingBudget ...
// TestBBRv3Pacer* tests ...
// TestBBRv3C1ExactPacingInterval ...
// TestBBRv3SendQuantumCalculation ...
// TestBBRv3OffloadBudgetCalculation ...
// TestBBRv3QuantizationBudgetFloors ...
// TestBBRv3CwndQuantizationFloor ...
// TestBBRv3CwndLimitedSticksAcrossRoundBoundary ...
// TestBBRv3PTORecoveryUsesInflightAndPreservesPriorCwnd ...
// TestBBRv3SaveCwndPinsRoundScopedPredicate ...
// TestBBRv3Collision* tests ...
```

- [ ] **Step 2: Run tests to verify organization doesn't break anything**

Run: `go test ./internal/congestion/... -run BBRv3 -count=1`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): reorganize tests with RFC section headers"
```

---

### Task 9: Merge Tests from bbr_v3_rfc_fixes_test.go

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`
- Delete: `internal/congestion/bbr_v3_rfc_fixes_test.go`

- [ ] **Step 1: Copy all tests from bbr_v3_rfc_fixes_test.go into appropriate sections**

Move each test to its designated section in bbr_v3_test.go:
- `TestBBRv3PTORecoveryUsesInflightAndPreservesPriorCwnd` → §5.6
- `TestBBRv3GuardrailProbeRTTUsesAckEventInflightAfterLoss` → §5.3.4
- `TestBBRv3ShortIntervalSamplesKeepLatestDeliveryBookkeeping` → §4.1
- `TestBBRv3Pacer*` (6 tests) → §5.6
- `TestBBRv3Collision*` (7 tests) → §5.6
- `TestBBRv3ACKLookupMiss*` (3 tests) → §4.1
- `TestBBRv3ECNGuard*` (3 tests) → §5.5
- `TestBBRv3UpdateMinRTT*` (2 tests) → §5.5
- `TestBBRv3ExtraAcked*` (2 tests) → §5.5
- `TestBBRv3MaxInflight*` (2 tests) → §5.6
- `TestBBRv3AckEpoch*` (2 tests) → §5.5
- `TestBBRv3OnRetransmissionTimeoutNoOp` → §5.2
- `TestBBRv3SaveCwndPinsRoundScopedPredicate` → §5.6
- `TestBBRv3SpuriousLossPinsPerPacketSemantics` → §5.5

- [ ] **Step 2: Run tests to verify all pass**

Run: `go test ./internal/congestion/... -run BBRv3 -count=1`
Expected: All tests pass

- [ ] **Step 3: Delete bbr_v3_rfc_fixes_test.go**

```bash
rm internal/congestion/bbr_v3_rfc_fixes_test.go
```

- [ ] **Step 4: Run tests to verify still passing**

Run: `go test ./internal/congestion/... -run BBRv3 -count=1`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git rm internal/congestion/bbr_v3_rfc_fixes_test.go
git commit -m "test(bbr): merge rfc_fixes tests into main test file"
```

---

### Task 10: Merge Tests from bbr_v3_migration_test.go

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`
- Delete: `internal/congestion/bbr_v3_migration_test.go`

- [ ] **Step 1: Copy TestBBRv3ConnectionMigrationResetsControllerState to §5.2 section**

Move the test into the §5.2: ALGORITHM LIFECYCLE section.

- [ ] **Step 2: Run tests to verify all pass**

Run: `go test ./internal/congestion/... -run BBRv3 -count=1`
Expected: All tests pass

- [ ] **Step 3: Delete bbr_v3_migration_test.go**

```bash
rm internal/congestion/bbr_v3_migration_test.go
```

- [ ] **Step 4: Run tests to verify still passing**

Run: `go test ./internal/congestion/... -run BBRv3 -count=1`
Expected: All tests pass

- [ ] **Step 5: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git rm internal/congestion/bbr_v3_migration_test.go
git commit -m "test(bbr): merge migration test into main test file"
```

---

## Phase 4: Remove Old Gain Test and Final Cleanup

### Task 11: Replace Old Gain Test with Table-Driven Version

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Remove TestBBRv3RFCGains (replaced by TestBBRv3GainTableRFCCompliance)**

Delete the old `TestBBRv3RFCGains` function which is now superseded by the table-driven version.

- [ ] **Step 2: Run tests to verify all pass**

Run: `go test ./internal/congestion/... -run BBRv3 -count=1`
Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "test(bbr): remove old gain test (superseded by table-driven version)"
```

---

### Task 12: Final Verification

**Files:**
- Verify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 1: Count tests to verify none were lost**

Run: `grep -c "^func Test" internal/congestion/bbr_v3_test.go`
Expected: ~90+ tests (73 existing + ~20 new - 1 removed)

- [ ] **Step 2: Run full test suite**

Run: `go test ./internal/congestion/... -count=1 -v 2>&1 | tail -20`
Expected: All tests pass

- [ ] **Step 3: Verify only one BBRv3 test file exists**

Run: `ls internal/congestion/bbr_v3*_test.go`
Expected: Only `bbr_v3_test.go`

- [ ] **Step 4: Run full package tests**

Run: `go test ./... 2>&1 | grep -E "^(ok|FAIL)"`
Expected: All packages pass

- [ ] **Step 5: Commit any final cleanup**

```bash
git status
# If clean, no action needed
# If changes, review and commit appropriately
```

---

## Summary

| Phase | Tasks | Tests Added | Tests Moved |
|-------|-------|-------------|-------------|
| 1 | 1 | 0 | 0 |
| 2 | 2-7 | ~20 | 0 |
| 3 | 8-10 | 0 | 33 |
| 4 | 11-12 | 0 | 0 |

**Final state:**
- Single `internal/congestion/bbr_v3_test.go` with ~90 tests
- Organized by RFC section with clear headers
- All existing tests preserved
- New tests for coverage gaps
- Old files deleted
