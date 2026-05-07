# BBRv3 Test Consolidation and RFC Compliance Design

> **For agentic workers:** Use `superpowers:writing-plans` to create the implementation plan from this spec.

**Goal:** Consolidate three BBRv3 test files into one well-organized file with comprehensive RFC draft-ietf-ccwg-bbr-05 compliance coverage.

**Scope:** `internal/congestion/bbr_v3_test.go` (consolidated), deleting `bbr_v3_rfc_fixes_test.go` and `bbr_v3_migration_test.go`.

---

## 1. File Structure

Single file organized by RFC section with clear delimiters:

```go
package congestion

// ============================================================================
// TEST FIXTURES AND HELPERS
// ============================================================================

// ============================================================================
// §4.1: DELIVERY RATE SAMPLING
// ============================================================================

// ============================================================================
// §5.2: ALGORITHM LIFECYCLE (Init, Migration, Idle Restart)
// ============================================================================

// ============================================================================
// §5.3.1: STARTUP
// ============================================================================

// ============================================================================
// §5.3.2: DRAIN
// ============================================================================

// ============================================================================
// §5.3.3: PROBEBW
// ============================================================================

// ============================================================================
// §5.3.4: PROBERTT
// ============================================================================

// ============================================================================
// §5.5: MODEL UPDATES (max_bw, min_rtt, extra_acked, ECN, Loss)
// ============================================================================

// ============================================================================
// §5.6: CONTROL PARAMETERS (Gains, Pacing, Cwnd, send_quantum)
// ============================================================================
```

---

## 2. Test Fixtures

### 2.1 Base Fixture (existing)

```go
func newTestBBRv3() *BBRv3 {
    return NewBBRV3(DefaultClock{}, utils.NewRTTStats(), nil, initialMaxDatagramSize, false, nil)
}
```

### 2.2 Setup Helpers (new)

Helpers set up state but don't assert. Each takes `*BBRv3` and optional `monotime.Time`.

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

### 2.3 Qlog Recorder (existing)

```go
type recordingQlogger struct {
    events []qlogwriter.Event
}

func (r *recordingQlogger) RecordEvent(ev qlogwriter.Event) {
    r.events = append(r.events, ev)
}

func (r *recordingQlogger) Close() error { return nil }
```

---

## 3. New Tests by Section

### 3.1 Per-Packet State (§4.1.2.2)

**TestBBRv3PerPacketStateCapture**
- Send packet when BBR has known state
- Assert all 6 P.* fields captured correctly:
  - `P.delivered` = `bbr.totalBytesAcked` at send
  - `P.delivered_time` = `bbr.deliveredTime` at send
  - `P.first_sent_time` = inherited or reset
  - `P.is_app_limited` = `bbr.totalBytesAcked < bbr.appLimitedUntil`
  - `P.tx_in_flight` = `bytesInFlight` parameter
  - `P.lost` = `bbr.totalBytesLost` at send (maps to `totalBytesLost` field)

**TestBBRv3PerPacketStateRoundTrip**
- Send packet, ACK packet
- Verify rate sample fields derived correctly from P.* state
- Assert RS.delivered, RS.send_elapsed, RS.ack_elapsed, RS.is_app_limited

**TestBBRv3FirstSentTimeInheritance**
- Consolidate existing firstSentTime tests
- Verify inheritance when packets in flight
- Verify reset when inflight drops to 0

### 3.2 Idle Restart (§5.4)

**TestBBRv3IdleRestartRefreshesPacingTokens**
- Exhaust pacing budget in steady state
- Simulate idle period
- Verify first send after idle has fresh pacing budget
- Verify `HasPacingBudget(now)` returns true

**TestBBRv3IdleRestartPreservesCwnd**
- Establish cwnd in ProbeBW
- Go idle, restart
- Assert cwnd unchanged (BBR maintains prior estimate)

**TestBBRv3IdleRestartFlagLifecycle**
- Verify `idleRestart` starts false
- Set true on idle detection
- Cleared after first ACK processing
- ProbeRTT suppression only during restart window

**TestBBRv3IdleRestartSuppressesProbeRTT** (existing, relocated)

### 3.3 send_quantum and offload_budget (§5.5.8, §5.6.3)

**TestBBRv3SendQuantumCalculation**
- Table-driven: verify `send_quantum = min(pacing_rate * 1ms, 64KB)`
- Cases: 1 MB/s → 1000B, 100 MB/s → 65535B (capped), 10 KB/s → 10B

**TestBBRv3OffloadBudgetCalculation**
- Verify `offload_budget = 2 * send_quantum`
- Verify minPipeCwnd floor applies

**TestBBRv3QuantizationBudgetUsesOffloadBudget**
- Verify quantizationBudget returns max of:
  - 3 * send_quantum
  - offload_budget
  - minPipeCwnd
- Test each floor as binding constraint

**TestBBRv3CwndQuantizationFloor**
- Small BDP scenario
- Verify cwnd respects quantization floor (minPipeCwnd)

### 3.4 ECN Alpha (§5.3.3.6.4)

**TestBBRv3ECNAlphaCalculation**
- Table-driven EWMA formula: `alpha = (1 - g) * alpha + g * (CE/acked)`
- g = 1/16 (BBR_ECN_ALPHA_GAIN)
- Cases: decay (0% CE), rise (50% CE), stable

**TestBBRv3ECNAlphaBounds**
- 100% CE → alpha approaches 1.0
- 0% CE → alpha approaches 0.0
- Zero acked bytes → alpha unchanged

**TestBBRv3ECNAlphaConvergence**
- Sustained 50% CE over multiple rounds
- Alpha converges to ~0.5

**TestBBRv3ECNAlphaReducesInflightLo**
- Formula: `inflightLo *= (1 - ecnAlpha * Beta)`
- alpha=0.5, Beta=0.3, inflightLo=100_000 → 85_000

### 3.5 ProbeBW Lower Bounds (§5.5.10)

**TestBBRv3ProbeBWCruiseLossReducesBounds**
- CRUISE + lossInRound=true
- `bwLo = max(bwLatest, bwLo * 0.7)`
- `inflightLo = max(inflightLatest, inflightLo * 0.7)`

**TestBBRv3ProbeBWCruiseECNReducesInflightLo**
- CRUISE + ecnInRound=true
- Only inflightLo reduced (not bwLo)
- Uses ecnAlpha in reduction

**TestBBRv3ProbeBWRefillClearsLowerBounds**
- Transition to REFILL
- bwLo and inflightLo reset to MaxByteCount

**TestBBRv3LowerBoundsConstrainCwnd**
- inflightLo < target cwnd
- Cwnd capped at inflightLo + maxDatagramSize

### 3.6 Table-Driven Gains (§5.6.1)

**TestBBRv3GainTableRFCCompliance**
```go
var gainTests = []struct {
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
```

**TestBBRv3StateTransitionSetsCorrectGains**
- Verify enterDrain(), enterProbeBW(), etc. set correct gains
- Not just updateGains() in isolation

---

## 4. Test Migration Map

### From `bbr_v3_test.go` (40 tests)

| Test | Destination Section |
|------|---------------------|
| TestBBRv3PacingBudget | §5.6: Control Parameters |
| TestBBRv3InitialQlogTelemetry | §5.2: Algorithm Lifecycle |
| TestBBRv3StartupRoundQlogTelemetry | §5.3.1: Startup |
| TestBBRv3StartupExitByFullBwPlateau | §5.3.1: Startup |
| TestBBRv3CheckFullBwReachedIgnoresIntraRoundSamples | §5.3.1: Startup |
| TestBBRv3StartupExitByExcessiveLoss | §5.3.1: Startup |
| TestBBRv3StartupExitByExcessiveECN | §5.3.1: Startup |
| TestBBRv3GuardrailAckAdvancesFirstSendTime | §4.1: Delivery Rate Sampling |
| TestBBRv3GuardrailNewestPacketTieBreakUsesPacketNumber | §4.1: Delivery Rate Sampling |
| TestBBRv3DrainCompletionAndProbeBWTransitions | §5.3.2: Drain |
| TestBBRv3DrainFallbackUsesDrainStartRound | §5.3.2: Drain |
| TestBBRv3ProbeTimingWallClockAndRenoRoundTrigger | §5.3.3: ProbeBW |
| TestBBRv3UpperAndLowerBoundAdaptation | §5.3.3: ProbeBW |
| TestBBRv3ProbeRTTEnterExitAndIdleRestartSuppression | §5.3.4: ProbeRTT |
| TestBBRv3AckAggregationRaisesCwndTarget | §5.5: Model Updates |
| TestBBRv3RFCGains | §5.6: Control Parameters (replaced by table-driven) |
| TestBBRv3ProbeRTTCwndUsesBoundedBandwidth | §5.3.4: ProbeRTT |
| TestBBRv3CwndLimitedSticksAcrossRoundBoundary | §5.6: Control Parameters |
| TestBBRv3OnAckEventEndFlushesPendingAckEvent | §4.1: Delivery Rate Sampling |
| TestBBRv3Name | §5.2: Algorithm Lifecycle |
| TestBBRv3SetRTTStats | §5.2: Algorithm Lifecycle |
| TestBBRv3StateString | §5.2: Algorithm Lifecycle |
| TestBBRv3PhaseString | §5.2: Algorithm Lifecycle |
| TestBBRv3SpuriousLoss* (6 tests) | §5.5: Model Updates |
| TestBBRv3Guardrail* (remaining) | Various by topic |

### From `bbr_v3_rfc_fixes_test.go` (32 tests)

| Test | Destination Section |
|------|---------------------|
| TestBBRv3PTORecoveryUsesInflightAndPreservesPriorCwnd | §5.6: Control Parameters |
| TestBBRv3GuardrailProbeRTTUsesAckEventInflightAfterLoss | §5.3.4: ProbeRTT |
| TestBBRv3ShortIntervalSamplesKeepLatestDeliveryBookkeeping | §4.1: Delivery Rate Sampling |
| TestBBRv3Pacer* (6 tests) | §5.6: Control Parameters |
| TestBBRv3Collision* (7 tests) | §5.6: Control Parameters |
| TestBBRv3ACKLookupMiss* (3 tests) | §4.1: Delivery Rate Sampling |
| TestBBRv3ECNGuard* (3 tests) | §5.5: Model Updates |
| TestBBRv3UpdateMinRTT* (2 tests) | §5.5: Model Updates |
| TestBBRv3ExtraAcked* (2 tests) | §5.5: Model Updates |
| TestBBRv3MaxInflight* (2 tests) | §5.6: Control Parameters |
| TestBBRv3AckEpoch* (2 tests) | §5.5: Model Updates |
| TestBBRv3OnRetransmissionTimeoutNoOp | §5.2: Algorithm Lifecycle |
| TestBBRv3SaveCwndPinsRoundScopedPredicate | §5.6: Control Parameters |
| TestBBRv3SpuriousLossPinsPerPacketSemantics | §5.5: Model Updates |

### From `bbr_v3_migration_test.go` (1 test)

| Test | Destination Section |
|------|---------------------|
| TestBBRv3ConnectionMigrationResetsControllerState | §5.2: Algorithm Lifecycle |

---

## 5. Implementation Order

1. **Phase 1: Create fixtures** — Add setup helpers to existing `bbr_v3_test.go`
2. **Phase 2: Add new tests** — Implement all new tests in appropriate sections
3. **Phase 3: Consolidate** — Move tests from other files, organize by section
4. **Phase 4: Delete old files** — Remove `bbr_v3_rfc_fixes_test.go` and `bbr_v3_migration_test.go`
5. **Phase 5: Verify** — Run `go test ./internal/congestion/...`, ensure all pass

---

## 6. Success Criteria

- Single `bbr_v3_test.go` with all tests organized by RFC section
- All 73 existing tests preserved and passing
- ~20 new tests added for identified gaps
- Each section has clear delimiter comments
- Table-driven gain test cites RFC sections
- No test duplication (consolidate overlapping tests)
- `go test ./internal/congestion/...` passes
