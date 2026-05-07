# BBRv3 Test Review Fixes Design

**Goal:** Address six issues identified in external code review of BBRv3 test consolidation work. Fix methodology gaps where tests validate internal helpers rather than RFC-mandated behavior through event paths.

**Scope:** `internal/congestion/bbr_v3_test.go`, `internal/congestion/bbr_v3.go` (comments only)

---

## 1. File Organization: Three-Part Structure

Reorganize the test file into three explicit categories with agentic guardrail comments.

### Part 1: RFC Compliance Tests

```go
// ############################################################################
// PART 1: RFC COMPLIANCE TESTS (draft-ietf-ccwg-bbr-05)
// ############################################################################
//
// PURPOSE: These tests enforce MANDATORY behavior specified by the RFC.
//
// AGENTIC GUARDRAIL: Any agent modifying bbr_v3.go MUST NOT break these tests.
// If a change causes a test failure here, the agent must either:
//   (a) Revert the change - the RFC requirement is non-negotiable, OR
//   (b) Cite a specific RFC section that justifies the new behavior
//
// Each test references the RFC section it enforces. Assertions include the
// RFC requirement text so violations are self-documenting.
// ############################################################################
```

Contains sections:
- §4.1: DELIVERY RATE SAMPLING
- §5.2: ALGORITHM LIFECYCLE
- §5.3.1: STARTUP
- §5.3.2: DRAIN
- §5.3.3: PROBEBW
- §5.3.4: PROBERTT
- §5.5: MODEL UPDATES
- §5.6: CONTROL PARAMETERS

### Part 2: Implementation Strategy Tests

```go
// ############################################################################
// PART 2: IMPLEMENTATION STRATEGY TESTS
// ############################################################################
//
// PURPOSE: These tests enforce CHOSEN behavior where the RFC grants discretion.
//
// AGENTIC GUARDRAIL: Agents MAY propose changes here if they can justify an
// alternative implementation strategy. However, changes must:
//   (a) Document why the alternative is preferred
//   (b) Maintain consistency with the chosen strategy (e.g., all-tcp_bbr or all-custom)
//   (c) Update both code AND tests together
//
// These are NOT optional tests - they enforce our implementation contracts.
// They differ from Part 1 only in that the RFC permits alternative approaches.
// ############################################################################
```

Contains:
- ECN RESPONSE (tcp_bbr.c-aligned)

### Part 3: Regression Tests

```go
// ############################################################################
// PART 3: REGRESSION TESTS
// ############################################################################
//
// PURPOSE: Pin bug fixes and edge cases discovered through testing/production.
//
// AGENTIC GUARDRAIL: These tests exist because something broke in the past.
// Do not delete without understanding WHY the test was added. Each test
// should reference the issue/commit that motivated it.
// ############################################################################
```

Contains existing guardrail tests.

---

## 2. Issue Fixes

### Issue 1: ECN Alpha Tests Overclaim RFC Compliance

**Problem:** Tests cite RFC §5.3.3.6.4 but the RFC explicitly leaves ECN response unspecified (§3.7).

**Root Cause:** Our implementation follows Google's tcp_bbr.c, not RFC requirements. The EWMA formula (1/16 gain) and inflightLo reduction (1/3 factor) are tcp_bbr.c implementation choices.

**Fix:**
1. Move all ECN tests to Part 2 (Implementation Strategy Tests)
2. Update section header:
   ```go
   // ============================================================================
   // ECN RESPONSE (tcp_bbr.c-aligned)
   // RFC §3.7: "This draft does not specify a specific response to ECN."
   // IMPLEMENTATION CHOICE: We follow Google's tcp_bbr.c approach:
   //   - EWMA ecn_alpha with gain = 1/16
   //   - inflightLo *= (1 - ecn_alpha * 1/3) on ECN-in-round
   // ============================================================================
   ```
3. Update test comments to reference tcp_bbr.c instead of RFC sections
4. Add `TestBBRv3ECNEventPath` - event-path integration test

**Tests affected:**
- `TestBBRv3ECNAlphaCalculation` - relabel
- `TestBBRv3ECNAlphaBounds` - relabel
- `TestBBRv3ECNAlphaConvergence` - relabel
- `TestBBRv3ECNAlphaReducesInflightLo` - relabel
- `TestBBRv3ECNEventPath` - new

### Issue 2: Round-Trip Sampler Test Too Weak

**Problem:** `TestBBRv3PerPacketStateRoundTrip` only checks `pendingAckedBytes > 0`, not actual RS.* fields from RFC §4.2.

**Fix:** Rewrite as `TestBBRv3RateSampleContract` with:
- Explicit known values for setup
- Assertions on all RFC §4.2 rate sample fields:
  - `RS.delivered` - bytes delivered in sample interval
  - `RS.send_elapsed` - time between first and last send
  - `RS.ack_elapsed` - time between first and last ACK
  - `RS.is_app_limited` - whether sample was app-limited
  - `RS.delivery_rate` - computed bytes/second
- RFC requirement text in assertion messages

### Issue 3: Idle Restart Tests Use Hand-Mutated State

**Problem:** Tests manually set `bbr.idleRestart = true` instead of driving through event path. The implementation detects idle via `priorInFlight == 0` in `OnPacketSent`.

**Fix:** Rewrite all three tests to use event path:

1. `TestBBRv3IdleRestartPacingReset` - Drive through `OnPacketSent` with `bytesInFlight == packetSize`, verify pacing rate reset in ProbeBW state (RFC §5.4)

2. `TestBBRv3IdleRestartPreservesCwnd` - Full idle→send→ACK cycle, verify cwnd unchanged (RFC §5.4)

3. `TestBBRv3IdleRestartFlagLifecycle` - Verify flag set on idle send (`priorInFlight == 0`), cleared after first ACK processing

### Issue 4: Per-Packet State Test Misses P.send_time

**Problem:** Test misses `P.send_time` (RFC §4.1.2.1.2) and misplaces `P.lost` (used in §5.5.10, not §4.1.2.2).

**Fix:**
1. Add `st.sentTime` assertion to `TestBBRv3PerPacketStateCapture`
2. Remove `st.totalBytesLost` assertion from that test
3. Add `TestBBRv3LossModelPerPacketState` in §5.5 section for loss-related fields

### Issue 5: Quantization Floor Test Too Weak

**Problem:** Test only asserts `>= minPipeCwnd`, doesn't prove each term can be binding.

**Fix:** Replace with table-driven `TestBBRv3QuantizationBudgetBindingTerms`:

| Case | inflight | send_quantum | minPipeCwnd | Expected Winner |
|------|----------|--------------|-------------|-----------------|
| Large inflight | 100KB | 1KB | 5KB | inflight |
| Large quantum | 1KB | 50KB | 5KB | offload_budget |
| Small everything | 1KB | 1KB | 5KB | minPipeCwnd |

### Issue 6: Need Event-Path Integration Tests

**Problem:** Tests call internal methods (`updateECNAlpha`, `adaptLowerBounds`) directly rather than driving through production event path.

**Fix:** Add event-path integration tests:

1. `TestBBRv3LowerBoundsEventPath` (§5.5) - Drive loss through `OnCongestionEvent`, complete round via ACKs, verify bwLo/inflightLo adapted through normal processing

2. `TestBBRv3ECNEventPath` (Part 2) - Drive ECN CE marks through `OnECNFeedback` → `OnPacketAcked` → `OnAckEventEnd`, verify ecn_alpha and inflightLo updated through event path

---

## 3. Implementation Code Comments

Add clarifying comments to `bbr_v3.go` for ECN implementation choice.

### Constants Section (around lines 139-147)

```go
// ECN Response Implementation
// RFC draft-ietf-ccwg-bbr-05 §3.7 states: "This draft does not specify a
// specific response to ECN, and instead leaves it as an area for future work."
//
// IMPLEMENTATION CHOICE: We align with Google's tcp_bbr.c (Linux kernel BBRv3):
//   - Track ECN marking ratio via EWMA with gain = 1/16
//   - Reduce inflightLo by (ecn_alpha * 1/3) when ECN observed in round
//
// This approach is tested in bbr_v3_test.go Part 2 (Implementation Strategy Tests).

// ECN_ALPHA_GAIN is the EWMA smoothing factor for ecn_alpha (tcp_bbr.c)
ECN_ALPHA_GAIN = 1.0 / 16.0

// ECN_FACTOR is the inflightLo reduction multiplier (tcp_bbr.c)
ECN_FACTOR = 1.0 / 3.0
```

### updateECNAlpha Function (line 1124)

```go
// updateECNAlpha updates the ECN alpha EWMA.
// This is an IMPLEMENTATION CHOICE following tcp_bbr.c bbr_update_ecn_alpha().
// The RFC does not mandate this formula - see §3.7.
func (bbr *BBRv3) updateECNAlpha(rs bbrRateSample) {
```

---

## 4. Success Criteria

1. All tests pass after reorganization
2. Test file has three-part structure with agentic guardrail comments
3. ECN tests moved to Part 2 with tcp_bbr.c attribution
4. Rate sample test verifies all RFC §4.2 fields
5. Idle restart tests drive through OnPacketSent event path
6. Per-packet state test includes sentTime, loss field moved to §5.5
7. Quantization test proves each term can be binding
8. Event-path integration tests added for ECN and lower-bounds
9. bbr_v3.go has ECN implementation choice comments
10. `go test ./internal/congestion/...` passes
