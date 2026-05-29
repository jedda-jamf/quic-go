# BBRv3 Review Findings Remediation

**Date:** 2026-05-29  
**Status:** Draft  
**Branch:** `algo/bbrv3` (primary), `algo/bbrv3-adaptive` (secondary)

---

## 1. Overview

This spec defines remediation actions for findings F1-F10 from the external BBRv3 implementation review, validated through adversarial cross-review by three agents against RFC draft-ietf-ccwg-bbr-05 and Google tcp_bbr.c v3.

### Scope

- Core BBRv3 fixes (F1, F2, F4, F5, F9)
- Spurious loss recovery consolidation (F3)
- Adaptive threshold corrections (F6, F7, F8, F10)
- Qlog instrumentation for Pacemaker integration
- Branch management for propagating changes

### Out of Scope

- New features beyond remediation
- Performance optimizations not tied to findings
- RFC deviations beyond those documented here

---

## 2. Finding Dispositions

| ID | Sev | Title | Disposition |
|----|-----|-------|-------------|
| F1 | M | Min-RTT suppression amplifier | Instrument first |
| F2 | H | Phase 4 gate proposal | Reject — do not implement |
| F3 | M | Per-packet vs episode-level spurious recovery | Combine implementations |
| F4 | H | Startup exit blocked at high RTT | Fix — surgical approach |
| F5 | M | No sustained loss regression test | Add test |
| F6 | M | Fabricated QUICHE 300 cap | Drop cap |
| F7 | M | Wrong `largest_acked` in monotonic growth | Fix to match QUICHE |
| F8 | M | `max(bdp, monotonic)` defeats self-relaxation | Defer — A/B test required |
| F9 | L | Interface dispatch documentation | Add comments |
| F10 | L | Dead code and initial threshold docs | Clean up |

---

## 3. Core BBRv3 Changes (`algo/bbrv3`)

### 3.1 F1: Qlog Instrumentation for Suppressed Samples

**Rationale:** The min-RTT rate suppression is RFC-compliant but may amplify loss-driven bound ratcheting. Static review cannot confirm causality; instrumentation is required before any code change.

**Changes to `bbr_v3.go`:**

Add per-round tracking in the `BBRv3RoundUpdated` qlog event:

```go
type BBRv3RoundUpdated struct {
    // Existing fields...
    
    // New instrumentation for F1
    SuppressedSamplesAtLossRoundStart uint64  // Suppressed samples that coincided with loss_round_start
    BwLatestAtRoundEnd                uint64  // bw_latest value at round boundary (bytes/sec)
    BwLoAtRoundEnd                    uint64  // bw_lo value at round boundary (bytes/sec)
    InflightLoAtRoundEnd              uint64  // inflight_lo value at round boundary (bytes)
}
```

**Implementation:**

1. Add counter `suppressedLossRoundStarts` incremented when `rs.deliveryRate == 0 && lossRoundStart`
2. Emit `BwLatestAtRoundEnd`, `BwLoAtRoundEnd`, `InflightLoAtRoundEnd` in `advanceLatestDeliverySignals`
3. Reset counters at round boundary

**Acceptance criteria:**
- Qlog events include new fields
- Pacemaker can parse and report the trajectory of `bw_latest`/`bw_lo`/`inflight_lo` across rounds
- Data from 1%/3% loss scenarios can confirm or refute F1 as collapse amplifier

### 3.2 F2: Reject Phase 4 Gate

**Rationale:** The current `max_bw` sampling gate is identical to tcp_bbr.c (line 1489). Adding a `rs.deliveryRate >= bwLo` gate would diverge from the reference implementation.

**Changes:**

1. Remove Phase 4 proposal from `docs/bbrv3-validation-investigation.md`
2. Add note documenting why the proposal was rejected:

```markdown
### Rejected: Phase 4 max_bw Sampling Gate

The proposal to gate `max_bw` sampling on `rs.deliveryRate >= bwLo` was rejected
after cross-review verification that the current gate matches tcp_bbr.c exactly
(line 1489). The "filter pollution" hypothesis treats a symptom; low samples 
cannot lower the windowed-max filter except via rotation.
```

**Acceptance criteria:**
- Phase 4 proposal removed from investigation doc
- Rejection rationale documented

### 3.3 F4: Fix Startup Exit at High RTT

**Rationale:** The `deliveryRate == 0` guard in `checkFullBwReached` prevents the plateau counter from advancing on suppressed round-start samples, causing Startup to never exit at high RTT. tcp_bbr.c (line 1935) has no such guard.

**Current code (`bbr_v3.go:1531`):**

```go
if bbr.fullBandwidthNow || rs.isAppLimited || rs.deliveryRate == 0 {
    return
}
```

**Fixed code:**

```go
if bbr.fullBandwidthNow || rs.isAppLimited {
    return
}

// ... existing round-start check ...

if bbr.roundStart {
    if rs.deliveryRate > 0 && rs.deliveryRate >= protocol.ByteCount(float64(bbr.fullBandwidth)*FULL_BW_GROWTH_THRESHOLD) {
        // Growth detected — reset counter (only on valid samples)
        bbr.fullBandwidth = rs.deliveryRate
        bbr.fullBandwidthCount = 0
    } else {
        // No growth — increment counter (even on suppressed samples, matching tcp_bbr.c)
        bbr.fullBandwidthCount++
    }
}
```

**Key behavior change:**
- Plateau counter (`fullBandwidthCount++`) advances on suppressed round-start samples
- Growth-reset branch (`fullBandwidthCount = 0`) only fires on valid samples with `deliveryRate > 0`
- Matches tcp_bbr.c behavior where round-start always advances the counter

**Acceptance criteria:**
- Test 5 (100ms RTT) exits Startup within expected rounds
- Existing Startup tests pass
- New test added: `TestBBRv3StartupExitsWithSuppressedRoundStartSamples`

### 3.4 F5: Sustained Loss Regression Test

**Rationale:** The test suite lacks a test that drives many rounds of moderate random loss. The 1%/3% collapse only appears in Pacemaker, making it slow to iterate.

**New test in `bbr_v3_test.go`:**

```go
func TestBBRv3SustainedLossStability(t *testing.T) {
    // Setup: 1 Gbps path, 50ms RTT, ~20 MB BDP
    // Drive 200 rounds with ~3% per-flight loss
    // Assert:
    //   - maxBandwidth() stays within 0.5-1.5x of offered rate
    //   - cwnd does not decay below 0.5 * BDP
    //   - bw_lo does not collapse to near-zero
}
```

**Test parameters:**
- Offered rate: 1 Gbps (125 MB/s)
- RTT: 50ms
- BDP: ~6.25 MB
- Rounds: 200
- Loss rate: 3% of `tx_in_flight` per sample
- Assertions:
  - `maxBandwidth() >= 62.5 MB/s` (0.5x offered)
  - `maxBandwidth() <= 187.5 MB/s` (1.5x offered)
  - `cwnd >= 3.125 MB` (0.5x BDP)
  - `bwLo >= 10 MB/s` (does not collapse)

**Acceptance criteria:**
- Test exists and runs in `go test`
- Test documents current behavior (may fail initially, establishing baseline)
- After F1 instrumentation, test either passes (if fix applied) or assertions are adjusted to document expected RFC-faithful behavior with rationale

### 3.5 F9: Interface Dispatch Comments

**Rationale:** The dispatch is sound but two behaviors warrant documentation.

**Changes to `sent_packet_handler.go`:**

1. At `detectSpuriousLosses` call site (~line 491):

```go
// detectSpuriousLosses only runs when this ACK advanced largestAcked.
// Spurious-loss signals are suppressed for reordered ACKs — this is
// intentional since the reordering regime triggers threshold adaptation
// through the normal loss path, not through spurious detection.
h.detectSpuriousLosses(ack, ackTime)
```

2. At ECN congestion `OnCongestionEvent` call (~line 445):

```go
// ECN congestion signal. BBRv3 early-returns on lostBytes==0 because
// it consumes ECN via OnECNFeedback instead. This call is retained for
// CCs that handle ECN through the loss path (e.g., NewReno/Cubic).
h.congestion.OnCongestionEvent(largestAcked, 0, priorInFlight)
```

**Acceptance criteria:**
- Comments added
- No behavior change

---

## 4. Spurious Loss Recovery Consolidation (F3)

**Rationale:** RFC §5.5.11 specifies episode-level spurious recovery. Neither branch is currently correct:
- Primary: correct restore (`max(current, undo)`), wrong trigger (per-packet)
- Adaptive: correct trigger (episode-level), wrong restore (reset to infinity)

### 4.1 Episode Tracking (from adaptive branch)

Port the following from `algo/bbrv3-adaptive` to `algo/bbrv3`:

**New fields in `BBRv3` struct:**

```go
// Loss episode tracking for §5.5.11 spurious recovery
lossEpisodeActive        bool
lossEpisodePackets       map[protocol.PacketNumber]protocol.ByteCount
lossEpisodeTotalBytes    protocol.ByteCount
lossEpisodeSpuriousBytes protocol.ByteCount
pendingLossPackets       map[protocol.PacketNumber]protocol.ByteCount
```

**Episode lifecycle:**

1. `OnCongestionEvent`: Add lost packet to `pendingLossPackets`
2. `adaptLowerBounds` (when cuts applied): Promote `pendingLossPackets` to active episode
3. `OnSpuriousLossDetected`: Accumulate `spuriousBytes` if packet in active episode
4. Restore when `spuriousBytes > totalBytes/2` (strict majority)

### 4.2 Correct Restore (keep from primary branch)

The restore logic must use `max(current, undo)` per RFC §5.5.11.2:

```go
func (bbr *BBRv3) restoreBoundsForSpuriousEpisode() {
    // RFC §5.5.11.2: BBR.bw_shortterm = max(BBR.bw_shortterm, BBR.undo_bw_shortterm)
    if bbr.undoBwLo > bbr.bwLo {
        bbr.bwLo = bbr.undoBwLo
    }
    if bbr.undoInflightLo > bbr.inflightLo {
        bbr.inflightLo = bbr.undoInflightLo
    }
    if bbr.undoInflightHi > bbr.inflightHi {
        bbr.inflightHi = bbr.undoInflightHi
    }
    
    // Clear episode state
    bbr.lossEpisodeActive = false
    bbr.lossEpisodePackets = nil
    bbr.lossEpisodeTotalBytes = 0
    bbr.lossEpisodeSpuriousBytes = 0
}
```

**Do NOT use `resetLowerBoundsForSpuriousRecovery()` from adaptive branch** — it resets to infinity which over-restores in mixed episodes.

### 4.3 Fix Integer Division Edge Case

The strict-`>` with integer division never fires at exact 50/50:

```go
// Wrong: 50 > 100/2 is 50 > 50 which is false
if bbr.lossEpisodeSpuriousBytes > bbr.lossEpisodeTotalBytes/2

// Correct: use 2x comparison to avoid division
if bbr.lossEpisodeSpuriousBytes*2 > bbr.lossEpisodeTotalBytes
```

### 4.4 Remove Dead Parameter

`OnSpuriousLossDetected` receives `spuriousBytes` but ignores it (uses episode tracking instead). Either:
- Remove the parameter from the interface, or
- Use it for the episode accumulation

**Decision:** Use it for accumulation — the loss detector already knows the packet size.

**Acceptance criteria:**
- Episode-level trigger implemented
- `max(current, undo)` restore preserved
- Integer division edge case fixed
- Dead parameter wired up or removed
- Existing spurious loss tests updated
- New test: `TestBBRv3SpuriousRecoveryRequiresMajority`

---

## 5. Adaptive Threshold Corrections (`algo/bbrv3-adaptive`)

### 5.1 F6: Drop 300 Cap

**Current code (`sent_packet_handler.go:68`):**

```go
maxAdaptiveReorderingThreshold = protocol.PacketNumber(300) // QUICHE kMaxPacketReorderingThreshold
```

**Change:** Remove the cap entirely to match QUICHE's unbounded growth.

```go
// Removed: maxAdaptiveReorderingThreshold — QUICHE has no cap
```

**Update `getPacketReorderingThreshold()`:**

```go
func (h *sentPacketHandler) getPacketReorderingThreshold() protocol.PacketNumber {
    threshold := protocol.PacketNumber(packetThreshold) // RFC 9002 default: 3

    if enableBDPScaledThreshold && h.maxDatagramSize > 0 {
        bdpThreshold := protocol.PacketNumber(h.bytesInFlight / h.maxDatagramSize / 2)
        bdpThreshold = max(packetThreshold, bdpThreshold)
        bdpThreshold = min(maxBDPScaledThreshold, bdpThreshold) // ngtcp2 cap: 256
        threshold = bdpThreshold
    }

    if enableMonotonicThresholdGrowth {
        threshold = max(threshold, h.adaptiveReorderingThreshold)
    }

    // No overall cap — matches QUICHE unbounded growth
    return threshold
}
```

**Acceptance criteria:**
- 300 cap removed
- Comments updated to remove false QUICHE attribution
- Design doc updated

### 5.2 F7: Use `previous_largest_acked`

**Current code (`sent_packet_handler.go`, `detectSpuriousLosses`):**

```go
packetReordering := h.appDataPackets.history.Difference(ack.LargestAcked(), pn)
```

**Change:** Capture `previous_largest_acked` before updating and use it.

**In `ReceivedAck` (~line 460), before updating `largestAcked`:**

```go
previousLargestAcked := pnSpace.largestAcked
// ... existing update logic ...
pnSpace.largestAcked = largestAcked

// Later, pass to detectSpuriousLosses
h.detectSpuriousLosses(ack, ackTime, previousLargestAcked)
```

**In `detectSpuriousLosses`:**

```go
func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time, previousLargestAcked protocol.PacketNumber) {
    // ...
    packetReordering := previousLargestAcked - pn + 1  // QUICHE formula
    // ...
}
```

**Acceptance criteria:**
- Gap calculation uses `previous_largest_acked`
- Threshold grows at QUICHE's rate, not faster

### 5.3 F8: Defer — A/B Test Plan

**Rationale:** The `max(bdpScaled, monotonic)` combination defeats ngtcp2's self-relaxation. This is a design choice requiring empirical data.

**No code change in this spec.** Define A/B test plan:

| Configuration | BDP-Scaled | Monotonic | Description |
|---------------|:----------:|:---------:|-------------|
| A: BDP-only | ✅ | ❌ | ngtcp2-style, self-relaxing |
| B: Monotonic-only | ❌ | ✅ | QUICHE-style, never shrinks |
| C: Current combo | ✅ | ✅ | `max()` of both |

**Test matrix:**

| Reorder Level | Runs per Config | Metrics |
|---------------|-----------------|---------|
| 0% (baseline) | 100 | Throughput, TTFB |
| 5% (mild) | 100 | Throughput, loss declarations, threshold evolution |
| 15% (moderate) | 100 | Throughput, loss declarations, threshold evolution |
| 25% (severe) | 100 | Throughput, loss declarations, threshold evolution |

**Total runs:** 1,200 (3 configs × 4 reorder levels × 100 runs)

**Decision criteria:**
- If monotonic-only matches or beats combo across all levels → adopt monotonic-only
- If BDP-only shows better recovery after transient reordering → consider BDP-only
- If combo provides measurable benefit → keep combo with documented rationale

**Acceptance criteria:**
- Test plan documented
- Pacemaker harness updated to run matrix
- Analysis report generated
- Decision made and implemented in follow-up spec

### 5.4 F10: Remove Dead Code, Document Initial Threshold

**Remove `getTimeThreshold()`** — no production caller.

**Document in design doc and code comment:**

```go
// defaultReorderingShift = 2 gives initial loss delay of 1.25× RTT.
// This is intentionally more permissive than RFC 9002's 1.125× (9/8) to
// reduce spurious loss declarations on paths with moderate jitter.
// The threshold widens further (up to 2.0× RTT) on time-based spurious loss.
```

**Acceptance criteria:**
- Dead code removed
- Initial threshold divergence documented

---

## 6. Qlog Changes Report for Pacemaker

The following qlog changes require Pacemaker parser updates:

### 6.1 New Fields in `BBRv3RoundUpdated`

| Field | Type | Description |
|-------|------|-------------|
| `suppressed_samples_at_loss_round_start` | uint64 | Count of suppressed samples coinciding with `loss_round_start` |
| `bw_latest_at_round_end` | uint64 | `bw_latest` value at round boundary (bytes/sec) |
| `bw_lo_at_round_end` | uint64 | `bw_lo` value at round boundary (bytes/sec) |
| `inflight_lo_at_round_end` | uint64 | `inflight_lo` value at round boundary (bytes) |

### 6.2 Analysis Requirements

The Pacemaker analysis tool should:

1. **Track bound trajectories** — Plot `bw_latest`, `bw_lo`, `inflight_lo` across rounds
2. **Correlate with suppression** — Flag rounds where `suppressed_samples_at_loss_round_start > 0`
3. **Detect death spiral** — Alert when `bw_lo` decreases for N consecutive rounds
4. **Report suppression rate** — `suppressed / total` samples per scenario

### 6.3 Pacemaker Analysis Skill Update

The `pacemaker-analysis` skill should be updated to:

1. Parse new qlog fields
2. Generate F1 instrumentation report showing:
   - Suppression rate by scenario
   - Correlation between suppression and bound ratcheting
   - Visualization of `bw_lo` trajectory vs expected floor

---

## 7. Branch Management

### 7.1 Change Propagation

Changes to `algo/bbrv3` must propagate to adaptive branches:

```
algo/bbrv3 (primary)
    ↓ rebase
algo/bbrv3-adaptive (F3 episode tracking consolidated here)
    ↓ cherry-pick feature flag changes
algo/bbrv3-adaptive-baseline
algo/bbrv3-adaptive-bdp
algo/bbrv3-adaptive-monotonic
algo/bbrv3-adaptive-time
algo/bbrv3-adaptive-full
```

### 7.2 Rebase Procedure

After changes to `algo/bbrv3`:

```bash
# Update adaptive base
git checkout algo/bbrv3-adaptive
git rebase algo/bbrv3
git push --force-with-lease

# Update feature flag branches (differ only in constants)
for branch in baseline bdp monotonic time full; do
    git checkout algo/bbrv3-adaptive-$branch
    git rebase algo/bbrv3-adaptive
    git push --force-with-lease
done
```

### 7.3 Conflict Resolution

Expected conflicts in `sent_packet_handler.go` feature flag constants — resolve by preserving branch-specific values:

| Branch | `enableBDPScaledThreshold` | `enableMonotonicThresholdGrowth` | `enableAdaptiveTimeThreshold` |
|--------|:--------------------------:|:--------------------------------:|:-----------------------------:|
| baseline | false | false | false |
| bdp | true | false | false |
| monotonic | false | true | false |
| time | false | false | true |
| full | true | true | true |

---

## 8. Acceptance Criteria Summary

### Must Have

- [ ] F1: Qlog instrumentation added, Pacemaker report written
- [ ] F2: Phase 4 proposal removed, rejection documented
- [ ] F3: Episode-level spurious recovery with correct restore
- [ ] F4: Startup exits at high RTT, growth-reset gated on valid samples
- [ ] F5: Sustained loss regression test exists
- [ ] F6: 300 cap removed from adaptive branch
- [ ] F7: `previous_largest_acked` used in gap calculation
- [ ] F9: Interface dispatch comments added
- [ ] F10: Dead code removed, initial threshold documented
- [ ] Branch management: All adaptive branches rebased

### Should Have

- [ ] F8 A/B test plan executed
- [ ] F8 decision made based on data

### Test Coverage

- [ ] `TestBBRv3StartupExitsWithSuppressedRoundStartSamples`
- [ ] `TestBBRv3SustainedLossStability`
- [ ] `TestBBRv3SpuriousRecoveryRequiresMajority`
- [ ] Existing tests pass after changes

---

## 9. Revision History

| Date | Author | Change |
|------|--------|--------|
| 2026-05-29 | Claude | Initial spec from brainstorming session |
