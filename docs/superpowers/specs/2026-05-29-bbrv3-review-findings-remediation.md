# BBRv3 Review Findings Remediation

**Date:** 2026-05-29  
**Status:** Draft  
**Branch:** `algo/bbrv3` (primary), `algo/bbrv3-adaptive` (secondary)

---

## 1. Overview

This spec defines remediation actions for findings F1-F10 from the external BBRv3 implementation review (Opus 4.8), validated through adversarial cross-review (Codex) against RFC draft-ietf-ccwg-bbr-05 and Google tcp_bbr.c v3.

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

Extend `BBRv3RoundUpdated` qlog event (which already has `ValidSamplesInRound`, `SuppressedSamplesInRound`, `MaxDeliveryRateInRound` at lines 2558-2560):

```go
type BBRv3RoundUpdated struct {
    // Existing fields (keep these)...
    ValidSamplesInRound      uint64
    SuppressedSamplesInRound uint64
    MaxDeliveryRateInRound   uint64
    
    // New instrumentation for F1
    SuppressedSamplesAtLossRoundStart uint64  // Subset: suppressed samples that coincided with loss_round_start
    BwLatestBeforeCut                 uint64  // bw_latest value BEFORE adaptLowerBounds runs (bytes/sec)
    BwLoBeforeCut                     uint64  // bw_lo value BEFORE adaptLowerBounds runs (bytes/sec)  
    InflightLoBeforeCut               uint64  // inflight_lo value BEFORE adaptLowerBounds runs (bytes)
    BwLoAfterCut                      uint64  // bw_lo value AFTER adaptLowerBounds runs (bytes/sec)
    InflightLoAfterCut                uint64  // inflight_lo value AFTER adaptLowerBounds runs (bytes)
}
```

**Implementation:**

1. Add counter `suppressedLossRoundStarts` incremented when `rs.deliveryRate == 0 && lossRoundStart`
2. Capture `bw_latest`/`bw_lo`/`inflight_lo` **before** `adaptLowerBounds` runs in `updateCongestionSignals` (this is the floor that clamps the cut)
3. Capture `bw_lo`/`inflight_lo` **after** `adaptLowerBounds` runs (to see the actual cut)
4. Emit in `BBRv3RoundUpdated` at round boundary
5. Build on existing `suppressedSamplesInRound` tracking, don't duplicate

**Candidate fix (gated on instrumentation data):**

If instrumentation confirms suppression-starved `bw_latest` drives the ratchet, the fix is to follow tcp_bbr.c rather than strict RFC §4.1.2.3:
- Let short-interval samples lift `bw_latest`/`max_bw` (for loss-cut floor purposes)
- Still suppress the rate for pacing/BDP calculations

This is a deliberate, documented RFC deviation to be implemented in a follow-up spec after data confirms causality.

**Acceptance criteria:**
- Qlog events include new fields at correct capture points
- Pacemaker can parse and report the trajectory of `bw_latest`/`bw_lo`/`inflight_lo` across rounds
- Before/after cut values visible in analysis
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

**Important:** The current code deliberately checks growth on **every ACK** (not just round boundaries) to prevent false-positive Startup exits — this is documented tcp_bbr.c alignment (bbr_v3.go:1481-1521). The team added this specifically because round-boundary-only checks caused 28% false-positive "filled pipe" detection. The fix must preserve this every-ACK growth check.

**Current code (`bbr_v3.go:1531`):**

```go
if bbr.fullBandwidthNow || rs.isAppLimited || rs.deliveryRate == 0 {
    return
}
```

**Fixed code — one-liner, just remove `|| rs.deliveryRate == 0`:**

```go
if bbr.fullBandwidthNow || rs.isAppLimited {
    return
}
// Rest of function unchanged:
// - Growth check on every ACK (thresh uses max(fullBandwidth, 1))
// - Suppressed sample (rate 0) fails 0 >= thresh, falls through
// - Counter increment at round-start now advances on suppressed samples
```

**Why this works:**
- `thresh := float64(max(bbr.fullBandwidth, 1)) * FULL_BW_GROWTH_THRESHOLD` ensures `thresh >= 1.25`
- Suppressed sample has `rs.deliveryRate == 0`
- `0 >= 1.25` is false → no growth reset (correct)
- Falls through to `if !bbr.roundStart { return }`
- At round-start: `fullBandwidthCount++` now advances (matching tcp_bbr.c)

**Key behavior preserved:**
- Every-ACK growth check (any high sample resets baseline)
- `max(fullBandwidth, 1)` guard prevents division issues
- Only the `deliveryRate == 0` early-return is removed

**Acceptance criteria:**
- Test 5 (100ms RTT) exits Startup within expected rounds
- Existing Startup tests pass (no regression to 28% false-positive rate)
- New test added: `TestBBRv3StartupExitsWithSuppressedRoundStartSamples`

### 3.4 F5: Sustained Loss Regression Test

**Rationale:** The test suite lacks a test that drives many rounds of moderate random loss. The 1%/3% collapse only appears in Pacemaker, making it slow to iterate.

**Note:** This requires a **closed-loop path model** where ACKs are fed at a rate driven by the controller's own cwnd/pacing decisions. The existing 100 tests are event-path (inject specific events, check state), not closed-loop. This test is more harness than the snippet implies.

**New test in `bbr_v3_test.go`:**

```go
func TestBBRv3SustainedLossStability(t *testing.T) {
    // Setup: 1 Gbps path, 50ms RTT
    // BDP: 125 MB/s × 50ms = 6.25 MB
    // Drive 200 rounds with ~3% per-flight loss via closed-loop model
    // Assert:
    //   - maxBandwidth() >= 62.5 MB/s (0.5x offered)
    //   - cwnd does not decay below 3.125 MB (0.5x BDP)
    //   - bw_lo does not collapse to near-zero
}
```

**Test parameters:**
- Offered rate: 1 Gbps (125 MB/s)
- RTT: 50ms
- BDP: 6.25 MB (125 MB/s × 0.05s)
- Rounds: 200
- Loss rate: 3% of `tx_in_flight` per sample
- Closed-loop: ACK rate determined by controller's pacing/cwnd

**Assertions:**
- `maxBandwidth() >= 62.5 MB/s` (0.5x offered) — lower bound
- No upper bound on `maxBandwidth()` — BBR legitimately overestimates (~1.18x typical)
- `cwnd >= 3.125 MB` (0.5x BDP)
- `bwLo >= 10 MB/s` (does not collapse to near-zero)

**Acceptance criteria:**
- Test exists and runs in `go test`
- Closed-loop harness implemented (feeds ACKs based on controller state)
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

### 4.2 Correct Restore (keep ALL behavior from primary branch)

The primary branch's current `OnSpuriousLossDetected` (bbr_v3.go:1994-2031) has the correct RFC §5.5.11.2 restore logic. The consolidation must preserve **all** of this behavior, not just the three bound assignments:

```go
func (bbr *BBRv3) restoreBoundsForSpuriousEpisode() {
    // 1. Clear loss-in-round flag since the loss was spurious
    bbr.lossInRound = false

    // 2. Reset full bandwidth estimator to re-probe after spurious loss
    bbr.resetFullBw()

    // 3. Restore bounds to max of current and saved values per RFC §5.5.11.2:
    //    BBR.bw_shortterm = max(BBR.bw_shortterm, BBR.undo_bw_shortterm)
    if bbr.undoBwLo > bbr.bwLo {
        bbr.bwLo = bbr.undoBwLo
    }
    if bbr.undoInflightLo > bbr.inflightLo {
        bbr.inflightLo = bbr.undoInflightLo
    }
    if bbr.undoInflightHi > bbr.inflightHi {
        bbr.inflightHi = bbr.undoInflightHi
    }

    // 4. Restore cwnd to max of current and saved, then apply bounds
    if bbr.undoCwnd > bbr.congestionWindow {
        bbr.congestionWindow = bbr.undoCwnd
    }
    bbr.boundCwndForInflightModel()

    // 5. State re-entry per RFC §5.5.11.2 (draft lines 3783-3788):
    //    If not in ProbeRTT and state changed, re-enter probing state
    if bbr.state != BBRProbeRTT && bbr.state != bbr.undoState {
        if bbr.undoState == BBRStartup {
            bbr.state = BBRStartup
            bbr.pacingGain = STARTUP_PACING_GAIN
            bbr.cwndGain = STARTUP_CWND_GAIN
            bbr.fullBandwidthReached = false
        } else if bbr.undoState == BBRProbeBW && bbr.undoProbeBWPhase == probeBWUp {
            bbr.startProbeBWUp(monotime.Now(), bbr.bwLatest)
        }
    }

    // 6. Clear episode state
    bbr.lossEpisodeActive = false
    bbr.lossEpisodePackets = nil
    bbr.lossEpisodeTotalBytes = 0
    bbr.lossEpisodeSpuriousBytes = 0

    // 7. Emit qlog event (preserve existing qlog emission)
}
```

**Do NOT use `resetLowerBoundsForSpuriousRecovery()` from adaptive branch** — it resets to infinity which over-restores in mixed episodes, and it drops the cwnd restore, state re-entry, and other behaviors the primary branch already gets right.

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

### 5.1 F6: Remove False QUICHE Attribution, Add Sanity Bound

**Current code (`sent_packet_handler.go:68`):**

```go
maxAdaptiveReorderingThreshold = protocol.PacketNumber(300) // QUICHE kMaxPacketReorderingThreshold
```

**Issue:** QUICHE has no `kMaxPacketReorderingThreshold` constant — this attribution is fabricated. However, an unbounded threshold can defer genuine loss detection arbitrarily on pathological paths.

**Change:** Keep a high sanity bound, but relabel it honestly as a quic-go safety limit.

```go
// maxAdaptiveReorderingThreshold is a quic-go safety bound (NOT a QUICHE port).
// QUICHE has no cap; we add this to prevent pathological paths from deferring
// loss detection indefinitely. Set to PN window size as a reasonable upper bound.
maxAdaptiveReorderingThreshold = protocol.PacketNumber(1 << 14) // 16384 — well above any realistic reordering
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

    // quic-go safety bound (not QUICHE — they have no cap)
    return min(threshold, maxAdaptiveReorderingThreshold)
}
```

**Acceptance criteria:**
- False QUICHE attribution removed
- Sanity bound retained with honest labeling
- Comments and design doc updated to clarify this is a quic-go safety decision

### 5.2 F7: Use `previous_largest_acked` with `history.Difference()`

**Current code (`sent_packet_handler.go`, `detectSpuriousLosses`):**

```go
packetReordering := h.appDataPackets.history.Difference(ack.LargestAcked(), pn)
```

**Issue:** Uses current ACK's `LargestAcked()`, but QUICHE uses `previous_largest_acked`. Also, raw subtraction (`previous - pn + 1`) would discard what `history.Difference()` provides: adjustment for skipped/non-ack-eliciting packet numbers.

**Change:** Capture `previous_largest_acked` before updating, and use `history.Difference()` to preserve skipped-PN adjustment.

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
    // Use history.Difference to account for skipped PNs, but with previous_largest_acked
    packetReordering := h.appDataPackets.history.Difference(previousLargestAcked, pn)
    // ...
}
```

**Note on +1 consistency:** QUICHE uses `previous_largest_acked - packet_number + 1`. The current code compares `Difference(...) >= threshold` with no +1 adjustment. Decision: keep using `Difference()` without +1, as the threshold comparison is already calibrated to this. Document this as a minor deviation from QUICHE's exact formula (off-by-one in threshold growth rate).

**Acceptance criteria:**
- Gap calculation uses `previous_largest_acked`
- Uses `history.Difference()` to preserve skipped-PN adjustment
- Threshold grows at approximately QUICHE's rate (within off-by-one)

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

### 7.1 F3 Episode Tracking — Special Handling

F3 ports episode tracking from `algo/bbrv3-adaptive` to `algo/bbrv3`. After this port, the episode code lives in **both** branches, which would cause conflicts on rebase.

**Sequence:**

1. Land F3 episode tracking on `algo/bbrv3` (primary)
2. When rebasing `algo/bbrv3-adaptive` onto the updated primary:
   - Drop/squash adaptive's original episode tracking commits
   - Primary becomes the single source of truth for episode logic
   - Adaptive branch retains only the feature flag constants and threshold logic

### 7.2 Change Propagation Order

```
algo/bbrv3 (primary)
    ↓ (F3 episode tracking now lives here)
    ↓ rebase (drop adaptive's duplicate episode commits)
algo/bbrv3-adaptive
    ↓ recreate feature flag branches from new tip
algo/bbrv3-adaptive-{baseline,bdp,monotonic,time,full}
```

### 7.3 Branch Status Check

**Before any force-push, verify:**

```bash
# Check for open PRs or shared history
gh pr list --head algo/bbrv3-adaptive
gh pr list --head algo/bbrv3-adaptive-baseline
# ... etc for each branch

# Check remote tracking
git branch -vv | grep adaptive
```

**If branches have open PRs or are used by CI:** Do NOT force-push. Instead, recreate the flag branches from the new adaptive tip:

```bash
# Safer approach: delete and recreate
git checkout algo/bbrv3-adaptive
git branch -D algo/bbrv3-adaptive-baseline  # delete local
git push origin --delete algo/bbrv3-adaptive-baseline  # delete remote
# Then recreate with correct constants
```

### 7.4 Rebase Procedure (if safe to force-push)

```bash
# 1. Update primary with F3
git checkout algo/bbrv3
# ... implement F3 ...
git push

# 2. Rebase adaptive, dropping duplicate episode commits
git checkout algo/bbrv3-adaptive
git rebase -i algo/bbrv3
# In interactive rebase: drop commits that add episode tracking (now in primary)
git push --force-with-lease

# 3. Recreate feature flag branches from new adaptive tip
for branch in baseline bdp monotonic time full; do
    git checkout algo/bbrv3-adaptive
    git checkout -B algo/bbrv3-adaptive-$branch
    # Edit sent_packet_handler.go:64-66 to set branch-specific flags
    git commit -am "set feature flags for $branch configuration"
    git push --force-with-lease origin algo/bbrv3-adaptive-$branch
done
```

### 7.5 Feature Flag Values

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
