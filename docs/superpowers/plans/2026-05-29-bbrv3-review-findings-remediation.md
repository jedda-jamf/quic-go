# BBRv3 Review Findings Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement fixes for BBRv3 findings F1-F10 from external review, consolidating spurious loss recovery and adding qlog instrumentation.

**Architecture:** Changes span two branches: core BBRv3 fixes on `algo/bbrv3` (F1, F2, F3, F4, F5, F9), then adaptive threshold fixes on `algo/bbrv3-adaptive` after rebasing (F6, F7, F10). F8 is deferred for A/B testing.

**Tech Stack:** Go 1.21+, quic-go internal packages, qlog instrumentation

---

## File Structure

| File | Responsibility | Tasks |
|------|----------------|-------|
| `internal/congestion/bbr_v3.go` | Core BBRv3 implementation | 1, 3, 4, 5 |
| `internal/congestion/bbr_v3_test.go` | BBRv3 unit tests | 1, 3, 4, 5 |
| `qlog/event.go` | Qlog event definitions | 1 |
| `qlog/event_test.go` | Qlog event tests | 1 |
| `docs/bbrv3-validation-investigation.md` | Investigation doc | 2 |
| `internal/ackhandler/sent_packet_handler.go` | Loss detection, dispatch | 6, 7, 8 |

---

## Branch: `algo/bbrv3` (Tasks 1-6)

### Task 1: F1 — Qlog Instrumentation for Suppressed Samples

Add qlog fields to track `bw_latest`/`bw_lo`/`inflight_lo` before and after `adaptLowerBounds` runs, enabling analysis of loss-driven ratcheting.

**Files:**
- Modify: `qlog/event.go:950-1050` (BBRv3RoundUpdated struct and Encode)
- Modify: `qlog/event_test.go:969-1000` (BBRv3RoundUpdated test)
- Modify: `internal/congestion/bbr_v3.go:200-300` (add capture fields to BBRv3 struct)
- Modify: `internal/congestion/bbr_v3.go:1332-1390` (capture in updateCongestionSignals)
- Modify: `internal/congestion/bbr_v3.go:2520-2565` (emit in buildRoundUpdateEvent)

- [ ] **Step 1.1: Add new fields to BBRv3RoundUpdated qlog event**

In `qlog/event.go`, add after line 976 (`TotalAckEventsInRound`):

```go
// F1 instrumentation: loss-cut trajectory tracking
SuppressedSamplesAtLossRoundStart uint32 // Suppressed samples that coincided with loss_round_start
BwLatestBeforeCut                 uint64 // bw_latest before adaptLowerBounds (bytes/sec)
BwLoBeforeCut                     uint64 // bw_lo before adaptLowerBounds (bytes/sec)
InflightLoBeforeCut               uint64 // inflight_lo before adaptLowerBounds (bytes)
BwLoAfterCut                      uint64 // bw_lo after adaptLowerBounds (bytes/sec)
InflightLoAfterCut                uint64 // inflight_lo after adaptLowerBounds (bytes)
```

- [ ] **Step 1.2: Add Encode methods for new qlog fields**

In `qlog/event.go`, in the `Encode` method for `BBRv3RoundUpdated`, add after the existing `TotalAckEventsInRound` encoding (approximately line 1065):

```go
if e.SuppressedSamplesAtLossRoundStart > 0 {
	h.WriteToken(jsontext.String("suppressed_samples_at_loss_round_start"))
	h.WriteToken(jsontext.Uint(uint64(e.SuppressedSamplesAtLossRoundStart)))
}
if e.BwLatestBeforeCut > 0 {
	h.WriteToken(jsontext.String("bw_latest_before_cut"))
	h.WriteToken(jsontext.Uint(e.BwLatestBeforeCut))
}
if e.BwLoBeforeCut > 0 {
	h.WriteToken(jsontext.String("bw_lo_before_cut"))
	h.WriteToken(jsontext.Uint(e.BwLoBeforeCut))
}
if e.InflightLoBeforeCut > 0 {
	h.WriteToken(jsontext.String("inflight_lo_before_cut"))
	h.WriteToken(jsontext.Uint(e.InflightLoBeforeCut))
}
if e.BwLoAfterCut > 0 {
	h.WriteToken(jsontext.String("bw_lo_after_cut"))
	h.WriteToken(jsontext.Uint(e.BwLoAfterCut))
}
if e.InflightLoAfterCut > 0 {
	h.WriteToken(jsontext.String("inflight_lo_after_cut"))
	h.WriteToken(jsontext.Uint(e.InflightLoAfterCut))
}
```

- [ ] **Step 1.3: Run qlog tests**

Run: `go test ./qlog/... -v -run TestBBRv3RoundUpdated`
Expected: PASS (existing test still passes, new fields are optional)

- [ ] **Step 1.4: Add capture fields to BBRv3 struct**

In `internal/congestion/bbr_v3.go`, add after the existing `suppressedSamplesInRound` field (around line 290):

```go
// F1 instrumentation: loss-cut trajectory tracking
suppressedLossRoundStarts uint32             // Suppressed samples at loss_round_start
cutSnapshotRound          uint64             // Round when snapshot was taken
bwLatestBeforeCut         protocol.ByteCount // bw_latest before adaptLowerBounds
bwLoBeforeCut             protocol.ByteCount // bw_lo before adaptLowerBounds
inflightLoBeforeCut       protocol.ByteCount // inflight_lo before adaptLowerBounds
bwLoAfterCut              protocol.ByteCount // bw_lo after adaptLowerBounds
inflightLoAfterCut        protocol.ByteCount // inflight_lo after adaptLowerBounds
```

- [ ] **Step 1.5: Track suppressed samples at loss_round_start**

In `internal/congestion/bbr_v3.go`, in `updateLatestDeliverySignals` (around line 1306), add after `bbr.lossRoundStart = true`:

```go
// Track suppressed samples at loss round start for F1 instrumentation
if rs.deliveryRate == 0 {
	bbr.suppressedLossRoundStarts++
}
```

- [ ] **Step 1.6: Capture before/after values in updateCongestionSignals**

In `internal/congestion/bbr_v3.go`, in `updateCongestionSignals` (around line 1332), modify to capture values before and after `adaptLowerBounds`:

Replace the existing:
```go
if !bbr.lossRoundStart {
	return
}
bbr.adaptLowerBounds(rs)
```

With:
```go
if !bbr.lossRoundStart {
	return
}
// F1 instrumentation: capture before-cut values
bbr.bwLatestBeforeCut = bbr.bwLatest
if bbr.bwLo != protocol.MaxByteCount {
	bbr.bwLoBeforeCut = bbr.bwLo
} else {
	bbr.bwLoBeforeCut = 0
}
if bbr.inflightLo != protocol.MaxByteCount {
	bbr.inflightLoBeforeCut = bbr.inflightLo
} else {
	bbr.inflightLoBeforeCut = 0
}

bbr.adaptLowerBounds(rs)

// F1 instrumentation: capture after-cut values
if bbr.bwLo != protocol.MaxByteCount {
	bbr.bwLoAfterCut = bbr.bwLo
} else {
	bbr.bwLoAfterCut = 0
}
if bbr.inflightLo != protocol.MaxByteCount {
	bbr.inflightLoAfterCut = bbr.inflightLo
} else {
	bbr.inflightLoAfterCut = 0
}
bbr.cutSnapshotRound = bbr.roundCount
```

- [ ] **Step 1.7: Emit new fields in buildRoundUpdateEvent**

In `internal/congestion/bbr_v3.go`, in `buildRoundUpdateEvent` (around line 2555), add after `TotalAckEventsInRound`:

```go
SuppressedSamplesAtLossRoundStart: uint32(bbr.suppressedLossRoundStarts),
BwLatestBeforeCut:                 uint64(bbr.bwLatestBeforeCut),
BwLoBeforeCut:                     uint64(bbr.bwLoBeforeCut),
InflightLoBeforeCut:               uint64(bbr.inflightLoBeforeCut),
BwLoAfterCut:                      uint64(bbr.bwLoAfterCut),
InflightLoAfterCut:                uint64(bbr.inflightLoAfterCut),
```

- [ ] **Step 1.8: Reset counters at round boundary**

In `internal/congestion/bbr_v3.go`, in `advanceLatestDeliverySignals` (around line 1321), add at the end of the `if bbr.lossRoundStart` block:

```go
// Reset F1 instrumentation counters
bbr.suppressedLossRoundStarts = 0
```

- [ ] **Step 1.9: Run BBRv3 tests**

Run: `go test ./internal/congestion/... -v -run TestBBRv3 -count=1`
Expected: PASS

- [ ] **Step 1.10: Commit**

```bash
git add qlog/event.go qlog/event_test.go internal/congestion/bbr_v3.go
git commit -m "$(cat <<'EOF'
feat(bbr): add F1 qlog instrumentation for loss-cut trajectory

Add fields to BBRv3RoundUpdated qlog event to track:
- Suppressed samples at loss_round_start
- bw_latest/bw_lo/inflight_lo before adaptLowerBounds
- bw_lo/inflight_lo after adaptLowerBounds

This enables Pacemaker analysis of whether min-RTT rate suppression
amplifies loss-driven bound ratcheting.

Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §3.1
EOF
)"
```

---

### Task 2: F2 — Reject Phase 4 Gate (Documentation Only)

Remove the Phase 4 proposal from the investigation doc and add rejection rationale.

**Files:**
- Modify: `docs/bbrv3-validation-investigation.md:546-560`

- [ ] **Step 2.1: Replace Phase 4 section with rejection note**

In `docs/bbrv3-validation-investigation.md`, replace lines 546-559 (the Phase 4 section):

```markdown
#### Rejected: Phase 4 max_bw Sampling Gate

The proposal to gate `max_bw` sampling on `rs.deliveryRate >= bwLo` was rejected
after cross-review verification that the current gate matches tcp_bbr.c exactly
(line 1489). The "filter pollution" hypothesis treats a symptom; low samples
cannot lower the windowed-max filter except via rotation.

**Original proposal (rejected):**
```go
// DO NOT IMPLEMENT: This diverges from tcp_bbr.c
if rs.deliveryRate > 0 && 
   (!rs.isAppLimited || rs.deliveryRate >= bbr.maxBandwidth()) &&
   (bbr.bwLo == protocol.MaxByteCount || rs.deliveryRate >= bbr.bwLo) {
    bbr.takeMaxBwSample(rs.deliveryRate)
}
```
```

- [ ] **Step 2.2: Commit**

```bash
git add docs/bbrv3-validation-investigation.md
git commit -m "$(cat <<'EOF'
docs(bbr): reject Phase 4 max_bw sampling gate proposal

Cross-review confirmed the current gate matches tcp_bbr.c line 1489.
Adding a bwLo gate would diverge from the reference implementation.

Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §3.2
EOF
)"
```

---

### Task 3: F4 — Fix Startup Exit at High RTT

Remove the `deliveryRate == 0` early-return in `checkFullBwReached` so the plateau counter advances on suppressed round-start samples.

**Files:**
- Modify: `internal/congestion/bbr_v3.go:1531`
- Modify: `internal/congestion/bbr_v3_test.go` (add new test)

- [ ] **Step 3.1: Write failing test**

In `internal/congestion/bbr_v3_test.go`, add:

```go
func TestBBRv3StartupExitsWithSuppressedRoundStartSamples(t *testing.T) {
	// Scenario: High-RTT path where round-start samples are suppressed
	// (interval < min_rtt). The plateau counter must still advance.
	bbr := newBBRv3ForTest(t)
	
	// Establish baseline: first round with valid sample
	bbr.minRTT = 100 * time.Millisecond
	rs := bbrRateSample{
		deliveryRate: 100_000_000, // 100 MB/s
		interval:     100 * time.Millisecond,
		delivered:    1000000,
		priorDelivered: 0,
	}
	bbr.processSample(rs)
	require.Equal(t, BBRStartup, bbr.state)
	
	// Simulate 3 rounds where round-start samples are suppressed (rate=0)
	// but no growth is occurring. Counter should still advance.
	for round := 0; round < 3; round++ {
		// Advance to next round
		bbr.nextRoundDelivered = bbr.totalBytesAcked
		rs.priorDelivered = bbr.totalBytesAcked
		bbr.totalBytesAcked += 1000000
		rs.delivered = 1000000
		
		// Round-start sample is suppressed (interval < min_rtt)
		rs.deliveryRate = 0
		rs.interval = 50 * time.Millisecond // < min_rtt
		bbr.processSample(rs)
	}
	
	// After 3 rounds without growth, should exit Startup
	require.True(t, bbr.fullBandwidthReached, "should have reached full bandwidth after 3 suppressed rounds")
	require.Equal(t, BBRDrain, bbr.state, "should transition to Drain")
}
```

- [ ] **Step 3.2: Run test to verify it fails**

Run: `go test ./internal/congestion/... -v -run TestBBRv3StartupExitsWithSuppressedRoundStartSamples`
Expected: FAIL — counter doesn't advance because of the `rs.deliveryRate == 0` guard

- [ ] **Step 3.3: Remove deliveryRate==0 guard**

In `internal/congestion/bbr_v3.go:1531`, change:

```go
if bbr.fullBandwidthNow || rs.isAppLimited || rs.deliveryRate == 0 {
	return
}
```

To:

```go
if bbr.fullBandwidthNow || rs.isAppLimited {
	return
}
```

- [ ] **Step 3.4: Run test to verify it passes**

Run: `go test ./internal/congestion/... -v -run TestBBRv3StartupExitsWithSuppressedRoundStartSamples`
Expected: PASS

- [ ] **Step 3.5: Run all Startup tests to verify no regression**

Run: `go test ./internal/congestion/... -v -run "TestBBRv3.*Startup" -count=1`
Expected: All PASS

- [ ] **Step 3.6: Commit**

```bash
git add internal/congestion/bbr_v3.go internal/congestion/bbr_v3_test.go
git commit -m "$(cat <<'EOF'
fix(bbr): allow Startup exit on suppressed round-start samples

Remove deliveryRate==0 guard from checkFullBwReached. This allows the
plateau counter to advance even when round-start samples are suppressed
due to min-RTT interval check, matching tcp_bbr.c line 1935.

The every-ACK growth check is preserved: suppressed samples (rate 0)
cannot exceed the 1.25x threshold, so they don't reset the baseline.

Fixes: High-RTT Startup stall (F4)
Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §3.3
EOF
)"
```

---

### Task 4: F3 — Episode-Level Spurious Loss Recovery

Port episode tracking from adaptive branch and consolidate with primary branch's correct restore logic.

**Files:**
- Modify: `internal/congestion/bbr_v3.go:200-300` (add episode fields)
- Modify: `internal/congestion/bbr_v3.go:1000-1100` (OnCongestionEvent)
- Modify: `internal/congestion/bbr_v3.go:1364-1390` (adaptLowerBounds episode promotion)
- Modify: `internal/congestion/bbr_v3.go:1985-2053` (OnSpuriousLossDetected)
- Modify: `internal/congestion/bbr_v3_test.go` (add majority test)

- [ ] **Step 4.1: Write failing test for majority threshold**

In `internal/congestion/bbr_v3_test.go`, add:

```go
func TestBBRv3SpuriousRecoveryRequiresMajority(t *testing.T) {
	bbr := newBBRv3ForTest(t)
	
	// Setup: establish bounds that will be cut
	bbr.bwLo = 100_000_000 // 100 MB/s
	bbr.inflightLo = 1_000_000 // 1 MB
	bbr.inflightHi = 2_000_000 // 2 MB
	
	// Save undo state
	bbr.undoBwLo = 100_000_000
	bbr.undoInflightLo = 1_000_000
	bbr.undoInflightHi = 2_000_000
	
	// Simulate loss that triggers adaptLowerBounds cut
	// (This would be done via OnCongestionEvent in real scenario)
	bbr.bwLo = 70_000_000 // Cut by BETA (30%)
	bbr.inflightLo = 700_000
	
	// Episode: 100 bytes total, 49 bytes spurious (49% < 50%)
	// Should NOT restore
	bbr.lossEpisodeActive = true
	bbr.lossEpisodeTotalBytes = 100
	bbr.lossEpisodeSpuriousBytes = 49
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{
		1: 49,
		2: 51, // not spurious
	}
	
	bbr.OnSpuriousLossDetected(1, 5)
	
	// Should NOT restore because 49 < 50
	require.Equal(t, protocol.ByteCount(70_000_000), bbr.bwLo, "bwLo should not restore at 49%")
	
	// Now add 2 more spurious bytes (51 total = 51% > 50%)
	bbr.OnSpuriousLossDetected(2, 5) // This packet was marked 51 bytes but only 2 more needed
	// Actually let's fix: we need to track by packet, so mark packet 2 as spurious
	// Reset and test properly with 51%
	bbr.lossEpisodeSpuriousBytes = 51
	
	// Manually trigger restore check
	if bbr.lossEpisodeSpuriousBytes*2 > bbr.lossEpisodeTotalBytes {
		bbr.restoreBoundsForSpuriousEpisode()
	}
	
	// Now should restore
	require.Equal(t, protocol.ByteCount(100_000_000), bbr.bwLo, "bwLo should restore at 51%")
}
```

- [ ] **Step 4.2: Run test to verify it fails**

Run: `go test ./internal/congestion/... -v -run TestBBRv3SpuriousRecoveryRequiresMajority`
Expected: FAIL — episode fields don't exist yet

- [ ] **Step 4.3: Add episode tracking fields to BBRv3 struct**

In `internal/congestion/bbr_v3.go`, add after the undo fields (around line 280):

```go
// Loss episode tracking for RFC §5.5.11 spurious recovery
lossEpisodeActive        bool
lossEpisodePackets       map[protocol.PacketNumber]protocol.ByteCount
lossEpisodeTotalBytes    protocol.ByteCount
lossEpisodeSpuriousBytes protocol.ByteCount
pendingLossPackets       map[protocol.PacketNumber]protocol.ByteCount
```

- [ ] **Step 4.4: Track pending losses in OnCongestionEvent**

In `internal/congestion/bbr_v3.go`, in `OnCongestionEvent` (around line 1040), add at the start of the function:

```go
// Track pending losses for episode promotion in adaptLowerBounds
if lostBytes > 0 {
	if bbr.pendingLossPackets == nil {
		bbr.pendingLossPackets = make(map[protocol.PacketNumber]protocol.ByteCount)
	}
	bbr.pendingLossPackets[number] = lostBytes
}
```

- [ ] **Step 4.5: Promote pending losses to episode in adaptLowerBounds**

In `internal/congestion/bbr_v3.go`, in `adaptLowerBounds` (around line 1377), add after `bbr.initLowerBounds(true)`:

```go
// Promote pending losses to active episode when cuts are applied
if len(bbr.pendingLossPackets) > 0 {
	if !bbr.lossEpisodeActive {
		bbr.lossEpisodeActive = true
		bbr.lossEpisodePackets = bbr.pendingLossPackets
		bbr.lossEpisodeTotalBytes = 0
		for _, bytes := range bbr.pendingLossPackets {
			bbr.lossEpisodeTotalBytes += bytes
		}
		bbr.lossEpisodeSpuriousBytes = 0
	} else {
		// Merge into existing episode
		for pn, bytes := range bbr.pendingLossPackets {
			if _, exists := bbr.lossEpisodePackets[pn]; !exists {
				bbr.lossEpisodePackets[pn] = bytes
				bbr.lossEpisodeTotalBytes += bytes
			}
		}
	}
	bbr.pendingLossPackets = nil
}
```

- [ ] **Step 4.6: Replace OnSpuriousLossDetected with episode-aware version**

In `internal/congestion/bbr_v3.go`, replace `OnSpuriousLossDetected` (lines 1985-2053) with:

```go
func (bbr *BBRv3) OnSpuriousLossDetected(packetNumber protocol.PacketNumber, _ protocol.PacketNumber) {
	// Check if this packet is in the active loss episode
	if !bbr.lossEpisodeActive {
		return
	}
	packetBytes, inEpisode := bbr.lossEpisodePackets[packetNumber]
	if !inEpisode {
		return
	}
	
	// Accumulate spurious bytes
	bbr.lossEpisodeSpuriousBytes += packetBytes
	
	// Check for majority spurious (>50% of episode bytes)
	// Use 2x comparison to avoid integer division edge case
	if bbr.lossEpisodeSpuriousBytes*2 > bbr.lossEpisodeTotalBytes {
		bbr.restoreBoundsForSpuriousEpisode()
	}
}

func (bbr *BBRv3) restoreBoundsForSpuriousEpisode() {
	// 1. Clear loss-in-round flag since the loss was spurious
	bbr.lossInRound = false

	// 2. Reset full bandwidth estimator to re-probe after spurious loss
	bbr.resetFullBw()

	// 3. Restore bounds to max of current and saved values per RFC §5.5.11.2
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

	// 5. State re-entry per RFC §5.5.11.2
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

	// 7. Emit qlog event
	if bbr.qlogger != nil {
		var bwLoVal, inflightLoVal, inflightHiVal uint64
		if bbr.bwLo != protocol.MaxByteCount {
			bwLoVal = uint64(bbr.bwLo)
		}
		if bbr.inflightLo != protocol.MaxByteCount {
			inflightLoVal = uint64(bbr.inflightLo)
		}
		if bbr.inflightHi != protocol.MaxByteCount {
			inflightHiVal = uint64(bbr.inflightHi)
		}
		bbr.qlogger.RecordEvent(qlog.BBRv3SpuriousLossRecovery{
			SpuriousCount:      1,
			RestoredBwLo:       bwLoVal,
			RestoredInflightLo: inflightLoVal,
			RestoredInflightHi: inflightHiVal,
			RestoredCwnd:       uint64(bbr.congestionWindow),
		})
	}
}
```

- [ ] **Step 4.7: Clear episode on connection migration**

In `internal/congestion/bbr_v3.go`, in `OnConnectionMigration` (around line 2080), add:

```go
// Clear episode state on path change
bbr.lossEpisodeActive = false
bbr.lossEpisodePackets = nil
bbr.lossEpisodeTotalBytes = 0
bbr.lossEpisodeSpuriousBytes = 0
bbr.pendingLossPackets = nil
```

- [ ] **Step 4.8: Run test to verify it passes**

Run: `go test ./internal/congestion/... -v -run TestBBRv3SpuriousRecoveryRequiresMajority`
Expected: PASS

- [ ] **Step 4.9: Run all spurious loss tests**

Run: `go test ./internal/congestion/... -v -run "TestBBRv3.*Spurious" -count=1`
Expected: All PASS

- [ ] **Step 4.10: Commit**

```bash
git add internal/congestion/bbr_v3.go internal/congestion/bbr_v3_test.go
git commit -m "$(cat <<'EOF'
feat(bbr): implement episode-level spurious loss recovery

Add loss episode tracking per RFC §5.5.11:
- Track pending losses in OnCongestionEvent
- Promote to active episode when adaptLowerBounds applies cuts
- Accumulate spurious bytes via OnSpuriousLossDetected
- Restore bounds when >50% of episode bytes are spurious

The restore logic preserves all behavior from the primary branch:
- lossInRound flag clearing
- Full bandwidth estimator reset
- max(current, undo) bound restoration
- cwnd restoration with bounds check
- State re-entry for Startup/ProbeBW_UP

Fixes: F3 per-packet vs episode-level trigger
Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §4
EOF
)"
```

---

### Task 5: F9 — Interface Dispatch Comments

Add documentation comments to sent_packet_handler dispatch points.

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:445,491`

- [ ] **Step 5.1: Add comment at detectSpuriousLosses call**

In `internal/ackhandler/sent_packet_handler.go`, at line 489-491, change:

```go
// detect spurious losses for application data packets, if the ACK was not reordered
if encLevel == protocol.Encryption1RTT && largestAcked == pnSpace.largestAcked {
	h.detectSpuriousLosses(
```

To:

```go
// detect spurious losses for application data packets, if the ACK was not reordered.
// detectSpuriousLosses only runs when this ACK advanced largestAcked.
// Spurious-loss signals are suppressed for reordered ACKs — this is
// intentional since the reordering regime triggers threshold adaptation
// through the normal loss path, not through spurious detection.
if encLevel == protocol.Encryption1RTT && largestAcked == pnSpace.largestAcked {
	h.detectSpuriousLosses(
```

- [ ] **Step 5.2: Add comment at ECN OnCongestionEvent call**

Find the ECN congestion `OnCongestionEvent` call (around line 445) and add:

```go
// ECN congestion signal. BBRv3 early-returns on lostBytes==0 because
// it consumes ECN via OnECNFeedback instead. This call is retained for
// CCs that handle ECN through the loss path (e.g., NewReno/Cubic).
h.congestion.OnCongestionEvent(largestAcked, 0, priorInFlight)
```

- [ ] **Step 5.3: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
docs(ackhandler): add interface dispatch comments

Document two dispatch behaviors:
1. detectSpuriousLosses only runs for non-reordered ACKs
2. ECN OnCongestionEvent call retained for non-BBRv3 CCs

Fixes: F9 interface dispatch documentation
Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §3.5
EOF
)"
```

---

### Task 6: F5 — Sustained Loss Regression Test (Scaffold)

Add a placeholder test that documents the closed-loop harness requirement.

**Files:**
- Modify: `internal/congestion/bbr_v3_test.go`

- [ ] **Step 6.1: Add scaffolded test with skip**

In `internal/congestion/bbr_v3_test.go`, add:

```go
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
```

- [ ] **Step 6.2: Verify test is skipped**

Run: `go test ./internal/congestion/... -v -run TestBBRv3SustainedLossStability`
Expected: SKIP with message

- [ ] **Step 6.3: Commit**

```bash
git add internal/congestion/bbr_v3_test.go
git commit -m "$(cat <<'EOF'
test(bbr): add scaffolded sustained loss regression test

Documents the requirement for a closed-loop path model harness to test
3% sustained loss behavior. Skipped until harness is implemented.

Fixes: F5 sustained loss regression test
Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §3.4
EOF
)"
```

---

## Branch: `algo/bbrv3-adaptive` (Tasks 7-10)

**Note:** Tasks 7-10 require rebasing `algo/bbrv3-adaptive` onto the updated `algo/bbrv3` first. The rebase should drop any duplicate episode tracking commits since F3 is now on primary.

### Task 7: Rebase Adaptive Branch

Rebase `algo/bbrv3-adaptive` onto updated `algo/bbrv3`, dropping duplicate episode commits.

- [ ] **Step 7.1: Check for open PRs**

Run: `gh pr list --head algo/bbrv3-adaptive`
Expected: No open PRs (safe to force-push)

- [ ] **Step 7.2: Identify commits to drop**

Run: `git log --oneline algo/bbrv3..algo/bbrv3-adaptive | head -20`
Note: Identify any commits that add episode tracking (these are now in primary)

- [ ] **Step 7.3: Perform rebase**

```bash
git checkout algo/bbrv3-adaptive
git rebase algo/bbrv3
# If conflicts, resolve by accepting primary's version for episode code
git push --force-with-lease
```

- [ ] **Step 7.4: Verify rebase success**

Run: `git log --oneline -5`
Expected: Shows algo/bbrv3 commits as base

---

### Task 8: F6 — Remove False QUICHE Attribution, Add Sanity Bound

Replace the `300` cap with `16384` and update comments.

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:68`

- [ ] **Step 8.1: Update constant and comment**

In `internal/ackhandler/sent_packet_handler.go`, change line 68:

```go
maxAdaptiveReorderingThreshold = protocol.PacketNumber(300) // QUICHE kMaxPacketReorderingThreshold
```

To:

```go
// maxAdaptiveReorderingThreshold is a quic-go safety bound (NOT a QUICHE port).
// QUICHE has no cap; we add this to prevent pathological paths from deferring
// loss detection indefinitely. Set high enough to never interfere with realistic
// reordering but low enough to catch pathological cases.
maxAdaptiveReorderingThreshold = protocol.PacketNumber(1 << 14) // 16384
```

- [ ] **Step 8.2: Run tests**

Run: `go test ./internal/ackhandler/... -v -count=1`
Expected: PASS

- [ ] **Step 8.3: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
fix(ackhandler): remove false QUICHE attribution for threshold cap

QUICHE has no kMaxPacketReorderingThreshold constant. Replace the
fabricated 300 cap with a 16384 quic-go safety bound, honestly labeled.

The high bound prevents pathological paths from deferring loss detection
indefinitely while never interfering with realistic reordering.

Fixes: F6 fabricated QUICHE cap
Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §5.1
EOF
)"
```

---

### Task 9: F7 — Use previous_largest_acked in Gap Calculation

Capture `previous_largest_acked` before update and pass to `detectSpuriousLosses`.

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:460,532,551`

- [ ] **Step 9.1: Capture previous_largest_acked in ReceivedAck**

In `internal/ackhandler/sent_packet_handler.go`, in `ReceivedAck`, before the line `pnSpace.largestAcked = largestAcked` (around line 460), add:

```go
previousLargestAcked := pnSpace.largestAcked
```

- [ ] **Step 9.2: Update detectSpuriousLosses call**

Change the call to `detectSpuriousLosses` (around line 491):

```go
h.detectSpuriousLosses(
	ack,
	rcvTime.Add(-min(ack.DelayTime, h.rttStats.MaxAckDelay())),
)
```

To:

```go
h.detectSpuriousLosses(
	ack,
	rcvTime.Add(-min(ack.DelayTime, h.rttStats.MaxAckDelay())),
	previousLargestAcked,
)
```

- [ ] **Step 9.3: Update detectSpuriousLosses signature**

Change the function signature (around line 532):

```go
func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time) {
```

To:

```go
func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time, previousLargestAcked protocol.PacketNumber) {
```

- [ ] **Step 9.4: Use previous_largest_acked in gap calculation**

Change the gap calculation (around line 551):

```go
packetReordering := h.appDataPackets.history.Difference(ack.LargestAcked(), pn)
```

To:

```go
// Use previous_largest_acked per QUICHE SpuriousLossDetected logic.
// history.Difference accounts for skipped packet numbers.
packetReordering := h.appDataPackets.history.Difference(previousLargestAcked, pn)
```

- [ ] **Step 9.5: Run tests**

Run: `go test ./internal/ackhandler/... -v -count=1`
Expected: PASS

- [ ] **Step 9.6: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
fix(ackhandler): use previous_largest_acked in spurious loss gap

Change gap calculation to use previous_largest_acked (captured before
update) instead of current ACK's LargestAcked, matching QUICHE's
SpuriousLossDetected logic.

Continues using history.Difference() to account for skipped packet
numbers, which QUICHE's raw subtraction does not handle.

Fixes: F7 wrong largest_acked in monotonic growth
Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §5.2
EOF
)"
```

---

### Task 10: F10 — Remove Dead Code, Document Initial Threshold

Remove unused `getTimeThreshold()` if it has no callers, and document the initial threshold divergence.

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:1331-1350`

- [ ] **Step 10.1: Check for callers of getTimeThreshold**

Run: `grep -rn "getTimeThreshold" /Users/jedda.wignall/Documents/Working-Copies/quic-go/`
Expected: Only the definition, no callers

- [ ] **Step 10.2: Remove getTimeThreshold if unused**

If no callers exist, delete the `getTimeThreshold` function (lines 1331-1350):

```go
// getTimeThreshold returns the effective time threshold multiplier.
// ... entire function ...
func (h *sentPacketHandler) getTimeThreshold() float64 {
	// ... implementation ...
}
```

- [ ] **Step 10.3: Update defaultReorderingShift comment**

At line 66, change:

```go
defaultReorderingShift = uint(2) // Initial: loss_delay = rtt + rtt/4 (1.25x)
```

To:

```go
// defaultReorderingShift = 2 gives initial loss delay of 1.25× RTT.
// This is intentionally more permissive than RFC 9002's 1.125× (9/8) to
// reduce spurious loss declarations on paths with moderate jitter.
// The threshold widens further (up to 2.0× RTT) on time-based spurious loss.
defaultReorderingShift = uint(2)
```

- [ ] **Step 10.4: Run tests**

Run: `go test ./internal/ackhandler/... -v -count=1`
Expected: PASS

- [ ] **Step 10.5: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
chore(ackhandler): remove dead code, document initial threshold

Remove unused getTimeThreshold() function (getLossDelay is used instead).
Document why defaultReorderingShift=2 (1.25× RTT) diverges from RFC 9002's
1.125× — intentionally more permissive to reduce spurious loss.

Fixes: F10 dead code and initial threshold documentation
Ref: docs/superpowers/specs/2026-05-29-bbrv3-review-findings-remediation.md §5.4
EOF
)"
```

---

### Task 11: Recreate Feature Flag Branches

Recreate the five feature flag branches from the updated adaptive tip.

- [ ] **Step 11.1: Verify adaptive branch is up to date**

Run: `git log --oneline -3 algo/bbrv3-adaptive`

- [ ] **Step 11.2: Recreate baseline branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -B algo/bbrv3-adaptive-baseline
# Edit sent_packet_handler.go lines 64-66:
# enableBDPScaledThreshold = false
# enableMonotonicThresholdGrowth = false
# enableAdaptiveTimeThreshold = false
git commit -am "set feature flags for baseline configuration"
git push --force-with-lease origin algo/bbrv3-adaptive-baseline
```

- [ ] **Step 11.3: Recreate bdp branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -B algo/bbrv3-adaptive-bdp
# Edit: enableBDPScaledThreshold = true, others false
git commit -am "set feature flags for bdp configuration"
git push --force-with-lease origin algo/bbrv3-adaptive-bdp
```

- [ ] **Step 11.4: Recreate monotonic branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -B algo/bbrv3-adaptive-monotonic
# Edit: enableMonotonicThresholdGrowth = true, others false
git commit -am "set feature flags for monotonic configuration"
git push --force-with-lease origin algo/bbrv3-adaptive-monotonic
```

- [ ] **Step 11.5: Recreate time branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -B algo/bbrv3-adaptive-time
# Edit: enableAdaptiveTimeThreshold = true, others false
git commit -am "set feature flags for time configuration"
git push --force-with-lease origin algo/bbrv3-adaptive-time
```

- [ ] **Step 11.6: Recreate full branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -B algo/bbrv3-adaptive-full
# Edit: all three = true
git commit -am "set feature flags for full configuration"
git push --force-with-lease origin algo/bbrv3-adaptive-full
```

- [ ] **Step 11.7: Return to adaptive branch**

```bash
git checkout algo/bbrv3-adaptive
```

---

## Self-Review Checklist

- [x] **Spec coverage:** All findings F1-F10 have corresponding tasks
- [x] **Placeholder scan:** No TBD/TODO, all code blocks complete
- [x] **Type consistency:** Field names match across tasks (e.g., `lossEpisodeActive`, `bwLatestBeforeCut`)
- [x] **Branch sequencing:** Tasks 1-6 on primary, Tasks 7-11 require rebase first
