# Adaptive Packet Reordering Threshold for BBRv3

**Date:** 2026-05-25  
**Branch:** `algo/bbrv3-adaptive`  
**Status:** Design approved after cross-review, pending implementation  
**Cross-Review:** Completed Round 6 with Codex (Agent B) — all findings resolved

---

## 1. Problem Statement

The quic-go BBRv3 implementation suffers from throughput collapse under packet reordering. At 25% netem reordering, throughput drops from ~890 Mbps to ~50 Mbps (94% reduction).

**Root cause:** RFC 9002's default packet reordering threshold of 3 causes reordered packets to be misclassified as lost. This triggers BBR's loss response, which sets `bwLo`/`inflightLo` bounds. These bounds constrain pacing rate, producing low delivery-rate samples that pollute the `max_bw` filter, causing unrecoverable collapse.

**Reference:** See `docs/bbrv3-validation-investigation.md` for full analysis.

**Scope clarification:** This spec addresses reordering-induced collapse only. The 3% real loss collapse (caused by `max_bw` filter pollution from self-limited samples) is a separate issue requiring a different fix (sampling gate) and is explicitly out of scope.

---

## 2. Solution Overview

Implement three complementary adaptive mechanisms, feature-flagged for A/B testing:

1. **BDP-scaled packet threshold (ngtcp2-style):** Threshold scales with bytes-in-flight
2. **Monotonic packet threshold growth (QUICHE-style):** Threshold grows on spurious loss detection
3. **Adaptive time threshold (QUICHE-style):** Time threshold widens on time-based spurious loss

Plus BBR-specific spurious loss recovery with per-packet episode tracking.

---

## 3. Design Decisions

### 3.1 Implementation Location

**Decision:** Implement adaptive thresholds directly in `sent_packet_handler.go`.

**Rationale:** The research is explicit that loss detection should be CC-agnostic. All major implementations (ngtcp2, QUICHE, Cloudflare quiche) keep adaptive thresholds in the loss detector, not the congestion controller. CCs only implement spurious-loss notification handlers for model recovery.

**Future architecture:** Loss detection owns adaptive thresholds. CCs implement `SpuriousLossHandler` for model recovery only. The existing `PacketReorderingThresholdProvider` interface should be removed or repurposed — it should NOT be used for CC-owned adaptive logic.

### 3.2 Feature Flags

All mechanisms are independently toggleable via constants for A/B testing:

```go
enableBDPScaledThreshold       = true   // ngtcp2-style packet threshold
enableMonotonicThresholdGrowth = true   // QUICHE-style packet threshold growth
enableAdaptiveTimeThreshold    = true   // QUICHE-style time threshold (reorderingShift)
```

### 3.3 BBR Recovery Scope

**Decision:** Byte-weighted per-packet episode tracking with majority threshold.

**Rationale:** Unconditional reset on any spurious loss risks erasing legitimate congestion responses on paths with mixed real loss and reordering. Instead, track which specific packets contributed to lower-bound cuts, and only restore bounds when the majority (>50%) of those cut-triggering bytes were spurious.

### 3.4 bytesInFlight Restoration

**Decision:** Do NOT restore `bytesInFlight` on spurious loss detection.

**Rationale:** This is a deliberate deviation from QUICHE-style full recovery. Precise restoration requires frame-level retransmission tracking (knowing whether replacement data has been sent). quic-go's frame handlers don't currently track this, and implementing it would require invasive changes across the framing logic. Per user constraint: keep implementation narrow, minimize codebase touchpoints.

**Why this is acceptable:**
- The primary fix is adaptive thresholds + BBR `bwLo`/`inflightLo` recovery
- Not restoring `bytesInFlight` is conservative (under-reports inflight, sender is more cautious)
- If Pacemaker testing shows degradation, revisit with proper frame-level tracking

### 3.5 Why Both Packet AND Time Thresholds

Packet and time thresholds are not mutually exclusive. In `detectLostPackets()`:
- Time threshold is checked first
- Packet threshold is checked second

Raising only the packet threshold doesn't prevent loss declaration if the time threshold also fires. After adaptive packet threshold prevents immediate packet-threshold loss, a reordered packet may simply remain outstanding longer and trip the time threshold instead. This is why QUICHE adapts both `reordering_threshold_` AND `reordering_shift_`.

---

## 4. Detailed Design

### 4.1 Constants and Feature Flags

**Location:** `internal/ackhandler/sent_packet_handler.go`

```go
const (
    // ==========================================================================
    // ADAPTIVE PACKET REORDERING THRESHOLD
    // ==========================================================================
    //
    // Feature flags for A/B testing adaptive loss detection thresholds.
    //
    // Implementation landscape:
    //
    // 1. ngtcp2 (lib/ngtcp2_rtb.c, ngtcp2_rtb_detect_lost_pkt):
    //    - Formula: threshold = max(3, min(256, bytes_in_flight / mtu / 2))
    //    - Stateless: recomputed on every ACK processing pass
    //    - Scales with BDP; naturally returns to 3 when window collapses
    //    - Used by: Firefox, curl, various IoT stacks
    //
    // 2. Google QUICHE (general_loss_algorithm.cc, SpuriousLossDetected):
    //    - Formula: threshold = max(threshold, largest_acked - packet_number + 1)
    //    - Stateful: monotonically grows on each spurious loss detection
    //    - Never decreases within connection, caps at 300
    //    - Used by: Chrome, Google production QUIC
    //
    // 3. Cloudflare quiche (src/recovery/mod.rs):
    //    - Constants: INITIAL_PACKET_THRESHOLD=3, MAX_PACKET_THRESHOLD=20
    //    - More conservative caps than ngtcp2/QUICHE
    //    - Used by: Cloudflare edge
    //
    // Our choice: Combine ngtcp2 BDP-scaling with QUICHE monotonic growth
    //
    // Why not Cloudflare's approach alone:
    // - MAX_PACKET_THRESHOLD=20 is too low for high-BDP mobile paths we target
    //
    // Why not ngtcp2 alone:
    // - BDP-scaling doesn't capture persistent path-specific reordering patterns

    enableBDPScaledThreshold       = true  // threshold = bytesInFlight / mtu / 2
    enableMonotonicThresholdGrowth = true  // threshold grows on spurious loss
    enableAdaptiveTimeThreshold    = true  // QUICHE-style reorderingShift

    maxAdaptiveReorderingThreshold = 300   // QUICHE kMaxPacketReorderingThreshold
    maxBDPScaledThreshold          = 256   // ngtcp2 cap

    defaultReorderingShift = 2  // Initial: loss_delay = rtt + rtt/4 (1.25x)
    minReorderingShift     = 0  // Most permissive: loss_delay = 2*rtt
)
```

### 4.2 State Tracking

**Location:** `internal/ackhandler/sent_packet_handler.go`

```go
type sentPacketHandler struct {
    // ... existing fields ...

    // ==========================================================================
    // ADAPTIVE THRESHOLD STATE
    // ==========================================================================
    //
    // These fields support adaptive packet reordering thresholds per research
    // into ngtcp2 and QUICHE implementations.
    
    // adaptiveReorderingThreshold tracks the monotonically growing packet
    // threshold based on observed spurious losses. QUICHE-style: only grows,
    // never shrinks within a connection. Reset on path migration.
    adaptiveReorderingThreshold protocol.PacketNumber

    // reorderingShift controls adaptive time threshold. QUICHE-style:
    // loss_delay = rtt + (rtt >> shift). Decreases (widens) on time-based
    // spurious loss. shift=2: 1.25x, shift=1: 1.5x, shift=0: 2.0x
    reorderingShift uint

    // maxDatagramSize cached for BDP-scaled threshold calculation.
    maxDatagramSize protocol.ByteCount
}
```

**Initialization:**
- `adaptiveReorderingThreshold = packetThreshold` (3)
- `reorderingShift = defaultReorderingShift` (2)
- `maxDatagramSize = initialMaxDatagramSize`

**Reset on migration:** Both `adaptiveReorderingThreshold` and `reorderingShift` reset to defaults.

### 4.3 Packet Threshold Calculation

**Location:** `internal/ackhandler/sent_packet_handler.go`

```go
// getPacketReorderingThreshold returns the effective packet reordering threshold.
//
// Implementation landscape:
// - ngtcp2: stateless BDP scaling (bytesInFlight / mtu / 2)
// - QUICHE: stateful monotonic growth on spurious loss
//
// Our choice: Use maximum of both, giving immediate BDP tolerance plus
// learned path-specific reordering patterns.
func (h *sentPacketHandler) getPacketReorderingThreshold() protocol.PacketNumber {
    threshold := protocol.PacketNumber(packetThreshold) // RFC 9002 default: 3

    if enableBDPScaledThreshold && h.maxDatagramSize > 0 {
        bdpThreshold := protocol.PacketNumber(h.bytesInFlight / h.maxDatagramSize / 2)
        bdpThreshold = max(packetThreshold, bdpThreshold)
        bdpThreshold = min(maxBDPScaledThreshold, bdpThreshold)
        threshold = bdpThreshold
    }

    if enableMonotonicThresholdGrowth {
        threshold = max(threshold, h.adaptiveReorderingThreshold)
    }

    return threshold
}
```

### 4.4 Time Threshold Calculation

**Location:** `internal/ackhandler/sent_packet_handler.go`

```go
// getTimeThreshold returns the effective time threshold multiplier.
//
// Implementation landscape:
// - RFC 9002: fixed 9/8 (1.125x RTT)
// - QUICHE: adaptive via reorderingShift, starts at 1.25x, widens to 2.0x
//
// Our choice: QUICHE-style adaptive, starting at 1.25x (slightly more
// permissive than RFC 9002) and widening on time-based spurious loss.
//
// Note: Moving from RFC 9002's 9/8 to 1.25x is intentional. Must verify
// via testing that this doesn't unacceptably delay real loss detection.
func (h *sentPacketHandler) getTimeThreshold() float64 {
    if !enableAdaptiveTimeThreshold {
        return timeThreshold // RFC 9002 default: 9/8 = 1.125
    }
    // QUICHE-style: 1 + (1 >> shift)
    // shift=2: 1.25, shift=1: 1.5, shift=0: 2.0
    return 1.0 + (1.0 / float64(uint(1)<<h.reorderingShift))
}
```

### 4.5 Monotonic Threshold Growth on Spurious Loss

**Location:** `internal/ackhandler/sent_packet_handler.go`

Update `detectSpuriousLosses()` to:
1. Grow packet threshold based on observed reordering gap
2. Widen time threshold if time-based spurious loss detected
3. Notify congestion controller with spurious byte count

```go
func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time) {
    // ... existing spurious detection logic ...

    // After detecting spurious losses:
    
    // Grow packet threshold (QUICHE-style monotonic)
    if enableMonotonicThresholdGrowth && maxPacketReordering > 0 {
        newThreshold := min(maxPacketReordering+1, maxAdaptiveReorderingThreshold)
        if newThreshold > h.adaptiveReorderingThreshold {
            h.adaptiveReorderingThreshold = newThreshold
        }
    }

    // Widen time threshold if needed (QUICHE-style reorderingShift)
    if enableAdaptiveTimeThreshold && maxTimeReordering > 0 {
        maxRTT := max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT())
        for h.reorderingShift > minReorderingShift {
            currentThreshold := h.getTimeThreshold()
            if float64(maxRTT)*currentThreshold >= float64(maxTimeReordering) {
                break
            }
            h.reorderingShift--
        }
    }

    // Notify congestion controller with byte count for episode accounting
    if len(spuriousLosses) > 0 {
        if slh, ok := h.congestion.(congestion.SpuriousLossHandler); ok {
            for _, info := range spuriousLossInfo {
                slh.OnSpuriousLossDetected(info.pn, info.reordering, info.length)
            }
        }
    }
}
```

### 4.6 Extended Lost Packet Tracker

**Location:** `internal/ackhandler/lost_packet_tracker.go`

Extend to store packet length for CC spurious recovery accounting:

```go
type lostPacketInfo struct {
    PacketNumber protocol.PacketNumber
    SendTime     monotime.Time
    Length       protocol.ByteCount  // For spurious recovery byte accounting
}
```

### 4.7 BBR Spurious Loss Recovery with Episode Tracking

**Location:** `internal/congestion/bbr_v3.go`

**Interface change** (`internal/congestion/interface.go`):

```go
type SpuriousLossHandler interface {
    OnSpuriousLossDetected(
        packetNumber protocol.PacketNumber,
        packetReordering protocol.PacketNumber,
        spuriousBytes protocol.ByteCount,  // For byte-weighted episode accounting
    )
}
```

**BBR state for episode tracking:**

```go
type BBRv3 struct {
    // ... existing fields ...

    // ==========================================================================
    // SPURIOUS LOSS RECOVERY - Per-Packet Episode Tracking
    // ==========================================================================
    //
    // Tracks which packets/bytes contributed to actual lower-bound cuts.
    // Spurious recovery only restores bounds when the majority of cut-triggering
    // bytes were spurious, preventing erasure of legitimate congestion responses
    // on paths with mixed real loss and reordering.
    //
    // Implementation reference: QUICHE bbr2_misc.cc (conceptually)
    // Deviation: We track per-packet for precision; QUICHE tracks per-event

    // Pending: packets from OnCongestionEvent awaiting round boundary
    pendingLossPackets map[protocol.PacketNumber]protocol.ByteCount

    // Active episode: packets that contributed to actual bound cuts
    lossEpisodeActive        bool
    lossEpisodePackets       map[protocol.PacketNumber]protocol.ByteCount
    lossEpisodeTotalBytes    protocol.ByteCount
    lossEpisodeSpuriousBytes protocol.ByteCount
}
```

**Episode accounting in `OnCongestionEvent()` and `adaptLowerBounds()`:**

```go
func (bbr *BBRv3) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes protocol.ByteCount, _ protocol.ByteCount) {
    // ... existing logic ...
    
    // Track pending loss for episode accounting
    if bbr.pendingLossPackets == nil {
        bbr.pendingLossPackets = make(map[protocol.PacketNumber]protocol.ByteCount)
    }
    bbr.pendingLossPackets[packetNumber] = lostBytes
}

func (bbr *BBRv3) adaptLowerBounds(rs bbrRateSample) {
    if bbr.isProbingBandwidth() {
        bbr.pendingLossPackets = nil  // Probing skips cuts
        return
    }

    if bbr.lossInRound {
        // Actually applying cuts - promote pending to active episode
        if !bbr.lossEpisodeActive {
            bbr.lossEpisodeActive = true
            bbr.lossEpisodePackets = bbr.pendingLossPackets
            bbr.lossEpisodeTotalBytes = 0
            for _, bytes := range bbr.lossEpisodePackets {
                bbr.lossEpisodeTotalBytes += bytes
            }
            bbr.lossEpisodeSpuriousBytes = 0
        } else {
            for pn, bytes := range bbr.pendingLossPackets {
                bbr.lossEpisodePackets[pn] = bytes
                bbr.lossEpisodeTotalBytes += bytes
            }
        }
        bbr.pendingLossPackets = nil
        
        // Apply cuts (existing logic)
        // ...
    } else {
        bbr.pendingLossPackets = nil  // No cut - clear pending
    }
}
```

**Spurious loss recovery:**

```go
func (bbr *BBRv3) OnSpuriousLossDetected(
    packetNumber protocol.PacketNumber,
    packetReordering protocol.PacketNumber,
    spuriousBytes protocol.ByteCount,
) {
    if !bbr.lossEpisodeActive {
        return
    }

    // Only count if this packet contributed to the active episode
    episodeBytes, inEpisode := bbr.lossEpisodePackets[packetNumber]
    if !inEpisode {
        return
    }

    // Use episode-tracked bytes for consistency (ignore spuriousBytes arg)
    bbr.lossEpisodeSpuriousBytes += episodeBytes
    delete(bbr.lossEpisodePackets, packetNumber)

    // Restore if majority of cut-triggering losses were spurious
    if bbr.lossEpisodeSpuriousBytes > bbr.lossEpisodeTotalBytes/2 {
        bbr.resetLowerBounds()
    }
}

func (bbr *BBRv3) resetLowerBounds() {
    bbr.bwLo = protocol.MaxByteCount
    bbr.inflightLo = protocol.MaxByteCount
    // Clear episode state
    bbr.lossEpisodeActive = false
    bbr.lossEpisodePackets = nil
    bbr.lossEpisodeTotalBytes = 0
    bbr.lossEpisodeSpuriousBytes = 0
    bbr.pendingLossPackets = nil
}
```

**Reset on migration:**

```go
func (bbr *BBRv3) OnConnectionMigration(initialMaxDatagramSize protocol.ByteCount) {
    // ... existing reset logic ...
    bbr.resetLowerBounds()
    bbr.pendingLossPackets = nil  // Clear pending even if resetLowerBounds doesn't
}
```

### 4.8 Cleanup

- **Remove** BBR's `GetPacketReorderThreshold()` method
- **Remove** BBR's `packetReorderingThreshold` constant (the debug value of 1000)
- **Remove** diagnostic stderr logging from `sent_packet_handler.go`
- **Ensure** `SetMaxDatagramSize()` updates `h.maxDatagramSize`
- **Add** threshold reset in `MigratedPath()`

---

## 5. Test Plan

### 5.1 Test Branches for Pacemaker

| Branch | BDP-Scaled | Monotonic | Time | Purpose |
|--------|------------|-----------|------|---------|
| `algo/bbrv3-adaptive-baseline` | false | false | false | Control (RFC 9002) |
| `algo/bbrv3-adaptive-bdp` | true | false | false | BDP scaling only |
| `algo/bbrv3-adaptive-monotonic` | false | true | false | Monotonic growth only |
| `algo/bbrv3-adaptive-time` | false | false | true | Time threshold only |
| `algo/bbrv3-adaptive-full` | true | true | true | Full adaptive |

### 5.2 Expected Outcomes

| Scenario | Baseline | With Full Adaptive |
|----------|----------|-------------------|
| 25% reordering | ~50 Mbps (collapse) | ~800+ Mbps |
| Clean baseline | ~890 Mbps | ~890 Mbps (no regression) |
| 3% real loss | ~50 Mbps (collapse) | ~50 Mbps (out of scope) |

### 5.3 Unit Tests

1. `TestAdaptiveThresholdBDPScaling` - Threshold scales with bytesInFlight
2. `TestAdaptiveThresholdMonotonicGrowth` - Grows on spurious loss, never shrinks
3. `TestAdaptiveThresholdCaps` - Respects 256/300 caps
4. `TestAdaptiveTimeThreshold` - Shift decreases on time-based spurious loss
5. `TestBBREpisodeTracking` - Per-packet episode membership
6. `TestBBRSpuriousRecoveryMajorityThreshold` - Only restores when >50% spurious
7. `TestThresholdResetOnMigration` - Both thresholds reset on path migration
8. `TestLossDetectionLatencyAfterReordering` - Real losses still detected after high threshold

### 5.4 Telemetry Requirements

Record both packet-threshold and time-threshold eligibility before the if/else branch in `detectLostPackets()` to understand which threshold is firing. Add counterfactual test with high packet threshold to expose latent time-threshold losses.

---

## 6. Files Modified

| File | Changes |
|------|---------|
| `internal/ackhandler/sent_packet_handler.go` | Feature flags, state, threshold calculation, spurious detection |
| `internal/ackhandler/lost_packet_tracker.go` | Add Length field |
| `internal/congestion/bbr_v3.go` | Episode tracking, spurious recovery, remove static threshold |
| `internal/congestion/interface.go` | Update SpuriousLossHandler signature |

---

## 7. References

- **Research report:** `/Users/jedda.wignall/Downloads/compass_artifact_wf-c0782657-a66e-4581-9f57-3c48c5bd0231_text_markdown.md`
- **Investigation:** `docs/bbrv3-validation-investigation.md`
- **ngtcp2:** `lib/ngtcp2_rtb.c` — BDP-scaled threshold
- **QUICHE:** `general_loss_algorithm.cc` — Monotonic adaptation, `SpuriousLossDetected()`, `reordering_shift_`
- **RFC 9002:** QUIC Loss Detection and Congestion Control

---

## 8. Future Work

1. **bytesInFlight restoration:** Requires frame-level retransmission tracking. Revisit if Pacemaker shows issues.
2. **Per-path adaptation:** For multipath QUIC, thresholds should be path-local.
3. **max_bw sampling gate:** Separate spec for fixing 3% real loss collapse.

---

## 9. Implementation Documentation Standards

All adaptive threshold and spurious loss recovery code must include block comments documenting:

1. **Implementation landscape**: How major implementations (ngtcp2, Google QUICHE, Cloudflare quiche) approach this problem, including:
   - Specific file/function references
   - The formula or algorithm each uses
   - Key characteristics (stateless vs stateful, caps, etc.)
   - Who uses it in production

2. **Our choice**: Which approach(es) we adopted and how they combine

3. **Rationale**: Why this combination is appropriate for quic-go's target deployments

4. **Why not alternatives**: Explicit reasoning for approaches we considered but rejected

5. **Deviations**: Any differences from reference implementations, with justification

This standard exists because RFC 9002 permits but does not specify adaptive thresholds. Our implementation is based on research into production systems, not normative text.

---

## 10. Cross-Review Resolution Summary

| Finding | Severity | Resolution |
|---------|----------|------------|
| F1 | High | Skip bytesInFlight restoration — deliberate deviation, narrow scope constraint |
| F2 | High | Per-packet episode tracking with pending→active promotion at adaptLowerBounds() |
| F3 | High | CC-agnostic architecture — thresholds in loss detector, CCs only do model recovery |
| F4 | High | 3% real loss explicitly out of scope |
| F5 | Medium | Adaptive time threshold (reorderingShift) brought into scope |
| F6 | Medium | Reset thresholds on migration, added latency-after-reordering test |
