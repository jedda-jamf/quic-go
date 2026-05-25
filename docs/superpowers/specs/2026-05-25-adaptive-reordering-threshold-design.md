# Adaptive Packet Reordering Threshold for BBRv3

**Date:** 2026-05-25  
**Branch:** `algo/bbrv3-adaptive`  
**Status:** Design approved, pending implementation

---

## 1. Problem Statement

The quic-go BBRv3 implementation suffers from throughput collapse under packet reordering. At 25% netem reordering, throughput drops from ~890 Mbps to ~50 Mbps (94% reduction).

**Root cause:** RFC 9002's default packet reordering threshold of 3 causes reordered packets to be misclassified as lost. This triggers BBR's loss response, which sets `bwLo`/`inflightLo` bounds. These bounds constrain pacing rate, producing low delivery-rate samples that pollute the `max_bw` filter, causing unrecoverable collapse.

**Reference:** See `docs/bbrv3-validation-investigation.md` for full analysis.

---

## 2. Solution Overview

Implement two complementary adaptive threshold mechanisms, feature-flagged for A/B testing:

1. **BDP-scaled threshold (ngtcp2-style):** Threshold scales with bytes-in-flight
2. **Monotonic growth (QUICHE-style):** Threshold grows on spurious loss detection

Plus BBR-specific spurious loss recovery to reset `bwLo`/`inflightLo` bounds.

---

## 3. Design Decisions

### 3.1 Implementation Location

**Decision:** Implement adaptive thresholds directly in `sent_packet_handler.go` (experimental).

**Rationale:** The future-state architecture would have congestion controllers own threshold adaptation via the `PacketReorderingThresholdProvider` interface. However, the full shape of that interface is not finalized. For A/B testing purposes, implementing in the loss detection layer is acceptable.

**Future refactoring:** Once proven, extract threshold logic into the congestion controller interface to enable pluggable CC algorithms to own their threshold adaptation.

### 3.2 Feature Flags

Both mechanisms are independently toggleable via constants:

```go
enableBDPScaledThreshold       = true   // ngtcp2-style
enableMonotonicThresholdGrowth = true   // QUICHE-style
```

This enables four test configurations for Pacemaker.

### 3.3 BBR Recovery Scope

**Decision:** Reset `bwLo`/`inflightLo` unconditionally on any spurious loss detection.

**Rationale:** Simpler than tracking which specific loss events set the bounds. If spurious losses are occurring, the loss-driven bounds are not trustworthy anyway.

---

## 4. Detailed Design

### 4.1 Constants and Feature Flags

**Location:** `internal/ackhandler/sent_packet_handler.go`

```go
const (
    // ADAPTIVE PACKET REORDERING THRESHOLD - EXPERIMENTAL
    //
    // Feature flags for A/B testing. Once proven, this logic should be
    // refactored into the congestion controller interface.
    //
    // Reference implementations:
    //   - ngtcp2: lib/ngtcp2_rtb.c
    //   - QUICHE: general_loss_algorithm.cc

    enableBDPScaledThreshold       = true  // threshold = bytesInFlight / mtu / 2
    enableMonotonicThresholdGrowth = true  // threshold grows on spurious loss

    maxAdaptiveReorderingThreshold = 300   // QUICHE cap
    maxBDPScaledThreshold          = 256   // ngtcp2 cap
)
```

### 4.2 State Tracking

**Location:** `internal/ackhandler/sent_packet_handler.go`

Add to `sentPacketHandler` struct:

```go
// ADAPTIVE THRESHOLD STATE - EXPERIMENTAL
adaptiveReorderingThreshold protocol.PacketNumber  // Monotonic growth state
maxDatagramSize             protocol.ByteCount     // For BDP calculation
```

Initialize in constructor:
- `adaptiveReorderingThreshold = packetThreshold` (3)
- `maxDatagramSize = initialMaxDatagramSize`

### 4.3 Threshold Calculation

**Location:** `internal/ackhandler/sent_packet_handler.go`

New method `getPacketReorderingThreshold()`:

```
1. Start with RFC 9002 default (3)
2. If enableBDPScaledThreshold:
   threshold = max(3, min(256, bytesInFlight / maxDatagramSize / 2))
3. If enableMonotonicThresholdGrowth:
   threshold = max(threshold, adaptiveReorderingThreshold)
4. Return threshold
```

Update `detectLostPackets()` to call this method instead of using static `packetThreshold`.

### 4.4 Monotonic Threshold Growth

**Location:** `internal/ackhandler/sent_packet_handler.go`

Update `detectSpuriousLosses()`:

When spurious loss is detected with reordering gap `g`:
```go
if enableMonotonicThresholdGrowth && g > 0 {
    newThreshold := min(g + 1, maxAdaptiveReorderingThreshold)
    adaptiveReorderingThreshold = max(adaptiveReorderingThreshold, newThreshold)
}
```

The threshold only grows, never shrinks (monotonic).

### 4.5 BBR Spurious Loss Recovery

**Location:** `internal/congestion/bbr_v3.go`

Implement `SpuriousLossHandler` interface:

```go
func (bbr *BBRv3) OnSpuriousLossDetected(packetNumber, packetReordering protocol.PacketNumber) {
    bbr.bwLo = protocol.MaxByteCount
    bbr.inflightLo = protocol.MaxByteCount
    // qlog event for observability
}
```

This resets the short-term lower bounds to unconstrained, allowing BBR to resume probing at full estimated bandwidth.

### 4.6 Cleanup

- **Remove** BBR's `GetPacketReorderThreshold()` method (returns hardcoded 1000)
- **Remove** BBR's `packetReorderingThreshold` constant
- **Remove** diagnostic stderr logging from `sent_packet_handler.go`
- **Ensure** `SetMaxDatagramSize()` updates `h.maxDatagramSize`

---

## 5. Test Plan

### 5.1 Test Branches for Pacemaker

| Branch | BDP-Scaled | Monotonic | Purpose |
|--------|------------|-----------|---------|
| `algo/bbrv3-adaptive-baseline` | false | false | Control (RFC 9002) |
| `algo/bbrv3-adaptive-bdp` | true | false | BDP scaling only |
| `algo/bbrv3-adaptive-monotonic` | false | true | Monotonic growth only |
| `algo/bbrv3-adaptive-full` | true | true | Full adaptive |

### 5.2 Expected Outcomes

| Scenario | Baseline | With Adaptive |
|----------|----------|---------------|
| 25% reordering | ~50 Mbps (collapse) | ~800+ Mbps |
| 3% loss | ~50 Mbps (collapse) | Better recovery |
| Clean | ~890 Mbps | ~890 Mbps (no regression) |

### 5.3 Unit Tests

1. `TestAdaptiveThresholdBDPScaling` - Threshold scales with bytesInFlight
2. `TestAdaptiveThresholdMonotonicGrowth` - Grows on spurious loss, never shrinks
3. `TestAdaptiveThresholdCaps` - Respects 256/300 caps
4. `TestBBRSpuriousLossRecovery` - `bwLo`/`inflightLo` reset on spurious loss

---

## 6. Files Modified

| File | Changes |
|------|---------|
| `internal/ackhandler/sent_packet_handler.go` | Feature flags, state, threshold calculation, monotonic growth |
| `internal/congestion/bbr_v3.go` | Spurious loss recovery, remove static threshold |
| `internal/congestion/interface.go` | No changes (interfaces already exist) |

---

## 7. References

- **Research report:** `/Users/jedda.wignall/Downloads/compass_artifact_wf-c0782657-a66e-4581-9f57-3c48c5bd0231_text_markdown.md`
- **Investigation:** `docs/bbrv3-validation-investigation.md`
- **ngtcp2:** `lib/ngtcp2_rtb.c` — BDP-scaled threshold
- **QUICHE:** `general_loss_algorithm.cc` — Monotonic adaptation, `SpuriousLossDetected()`
- **RFC 9002:** QUIC Loss Detection and Congestion Control

---

## 8. Future Work

Once proven effective via Pacemaker testing:

1. Refactor adaptive threshold logic into `PacketReorderingThresholdProvider` interface
2. Allow congestion controllers to own threshold adaptation
3. Consider per-path adaptation for multipath QUIC
4. Evaluate `bytesInFlight` restoration on spurious loss (QUICHE does this)
