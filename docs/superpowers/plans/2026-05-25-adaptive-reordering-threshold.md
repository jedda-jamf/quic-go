# Adaptive Packet Reordering Threshold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement adaptive packet reordering thresholds to fix BBRv3 throughput collapse under reordering (94% drop at 25% netem reordering).

**Architecture:** Three mechanisms in loss detector (`sent_packet_handler.go`): BDP-scaled threshold (ngtcp2), monotonic growth (QUICHE), adaptive time threshold (QUICHE reorderingShift). BBR implements per-packet episode tracking for spurious loss recovery. CC-agnostic design: thresholds in loss detector, CCs only do model recovery.

**Tech Stack:** Go, quic-go internal packages, no external dependencies.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/ackhandler/sent_packet_handler.go` | Adaptive threshold state, calculation methods, spurious detection with byte counting |
| `internal/ackhandler/lost_packet_tracker.go` | Add `Length` field for byte accounting |
| `internal/congestion/interface.go` | Update `SpuriousLossHandler` signature with `spuriousBytes` |
| `internal/congestion/bbr_v3.go` | Episode tracking maps, spurious recovery with majority threshold |
| `internal/ackhandler/sent_packet_handler_test.go` | Unit tests for adaptive thresholds |
| `internal/congestion/bbr_v3_test.go` | Unit tests for episode tracking |

---

### Task 1: Extend lostPacketTracker with Length Field

**Files:**
- Modify: `internal/ackhandler/lost_packet_tracker.go:11-14`

- [ ] **Step 1: Write the failing test**

Create test file `internal/ackhandler/lost_packet_tracker_test.go`:

```go
package ackhandler

import (
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestLostPacketTrackerStoresLength(t *testing.T) {
	tracker := newLostPacketTracker(10)
	now := monotime.Now()
	
	tracker.Add(1, now, 1200)
	tracker.Add(2, now, 800)
	
	var lengths []protocol.ByteCount
	for _, _, length := range tracker.All() {
		lengths = append(lengths, length)
	}
	
	require.Equal(t, []protocol.ByteCount{1200, 800}, lengths)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/ackhandler/... -run TestLostPacketTrackerStoresLength`
Expected: FAIL with compilation error (Add takes 2 args, All yields 2 values)

- [ ] **Step 3: Update lostPacket struct to include Length**

In `internal/ackhandler/lost_packet_tracker.go`, change the struct:

```go
type lostPacket struct {
	PacketNumber protocol.PacketNumber
	SendTime     monotime.Time
	Length       protocol.ByteCount // For spurious recovery byte accounting
}
```

- [ ] **Step 4: Update Add method signature**

```go
func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time, length protocol.ByteCount) {
	if len(t.lostPackets) == t.maxLength {
		t.lostPackets = t.lostPackets[1:]
	}
	t.lostPackets = append(t.lostPackets, lostPacket{
		PacketNumber: p,
		SendTime:     sendTime,
		Length:       length,
	})
}
```

- [ ] **Step 5: Update All iterator to yield Length**

```go
func (t *lostPacketTracker) All() iter.Seq3[protocol.PacketNumber, monotime.Time, protocol.ByteCount] {
	return func(yield func(protocol.PacketNumber, monotime.Time, protocol.ByteCount) bool) {
		for _, p := range t.lostPackets {
			if !yield(p.PacketNumber, p.SendTime, p.Length) {
				return
			}
		}
	}
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test -v ./internal/ackhandler/... -run TestLostPacketTrackerStoresLength`
Expected: PASS

- [ ] **Step 7: Update call site in sent_packet_handler.go**

Find the `h.lostPackets.Add(pn, p.SendTime)` call in `detectLostPackets()` (around line 918) and update to:

```go
h.lostPackets.Add(pn, p.SendTime, p.Length)
```

- [ ] **Step 8: Run full ackhandler tests**

Run: `go test -v ./internal/ackhandler/...`
Expected: PASS (all existing tests)

- [ ] **Step 9: Commit**

```bash
git add internal/ackhandler/lost_packet_tracker.go internal/ackhandler/lost_packet_tracker_test.go internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
feat(ackhandler): add Length field to lost packet tracker

Add packet length tracking to lostPacketTracker for byte-weighted
spurious loss recovery. This enables the congestion controller to
account for spurious losses by bytes rather than packet count.
EOF
)"
```

---

### Task 2: Update SpuriousLossHandler Interface

**Files:**
- Modify: `internal/congestion/interface.go:68-70`

- [ ] **Step 1: Update the interface signature**

In `internal/congestion/interface.go`, change:

```go
// SpuriousLossHandler is implemented by congestion controllers that can react
// to packets that were spuriously declared lost.
type SpuriousLossHandler interface {
	OnSpuriousLossDetected(
		packetNumber protocol.PacketNumber,
		packetReordering protocol.PacketNumber,
		spuriousBytes protocol.ByteCount, // For byte-weighted episode accounting
	)
}
```

- [ ] **Step 2: Run tests to find compile errors**

Run: `go build ./...`
Expected: Compile error in bbr_v3.go (signature mismatch)

- [ ] **Step 3: Update BBR's OnSpuriousLossDetected signature**

In `internal/congestion/bbr_v3.go`, around line 1927, update:

```go
func (bbr *BBRv3) OnSpuriousLossDetected(
	_ protocol.PacketNumber,
	_ protocol.PacketNumber,
	_ protocol.ByteCount,
) {
```

- [ ] **Step 4: Update call site in sent_packet_handler.go**

In `detectSpuriousLosses()` around line 581-586, update:

```go
if slh, ok := h.congestion.(congestion.SpuriousLossHandler); ok {
	for _, pn := range spuriousLosses {
		packetReordering := h.appDataPackets.history.Difference(ack.LargestAcked(), pn)
		// Length is not yet available here - will be added in Task 4
		slh.OnSpuriousLossDetected(pn, packetReordering, 0)
	}
}
```

- [ ] **Step 5: Run full build and tests**

Run: `go build ./... && go test ./internal/congestion/... ./internal/ackhandler/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/congestion/interface.go internal/congestion/bbr_v3.go internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
feat(congestion): add spuriousBytes to SpuriousLossHandler interface

Extend OnSpuriousLossDetected with byte count parameter to support
byte-weighted spurious loss recovery in congestion controllers.
EOF
)"
```

---

### Task 3: Add Adaptive Threshold Constants and State

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:19-31` (constants)
- Modify: `internal/ackhandler/sent_packet_handler.go:68-118` (struct fields)

- [ ] **Step 1: Add feature flag constants after existing constants**

In `internal/ackhandler/sent_packet_handler.go`, after line 31 (after `maxPTODuration`), add:

```go
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

	maxAdaptiveReorderingThreshold = protocol.PacketNumber(300) // QUICHE kMaxPacketReorderingThreshold
	maxBDPScaledThreshold          = protocol.PacketNumber(256) // ngtcp2 cap

	defaultReorderingShift = uint(2) // Initial: loss_delay = rtt + rtt/4 (1.25x)
	minReorderingShift     = uint(0) // Most permissive: loss_delay = 2*rtt
```

- [ ] **Step 2: Add adaptive state fields to sentPacketHandler struct**

In the `sentPacketHandler` struct (after line 117, before the closing brace), add:

```go
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
```

- [ ] **Step 3: Initialize state in NewSentPacketHandler**

In `NewSentPacketHandler()`, in the struct initialization (around line 156-170), add these fields:

```go
	h := &sentPacketHandler{
		// ... existing fields ...
		adaptiveReorderingThreshold: packetThreshold,
		reorderingShift:             defaultReorderingShift,
		maxDatagramSize:             initialMaxDatagramSize,
	}
```

- [ ] **Step 4: Run build to verify no syntax errors**

Run: `go build ./internal/ackhandler/...`
Expected: PASS (compiles)

- [ ] **Step 5: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
feat(ackhandler): add adaptive threshold constants and state

Add feature flags and state fields for adaptive packet reordering
thresholds. Implements ngtcp2-style BDP scaling combined with
QUICHE-style monotonic growth on spurious loss.
EOF
)"
```

---

### Task 4: Implement Threshold Calculation Methods

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go` (add methods)
- Create: Test in `internal/ackhandler/sent_packet_handler_test.go`

- [ ] **Step 1: Write failing test for BDP-scaled threshold**

Add to `internal/ackhandler/sent_packet_handler_test.go`:

```go
func TestAdaptiveThresholdBDPScaling(t *testing.T) {
	// With 100KB in flight and 1200 byte MTU:
	// BDP threshold = 100000 / 1200 / 2 = 41
	h := &sentPacketHandler{
		bytesInFlight:               100000,
		maxDatagramSize:             1200,
		adaptiveReorderingThreshold: packetThreshold,
		reorderingShift:             defaultReorderingShift,
	}
	
	threshold := h.getPacketReorderingThreshold()
	require.GreaterOrEqual(t, threshold, protocol.PacketNumber(41))
	require.LessOrEqual(t, threshold, protocol.PacketNumber(256)) // BDP cap
}

func TestAdaptiveThresholdMonotonicGrowth(t *testing.T) {
	h := &sentPacketHandler{
		bytesInFlight:               1200, // Low BDP = threshold 3
		maxDatagramSize:             1200,
		adaptiveReorderingThreshold: 50, // Previously grown
		reorderingShift:             defaultReorderingShift,
	}
	
	threshold := h.getPacketReorderingThreshold()
	require.Equal(t, protocol.PacketNumber(50), threshold)
}

func TestAdaptiveThresholdCaps(t *testing.T) {
	h := &sentPacketHandler{
		bytesInFlight:               100000000, // Huge BDP
		maxDatagramSize:             1200,
		adaptiveReorderingThreshold: 500, // Above cap
		reorderingShift:             defaultReorderingShift,
	}
	
	threshold := h.getPacketReorderingThreshold()
	// Should be capped at maxAdaptiveReorderingThreshold (300)
	require.LessOrEqual(t, threshold, maxAdaptiveReorderingThreshold)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v ./internal/ackhandler/... -run TestAdaptiveThreshold`
Expected: FAIL (method not defined)

- [ ] **Step 3: Implement getPacketReorderingThreshold method**

Add after the `MigratedPath` method in `sent_packet_handler.go`:

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

	return min(threshold, maxAdaptiveReorderingThreshold)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v ./internal/ackhandler/... -run TestAdaptiveThreshold`
Expected: PASS

- [ ] **Step 5: Write test for adaptive time threshold**

```go
func TestAdaptiveTimeThreshold(t *testing.T) {
	h := &sentPacketHandler{
		reorderingShift: 2, // 1.25x
	}
	require.InDelta(t, 1.25, h.getTimeThreshold(), 0.01)
	
	h.reorderingShift = 1 // 1.5x
	require.InDelta(t, 1.5, h.getTimeThreshold(), 0.01)
	
	h.reorderingShift = 0 // 2.0x
	require.InDelta(t, 2.0, h.getTimeThreshold(), 0.01)
}
```

- [ ] **Step 6: Implement getTimeThreshold method**

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

- [ ] **Step 7: Run all threshold tests**

Run: `go test -v ./internal/ackhandler/... -run "TestAdaptiveThreshold|TestAdaptiveTime"`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go internal/ackhandler/sent_packet_handler_test.go
git commit -m "$(cat <<'EOF'
feat(ackhandler): implement adaptive threshold calculation methods

Add getPacketReorderingThreshold() combining ngtcp2 BDP-scaling with
QUICHE monotonic growth. Add getTimeThreshold() for QUICHE-style
adaptive time threshold via reorderingShift.
EOF
)"
```

---

### Task 5: Integrate Adaptive Thresholds into detectLostPackets

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:852-934` (detectLostPackets)

- [ ] **Step 1: Replace static threshold with adaptive method**

In `detectLostPackets()`, replace lines 855-858:

```go
// OLD:
packetReorderThreshold := protocol.PacketNumber(packetThreshold)
if pth, ok := h.congestion.(congestion.PacketReorderingThresholdProvider); ok {
	packetReorderThreshold = pth.GetPacketReorderThreshold()
}

// NEW:
packetReorderThreshold := h.getPacketReorderingThreshold()
```

- [ ] **Step 2: Replace static time threshold with adaptive method**

Replace line 861:

```go
// OLD:
lossDelay := time.Duration(timeThreshold * maxRTT)

// NEW:
lossDelay := time.Duration(h.getTimeThreshold() * maxRTT)
```

- [ ] **Step 3: Remove diagnostic stderr logging**

Remove the diagnostic logging block in `NewSentPacketHandler()` (lines 176-184):

```go
// DELETE these lines:
// Log effective packet reordering threshold at startup (unconditionally to stderr for diagnostics)
reorderThreshold := protocol.PacketNumber(packetThreshold)
implementsInterface := false
if pth, ok := cc.(congestion.PacketReorderingThresholdProvider); ok {
	reorderThreshold = pth.GetPacketReorderThreshold()
	implementsInterface = true
}
fmt.Fprintf(os.Stderr, "[quic-go] sent_packet_handler: packet_reorder_threshold=%d (default=%d, interface_detected=%v, cc_type=%T)\n",
	reorderThreshold, packetThreshold, implementsInterface, cc)
```

Also remove the `"os"` import if it's no longer needed.

- [ ] **Step 4: Run tests to verify no regressions**

Run: `go test -v ./internal/ackhandler/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
feat(ackhandler): integrate adaptive thresholds into loss detection

Replace static packetThreshold/timeThreshold with adaptive methods.
Remove CC-owned PacketReorderingThresholdProvider check - thresholds
now owned by loss detector per CC-agnostic architecture.
EOF
)"
```

---

### Task 6: Implement Spurious Loss Detection with Byte Tracking

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:542-588` (detectSpuriousLosses)

- [ ] **Step 1: Write test for spurious detection updating thresholds**

Add to test file:

```go
func TestSpuriousLossGrowsPacketThreshold(t *testing.T) {
	// Setup handler with low initial threshold
	h := &sentPacketHandler{
		adaptiveReorderingThreshold: 3,
		reorderingShift:             2,
		// ... minimal required fields
	}
	
	// Simulate spurious loss with gap of 10
	h.updateAdaptiveThresholds(10, 0)
	
	require.Equal(t, protocol.PacketNumber(11), h.adaptiveReorderingThreshold)
}

func TestSpuriousLossWidensTimeThreshold(t *testing.T) {
	h := &sentPacketHandler{
		reorderingShift: 2, // 1.25x
		rttStats:        &utils.RTTStats{},
	}
	h.rttStats.UpdateRTT(100*time.Millisecond, 0)
	
	// Spurious loss with time reordering exceeding current threshold
	// Current threshold at shift=2: 1.25 * 100ms = 125ms
	// If reordering was 150ms, shift should decrease
	h.updateAdaptiveThresholds(0, 150*time.Millisecond)
	
	require.Less(t, h.reorderingShift, uint(2))
}
```

- [ ] **Step 2: Extract threshold update logic into helper method**

Add new method:

```go
// updateAdaptiveThresholds grows thresholds based on observed spurious loss.
//
// Implementation landscape:
// - QUICHE: threshold = max(threshold, gap+1), caps at 300
// - QUICHE: reorderingShift decreases (widens time) on time-based spurious loss
func (h *sentPacketHandler) updateAdaptiveThresholds(maxPacketReordering protocol.PacketNumber, maxTimeReordering time.Duration) {
	// Grow packet threshold (QUICHE-style monotonic)
	if enableMonotonicThresholdGrowth && maxPacketReordering > 0 {
		newThreshold := min(maxPacketReordering+1, maxAdaptiveReorderingThreshold)
		if newThreshold > h.adaptiveReorderingThreshold {
			h.adaptiveReorderingThreshold = newThreshold
		}
	}

	// Widen time threshold if needed (QUICHE-style reorderingShift)
	if enableAdaptiveTimeThreshold && maxTimeReordering > 0 && h.rttStats != nil {
		maxRTT := max(h.rttStats.LatestRTT(), h.rttStats.SmoothedRTT())
		for h.reorderingShift > minReorderingShift {
			currentThreshold := h.getTimeThreshold()
			if time.Duration(float64(maxRTT)*currentThreshold) >= maxTimeReordering {
				break
			}
			h.reorderingShift--
		}
	}
}
```

- [ ] **Step 3: Update detectSpuriousLosses to track bytes and call update**

Refactor `detectSpuriousLosses()` to:

```go
func (h *sentPacketHandler) detectSpuriousLosses(ack *wire.AckFrame, ackTime monotime.Time) {
	var maxPacketReordering protocol.PacketNumber
	var maxTimeReordering time.Duration
	ackRangeIdx := len(ack.AckRanges) - 1

	type spuriousInfo struct {
		pn        protocol.PacketNumber
		reorder   protocol.PacketNumber
		length    protocol.ByteCount
	}
	var spuriousLosses []spuriousInfo

	for pn, sendTime, length := range h.lostPackets.All() {
		ackRange := ack.AckRanges[ackRangeIdx]
		for pn > ackRange.Largest {
			if ackRangeIdx == 0 {
				break
			}
			ackRangeIdx--
			ackRange = ack.AckRanges[ackRangeIdx]
		}
		if pn < ackRange.Smallest {
			continue
		}
		if pn <= ackRange.Largest {
			packetReordering := h.appDataPackets.history.Difference(ack.LargestAcked(), pn)
			timeReordering := ackTime.Sub(sendTime)
			maxPacketReordering = max(maxPacketReordering, packetReordering)
			maxTimeReordering = max(maxTimeReordering, timeReordering)

			if h.qlogger != nil {
				h.qlogger.RecordEvent(qlog.SpuriousLoss{
					EncryptionLevel:  protocol.Encryption1RTT,
					PacketNumber:     pn,
					PacketReordering: uint64(packetReordering),
					TimeReordering:   timeReordering,
				})
			}
			spuriousLosses = append(spuriousLosses, spuriousInfo{
				pn:      pn,
				reorder: packetReordering,
				length:  length,
			})
		}
	}

	// Remove from lost tracker
	for _, info := range spuriousLosses {
		h.lostPackets.Delete(info.pn)
	}

	// Update adaptive thresholds
	if len(spuriousLosses) > 0 {
		h.updateAdaptiveThresholds(maxPacketReordering, maxTimeReordering)

		// Notify congestion controller
		if slh, ok := h.congestion.(congestion.SpuriousLossHandler); ok {
			for _, info := range spuriousLosses {
				slh.OnSpuriousLossDetected(info.pn, info.reorder, info.length)
			}
		}
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test -v ./internal/ackhandler/... -run "TestSpuriousLoss"`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `go test ./internal/ackhandler/...`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go internal/ackhandler/sent_packet_handler_test.go
git commit -m "$(cat <<'EOF'
feat(ackhandler): implement spurious loss detection with threshold adaptation

Refactor detectSpuriousLosses to track packet lengths and update
adaptive thresholds on spurious loss. Implements QUICHE-style
monotonic packet threshold growth and reorderingShift time adaptation.
EOF
)"
```

---

### Task 7: Add Threshold Reset on Path Migration

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:1195-1225` (MigratedPath)

- [ ] **Step 1: Write test for threshold reset on migration**

```go
func TestThresholdResetOnMigration(t *testing.T) {
	h := &sentPacketHandler{
		adaptiveReorderingThreshold: 100,
		reorderingShift:             0, // Maximally widened
		// ... other required fields
	}
	
	h.resetAdaptiveThresholds()
	
	require.Equal(t, protocol.PacketNumber(packetThreshold), h.adaptiveReorderingThreshold)
	require.Equal(t, defaultReorderingShift, h.reorderingShift)
}
```

- [ ] **Step 2: Add resetAdaptiveThresholds helper**

```go
// resetAdaptiveThresholds resets adaptive thresholds to defaults.
// Called on path migration since new path may have different reordering characteristics.
func (h *sentPacketHandler) resetAdaptiveThresholds() {
	h.adaptiveReorderingThreshold = packetThreshold
	h.reorderingShift = defaultReorderingShift
}
```

- [ ] **Step 3: Call reset in MigratedPath**

In `MigratedPath()`, after `h.rttStats.ResetForPathMigration()` (line 1196), add:

```go
h.resetAdaptiveThresholds()
```

- [ ] **Step 4: Run tests**

Run: `go test -v ./internal/ackhandler/... -run TestThresholdReset`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go internal/ackhandler/sent_packet_handler_test.go
git commit -m "$(cat <<'EOF'
feat(ackhandler): reset adaptive thresholds on path migration

New paths may have different reordering characteristics, so reset
thresholds to defaults and let them adapt to the new path.
EOF
)"
```

---

### Task 8: Update SetMaxDatagramSize to Cache Value

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go:1105-1107` (SetMaxDatagramSize)

- [ ] **Step 1: Update SetMaxDatagramSize to cache the value**

```go
func (h *sentPacketHandler) SetMaxDatagramSize(s protocol.ByteCount) {
	h.maxDatagramSize = s
	h.congestion.SetMaxDatagramSize(s)
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/ackhandler/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "$(cat <<'EOF'
feat(ackhandler): cache maxDatagramSize for BDP-scaled threshold

Cache the max datagram size in sent_packet_handler for use in
BDP-scaled packet reordering threshold calculation.
EOF
)"
```

---

### Task 9: Add BBR Episode Tracking State

**Files:**
- Modify: `internal/congestion/bbr_v3.go` (add fields to struct)

- [ ] **Step 1: Add episode tracking fields to BBRv3 struct**

Find the BBRv3 struct definition and add after the existing loss-related fields:

```go
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

	// pendingLossPackets: packets from OnCongestionEvent awaiting round boundary
	pendingLossPackets map[protocol.PacketNumber]protocol.ByteCount

	// lossEpisodeActive: true when we have an active loss episode with bound cuts
	lossEpisodeActive bool

	// lossEpisodePackets: packets that contributed to actual bound cuts
	lossEpisodePackets map[protocol.PacketNumber]protocol.ByteCount

	// lossEpisodeTotalBytes: total bytes in the active loss episode
	lossEpisodeTotalBytes protocol.ByteCount

	// lossEpisodeSpuriousBytes: bytes determined to be spurious in active episode
	lossEpisodeSpuriousBytes protocol.ByteCount
```

- [ ] **Step 2: Run build**

Run: `go build ./internal/congestion/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3.go
git commit -m "$(cat <<'EOF'
feat(bbr): add per-packet episode tracking state

Add state fields for tracking loss episodes with byte-weighted
spurious loss recovery. Tracks pending losses awaiting round
boundary and active episode packets that triggered bound cuts.
EOF
)"
```

---

### Task 10: Implement Episode Accounting in OnCongestionEvent

**Files:**
- Modify: `internal/congestion/bbr_v3.go:855-903` (OnCongestionEvent)

- [ ] **Step 1: Write test for pending loss tracking**

Add to `bbr_v3_test.go`:

```go
func TestBBRPendingLossTracking(t *testing.T) {
	bbr := newTestBBRv3()
	
	// Simulate loss
	bbr.OnCongestionEvent(100, 1200, 0)
	
	require.NotNil(t, bbr.pendingLossPackets)
	require.Equal(t, protocol.ByteCount(1200), bbr.pendingLossPackets[100])
}
```

- [ ] **Step 2: Add pending loss tracking to OnCongestionEvent**

At the start of `OnCongestionEvent()`, after the collision check, add:

```go
	// Track pending loss for episode accounting
	if bbr.pendingLossPackets == nil {
		bbr.pendingLossPackets = make(map[protocol.PacketNumber]protocol.ByteCount)
	}
	bbr.pendingLossPackets[packetNumber] = lostBytes
```

- [ ] **Step 3: Run test**

Run: `go test -v ./internal/congestion/... -run TestBBRPendingLoss`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/congestion/bbr_v3.go internal/congestion/bbr_v3_test.go
git commit -m "$(cat <<'EOF'
feat(bbr): track pending losses in OnCongestionEvent

Record lost packets in pendingLossPackets map for later promotion
to active episode when adaptLowerBounds() applies bound cuts.
EOF
)"
```

---

### Task 11: Implement Episode Promotion in adaptLowerBounds

**Files:**
- Modify: `internal/congestion/bbr_v3.go:1361-1386` (adaptLowerBounds)

- [ ] **Step 1: Write test for episode promotion**

```go
func TestBBREpisodePromotion(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRProbeBW
	bbr.probeBWPhase = probeBWCruise // Not probing
	
	// Simulate pending loss
	bbr.pendingLossPackets = map[protocol.PacketNumber]protocol.ByteCount{
		100: 1200,
		101: 800,
	}
	bbr.lossInRound = true
	
	// Trigger adaptLowerBounds
	bbr.adaptLowerBounds(bbrRateSample{})
	
	require.True(t, bbr.lossEpisodeActive)
	require.Equal(t, protocol.ByteCount(2000), bbr.lossEpisodeTotalBytes)
	require.Nil(t, bbr.pendingLossPackets)
}
```

- [ ] **Step 2: Update adaptLowerBounds to promote pending to active**

Modify `adaptLowerBounds()`:

```go
func (bbr *BBRv3) adaptLowerBounds(bbrRateSample) {
	if bbr.isProbingBandwidth() {
		bbr.pendingLossPackets = nil // Probing skips cuts
		return
	}

	// Lower-bound adaptation:
	// - Loss drives multiplicative cuts of bw_lo/inflight_lo.
	// - ECN drives inflight_lo via ecn_alpha scaling.
	ecnInflightLo := protocol.MaxByteCount
	if bbr.ecnInRound && ECN_FACTOR > 0 {
		bbr.initLowerBounds(false)
		alphaFloat := float64(bbr.ecnAlpha) / float64(ECN_ALPHA_UNIT)
		ecnInflightLo = protocol.ByteCount(float64(bbr.inflightLo) * (1.0 - alphaFloat*ECN_FACTOR))
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
			// Merge pending into active episode
			for pn, bytes := range bbr.pendingLossPackets {
				bbr.lossEpisodePackets[pn] = bytes
				bbr.lossEpisodeTotalBytes += bytes
			}
		}
		bbr.pendingLossPackets = nil

		bbr.initLowerBounds(true)
		cut := 1.0 - BETA_REDUCTION
		bbr.bwLo = max(bbr.bwLatest, protocol.ByteCount(float64(bbr.bwLo)*cut))
		bbr.inflightLo = max(bbr.inflightLatest, protocol.ByteCount(float64(bbr.inflightLo)*cut))
	} else {
		bbr.pendingLossPackets = nil // No cut - clear pending
	}
	if ecnInflightLo != protocol.MaxByteCount {
		bbr.inflightLo = min(bbr.inflightLo, ecnInflightLo)
	}
	if bbr.bwLo == 0 {
		bbr.bwLo = 1
	}
}
```

- [ ] **Step 3: Run test**

Run: `go test -v ./internal/congestion/... -run TestBBREpisode`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/congestion/bbr_v3.go internal/congestion/bbr_v3_test.go
git commit -m "$(cat <<'EOF'
feat(bbr): implement episode promotion in adaptLowerBounds

When lower bounds are actually cut (lossInRound true, not probing),
promote pending losses to active episode. This tracks which packets
contributed to the actual bound cuts for precise spurious recovery.
EOF
)"
```

---

### Task 12: Implement Byte-Weighted Spurious Recovery

**Files:**
- Modify: `internal/congestion/bbr_v3.go:1914-1964` (OnSpuriousLossDetected)

- [ ] **Step 1: Write test for majority-threshold recovery**

```go
func TestBBRSpuriousRecoveryMajorityThreshold(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{
		100: 1000,
		101: 500,
		102: 500,
	}
	bbr.lossEpisodeTotalBytes = 2000
	bbr.lossEpisodeSpuriousBytes = 0
	bbr.bwLo = 1000
	bbr.inflightLo = 10000
	
	// First spurious: 1000 bytes (50%, not majority yet)
	bbr.OnSpuriousLossDetected(100, 10, 1000)
	require.True(t, bbr.lossEpisodeActive) // Not restored yet
	require.Equal(t, protocol.ByteCount(1000), bbr.bwLo) // Unchanged
	
	// Second spurious: 500 more bytes (75% total, majority)
	bbr.OnSpuriousLossDetected(101, 10, 500)
	require.False(t, bbr.lossEpisodeActive) // Restored
	require.Equal(t, protocol.MaxByteCount, bbr.bwLo) // Reset
}

func TestBBRSpuriousRecoveryIgnoresNonEpisodePackets(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.lossEpisodeActive = true
	bbr.lossEpisodePackets = map[protocol.PacketNumber]protocol.ByteCount{
		100: 1000,
	}
	bbr.lossEpisodeTotalBytes = 1000
	bbr.bwLo = 1000
	
	// Spurious packet NOT in episode
	bbr.OnSpuriousLossDetected(200, 10, 1000)
	
	// Should be unchanged
	require.True(t, bbr.lossEpisodeActive)
	require.Equal(t, protocol.ByteCount(0), bbr.lossEpisodeSpuriousBytes)
}
```

- [ ] **Step 2: Rewrite OnSpuriousLossDetected with episode tracking**

```go
// OnSpuriousLossDetected handles per-packet spurious loss notification.
//
// Implementation: Per-packet episode tracking with byte-weighted majority threshold.
// Only restores bounds when >50% of cut-triggering bytes were spurious, preventing
// erasure of legitimate congestion responses on paths with mixed real loss and reordering.
//
// Deviation from current behavior: The previous implementation restored bounds
// immediately on any spurious loss. This conservative approach waits for majority.
func (bbr *BBRv3) OnSpuriousLossDetected(
	packetNumber protocol.PacketNumber,
	_ protocol.PacketNumber,
	_ protocol.ByteCount,
) {
	if !bbr.lossEpisodeActive {
		return
	}

	// Only count if this packet contributed to the active episode
	episodeBytes, inEpisode := bbr.lossEpisodePackets[packetNumber]
	if !inEpisode {
		return
	}

	// Use episode-tracked bytes for consistency
	bbr.lossEpisodeSpuriousBytes += episodeBytes
	delete(bbr.lossEpisodePackets, packetNumber)

	// Restore if majority of cut-triggering losses were spurious
	if bbr.lossEpisodeSpuriousBytes > bbr.lossEpisodeTotalBytes/2 {
		bbr.resetLowerBoundsForSpuriousRecovery()
	}
}

// resetLowerBoundsForSpuriousRecovery restores bounds after spurious loss detection.
func (bbr *BBRv3) resetLowerBoundsForSpuriousRecovery() {
	bbr.bwLo = protocol.MaxByteCount
	bbr.inflightLo = protocol.MaxByteCount
	
	// Clear episode state
	bbr.lossEpisodeActive = false
	bbr.lossEpisodePackets = nil
	bbr.lossEpisodeTotalBytes = 0
	bbr.lossEpisodeSpuriousBytes = 0
	bbr.pendingLossPackets = nil
	
	// Clear loss-in-round flag since the loss was spurious
	bbr.lossInRound = false
	
	// Reset full bandwidth estimator to re-probe after spurious loss
	bbr.resetFullBw()
}
```

- [ ] **Step 3: Run tests**

Run: `go test -v ./internal/congestion/... -run "TestBBRSpuriousRecovery"`
Expected: PASS

- [ ] **Step 4: Run full BBR test suite**

Run: `go test ./internal/congestion/...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/congestion/bbr_v3.go internal/congestion/bbr_v3_test.go
git commit -m "$(cat <<'EOF'
feat(bbr): implement byte-weighted spurious loss recovery

Replace immediate spurious recovery with episode-based approach.
Only restore bounds when majority (>50%) of cut-triggering bytes
were spurious, preventing erasure of legitimate congestion responses.
EOF
)"
```

---

### Task 13: Clear Episode State on Migration

**Files:**
- Modify: `internal/congestion/bbr_v3.go` (OnConnectionMigration)

- [ ] **Step 1: Find and update OnConnectionMigration**

Search for `OnConnectionMigration` and add episode clearing:

```go
func (bbr *BBRv3) OnConnectionMigration(initialMaxDatagramSize protocol.ByteCount) {
	// ... existing reset logic ...
	
	// Clear episode tracking state
	bbr.lossEpisodeActive = false
	bbr.lossEpisodePackets = nil
	bbr.lossEpisodeTotalBytes = 0
	bbr.lossEpisodeSpuriousBytes = 0
	bbr.pendingLossPackets = nil
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/congestion/...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3.go
git commit -m "$(cat <<'EOF'
feat(bbr): clear episode state on connection migration

New paths need fresh episode tracking, so clear all episode state
when migrating to a new path.
EOF
)"
```

---

### Task 14: Remove CC-Owned Threshold Interface from BBR

**Files:**
- Modify: `internal/congestion/bbr_v3.go` (remove GetPacketReorderThreshold)

- [ ] **Step 1: Search for and remove GetPacketReorderThreshold**

Run: `grep -n "GetPacketReorderThreshold\|packetReorderingThreshold" internal/congestion/bbr_v3.go`

Remove:
- The `packetReorderingThreshold` constant (if present)
- The `GetPacketReorderThreshold()` method (if present)

- [ ] **Step 2: Run build and tests**

Run: `go build ./... && go test ./...`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/congestion/bbr_v3.go
git commit -m "$(cat <<'EOF'
refactor(bbr): remove CC-owned threshold interface

Per CC-agnostic architecture, loss detection owns adaptive thresholds.
Remove GetPacketReorderThreshold from BBR - this debug override is
no longer needed.
EOF
)"
```

---

### Task 15: Integration Test - Full Flow

**Files:**
- Test existing integration tests

- [ ] **Step 1: Run full test suite**

Run: `go test ./...`
Expected: PASS

- [ ] **Step 2: Run integration tests specifically**

Run: `go test -v ./integrationtests/...`
Expected: PASS

- [ ] **Step 3: Verify no new compilation warnings**

Run: `go build ./... 2>&1 | head -50`
Expected: Clean build

- [ ] **Step 4: Final commit for integration**

If any fixes were needed:

```bash
git add -A
git commit -m "$(cat <<'EOF'
fix: address integration test issues

[describe any fixes made]
EOF
)"
```

---

### Task 16: Create Test Branch Variants for Pacemaker

**Files:**
- Modify: `internal/ackhandler/sent_packet_handler.go` (feature flags)

- [ ] **Step 1: Create baseline branch (all flags false)**

```bash
git checkout -b algo/bbrv3-adaptive-baseline
```

Edit `sent_packet_handler.go` to set:
```go
enableBDPScaledThreshold       = false
enableMonotonicThresholdGrowth = false
enableAdaptiveTimeThreshold    = false
```

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "test: adaptive threshold baseline (all flags false)"
```

- [ ] **Step 2: Create BDP-only branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -b algo/bbrv3-adaptive-bdp
```

Edit flags:
```go
enableBDPScaledThreshold       = true
enableMonotonicThresholdGrowth = false
enableAdaptiveTimeThreshold    = false
```

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "test: adaptive threshold BDP-scaling only"
```

- [ ] **Step 3: Create monotonic-only branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -b algo/bbrv3-adaptive-monotonic
```

Edit flags:
```go
enableBDPScaledThreshold       = false
enableMonotonicThresholdGrowth = true
enableAdaptiveTimeThreshold    = false
```

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "test: adaptive threshold monotonic growth only"
```

- [ ] **Step 4: Create time-only branch**

```bash
git checkout algo/bbrv3-adaptive
git checkout -b algo/bbrv3-adaptive-time
```

Edit flags:
```go
enableBDPScaledThreshold       = false
enableMonotonicThresholdGrowth = false
enableAdaptiveTimeThreshold    = true
```

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "test: adaptive threshold time-threshold only"
```

- [ ] **Step 5: Create full branch (already on algo/bbrv3-adaptive)**

```bash
git checkout algo/bbrv3-adaptive
git checkout -b algo/bbrv3-adaptive-full
```

Verify flags are all true, then:

```bash
git add internal/ackhandler/sent_packet_handler.go
git commit -m "test: adaptive threshold full (all mechanisms enabled)"
```

- [ ] **Step 6: Return to main development branch**

```bash
git checkout algo/bbrv3-adaptive
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Extend lostPacketTracker with Length | lost_packet_tracker.go |
| 2 | Update SpuriousLossHandler interface | interface.go, bbr_v3.go |
| 3 | Add adaptive threshold constants/state | sent_packet_handler.go |
| 4 | Implement threshold calculation methods | sent_packet_handler.go |
| 5 | Integrate into detectLostPackets | sent_packet_handler.go |
| 6 | Implement spurious detection with bytes | sent_packet_handler.go |
| 7 | Add threshold reset on migration | sent_packet_handler.go |
| 8 | Cache maxDatagramSize | sent_packet_handler.go |
| 9 | Add BBR episode tracking state | bbr_v3.go |
| 10 | Implement pending loss tracking | bbr_v3.go |
| 11 | Implement episode promotion | bbr_v3.go |
| 12 | Implement byte-weighted spurious recovery | bbr_v3.go |
| 13 | Clear episode state on migration | bbr_v3.go |
| 14 | Remove CC-owned threshold interface | bbr_v3.go |
| 15 | Integration test full flow | - |
| 16 | Create test branch variants | - |

**Total estimated time:** 2-3 hours for implementation, additional time for testing.
