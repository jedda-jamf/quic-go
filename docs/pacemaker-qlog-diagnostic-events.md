# Pacemaker Qlog Diagnostic Events: BBRv3 State Machine Analysis

**Date:** 2026-05-27  
**Branch:** `algo/bbrv3-adaptive`  
**Purpose:** Enable diagnosis of BBRv3 startup exit issues (stuck-in-startup, spurious ProbeRTT)

## Summary of Changes

This document describes qlog schema changes made to support diagnosis of two BBRv3 state machine issues:

1. **F1: Spurious ProbeRTT Entry** — Some runs enter ProbeRTT directly from Startup on the first valid ACK
2. **F2: Filled-Pipe Estimator Starvation** — Rate sample suppression may prevent the filled-pipe estimator from running

---

## Change 1: Extended `recovery:bbr_round_updated` Event

### New Fields Added

| Field | Type | Description |
|-------|------|-------------|
| `min_rtt` | float (ms) | Current BBR min_rtt estimate. Compare against `rate_sample_interval` to determine if suppression occurred. |
| `valid_samples_in_round` | uint64 | Count of ACK events this round where `deliveryRate > 0` (valid samples). |
| `suppressed_samples_in_round` | uint64 | Count of ACK events this round where `interval < min_rtt` caused rate suppression. |
| `max_delivery_rate_in_round` | uint64 (bytes/s) | Highest valid `deliveryRate` observed this round. Shows what the estimator *could* have used. |
| `total_ack_events_in_round` | uint64 | Total ACK events processed this round (valid + suppressed + other). |

### Example Event

```json
{
  "name": "recovery:bbr_round_updated",
  "data": {
    "state": "startup",
    "phase": "",
    "round_count": 42,
    "round_start": true,
    "loss_in_round": false,
    "ecn_in_round": false,
    "delivery_rate": 0,
    "delivery_rate_valid": false,
    "app_limited": false,
    "full_bw": 125000000,
    "full_bw_count": 0,
    "full_bw_now": false,
    "full_bw_reached": false,
    "pacing_rate": 346250000,
    "bytes_in_flight": 3900000,
    "cwnd": 7800000,
    "send_elapsed": 25.5,
    "ack_elapsed": 28.2,
    "rate_sample_interval": 28.2,
    "min_rtt": 30.0,
    "valid_samples_in_round": 15,
    "suppressed_samples_in_round": 2,
    "max_delivery_rate_in_round": 118000000,
    "total_ack_events_in_round": 17
  }
}
```

### Diagnostic Interpretation

**Detecting F2 (Filled-Pipe Estimator Starvation):**

```python
# If round-start sample was suppressed but valid samples existed off-round
if event.delivery_rate == 0 and event.valid_samples_in_round > 0:
    # The filled-pipe estimator was starved on this round boundary
    # but valid samples existed that could have updated full_bw
    pass

# If all samples this round were suppressed
if event.suppressed_samples_in_round == event.total_ack_events_in_round:
    # No valid rate samples at all this round
    pass

# Check if suppression explains stuck full_bw_count
if event.suppressed_samples_in_round > 0 and event.full_bw_count == 0:
    # Rate suppression may be preventing plateau detection
    pass
```

---

## Change 2: New `recovery:bbr_probe_rtt_check` Event

### Event Schema

| Field | Type | Description |
|-------|------|-------------|
| `rtt_sample` | float (ms) | RTT sample from the ACK event that triggered ProbeRTT entry |
| `probe_rtt_min_stamp_was_zero` | bool | Was `probeRTTMinStamp` uninitialized (zero) when checked? **Key diagnostic for F1.** |
| `probe_expired` | bool | Did the 5-second ProbeRTT interval expire? (includes IsZero case) |
| `idle_restart` | bool | Was the connection in idle-restart state? (would suppress ProbeRTT entry) |
| `round_count` | uint64 | Round count when ProbeRTT was entered |
| `state_before` | string | BBR state immediately before transition (e.g., "startup", "probe_bw") |

### Example Event

```json
{
  "name": "recovery:bbr_probe_rtt_check",
  "data": {
    "rtt_sample": 30.5,
    "probe_rtt_min_stamp_was_zero": true,
    "probe_expired": true,
    "idle_restart": false,
    "round_count": 3,
    "state_before": "startup"
  }
}
```

### Diagnostic Interpretation

**Detecting F1 (Spurious ProbeRTT Entry):**

```python
# Spurious ProbeRTT entry from uninitialized stamp
if (event.probe_rtt_min_stamp_was_zero and 
    event.state_before == "startup" and 
    event.round_count < 10):
    # This is the bug: ProbeRTT entered from Startup due to
    # probeRTTMinStamp being zero (never initialized)
    pass
```

### When This Event is Emitted

- **Only** when BBR actually enters ProbeRTT state
- NOT emitted on every `updateMinRTT()` call
- Typical frequency: at most once per ~5 seconds per connection (ProbeRTT interval)
- During the diagnosed bug: may fire once on the first valid ACK

---

## Parser Implementation Guide

### 1. Update Event Type Registry

Add the new event type to your parser's event registry:

```python
EVENT_TYPES = {
    # ... existing events ...
    "recovery:bbr_probe_rtt_check": BBRv3ProbeRTTCheckEvent,
}
```

### 2. Define Event Class for `bbr_probe_rtt_check`

```python
@dataclass
class BBRv3ProbeRTTCheckEvent:
    rtt_sample_ms: float
    probe_rtt_min_stamp_was_zero: bool
    probe_expired: bool
    idle_restart: bool
    round_count: int
    state_before: str
    
    @classmethod
    def from_json(cls, data: dict) -> "BBRv3ProbeRTTCheckEvent":
        return cls(
            rtt_sample_ms=data["rtt_sample"],
            probe_rtt_min_stamp_was_zero=data["probe_rtt_min_stamp_was_zero"],
            probe_expired=data["probe_expired"],
            idle_restart=data["idle_restart"],
            round_count=data["round_count"],
            state_before=data["state_before"],
        )
```

### 3. Extend Existing `bbr_round_updated` Parser

Add the new fields to your existing parser:

```python
@dataclass  
class BBRv3RoundUpdatedEvent:
    # ... existing fields ...
    
    # New diagnostic fields
    min_rtt_ms: float
    valid_samples_in_round: int
    suppressed_samples_in_round: int
    max_delivery_rate_in_round: int
    total_ack_events_in_round: int
    
    @classmethod
    def from_json(cls, data: dict) -> "BBRv3RoundUpdatedEvent":
        return cls(
            # ... existing field parsing ...
            
            # New fields (with defaults for backwards compatibility)
            min_rtt_ms=data.get("min_rtt", 0.0),
            valid_samples_in_round=data.get("valid_samples_in_round", 0),
            suppressed_samples_in_round=data.get("suppressed_samples_in_round", 0),
            max_delivery_rate_in_round=data.get("max_delivery_rate_in_round", 0),
            total_ack_events_in_round=data.get("total_ack_events_in_round", 0),
        )
```

### 4. Analysis Queries

**Query 1: Find spurious ProbeRTT entries from Startup**

```python
def find_spurious_probe_rtt_entries(events):
    return [
        e for e in events 
        if isinstance(e, BBRv3ProbeRTTCheckEvent)
        and e.probe_rtt_min_stamp_was_zero
        and e.state_before == "startup"
    ]
```

**Query 2: Find rounds where filled-pipe estimator was starved**

```python
def find_starved_rounds(events):
    return [
        e for e in events
        if isinstance(e, BBRv3RoundUpdatedEvent)
        and e.delivery_rate == 0  # Round-start sample suppressed
        and e.valid_samples_in_round > 0  # But valid samples existed
        and e.state == "startup"
    ]
```

**Query 3: Compute suppression ratio per run**

```python
def compute_suppression_stats(events):
    rounds = [e for e in events if isinstance(e, BBRv3RoundUpdatedEvent)]
    total_samples = sum(r.total_ack_events_in_round for r in rounds)
    suppressed = sum(r.suppressed_samples_in_round for r in rounds)
    return {
        "total_ack_events": total_samples,
        "suppressed_events": suppressed,
        "suppression_ratio": suppressed / total_samples if total_samples > 0 else 0,
    }
```

---

## Expected Diagnostic Output

### For F1 (Spurious ProbeRTT)

If the hypothesis is correct, anomalous runs (10%) will show:
```
bbr_probe_rtt_check events:
  - state_before: "startup"
  - probe_rtt_min_stamp_was_zero: true
  - round_count: 1-5 (very early)
```

Normal runs (90%) will either:
- Have no early `bbr_probe_rtt_check` events from startup, OR
- Show ProbeRTT entry after 5+ seconds with `probe_rtt_min_stamp_was_zero: false`

### For F2 (Rate Sample Suppression)

If the hypothesis is correct, stuck-in-startup runs will show:
```
bbr_round_updated events in startup state:
  - delivery_rate: 0 (suppressed)
  - valid_samples_in_round: > 0 (samples existed)
  - full_bw_count: stays at 0 or resets frequently
```

---

## Backwards Compatibility

- New fields in `bbr_round_updated` are always emitted (not conditional)
- Existing parsers that don't recognize new fields will ignore them (standard JSON behavior)
- The new `bbr_probe_rtt_check` event can be ignored by parsers that don't need it
- Use `.get()` with defaults when parsing to handle qlogs from older quic-go versions

---

## Files Changed

| File | Changes |
|------|---------|
| `internal/congestion/bbr_v3.go` | Added round-level accumulators, emit ProbeRTT check event |
| `qlog/event.go` | Added new fields to `BBRv3RoundUpdated`, added `BBRv3ProbeRTTCheck` event |

---

## Next Steps After Parser Update

1. Re-run the baseline test batches from the investigation report
2. Extract the new diagnostic fields
3. Validate or refute hypotheses F1 and F2
4. If confirmed, proceed with fixes:
   - F1: Initialize `probeRTTMinStamp = now` in `resetControllerState()`
   - F2: Consider aligning with Google's filled-pipe estimator (update baseline off-round)
