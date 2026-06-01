# BBRv3 Polish Spec

## Goal

Improve documentation, naming consistency, and test coverage in the BBRv3 congestion control implementation without changing runtime behavior. Prepare the codebase for eventual upstream contribution once a pluggable congestion control interface exists.

## Scope

- **In scope:** Documentation, naming, struct organization, internal refactoring, test additions
- **Out of scope:** File splits, qlog schema changes, behavioral changes, interface modifications

## Items

### 1. Documentation Additions

#### 1a. Constants Block Header

Add a header comment to `bbr_v3.go` lines 1-15 explaining:
- Implementation tracks draft-ietf-ccwg-bbr-05 + Google's tcp_bbr.c v3
- Key divergences from RFC with rationale pointers
- Terminology mapping: RFC "shortterm/longterm" ↔ code naming

#### 1c. bbrRateSample Lifecycle Doc

Add doc comment to `bbrRateSample` struct explaining:
- Created fresh per ACK event in `OnPacketAcked()`
- Populated incrementally as packets in the ACK are processed
- Consumed in `processPendingAckEvent()` then cleared

#### 3c. State Machine Invariant Docs

Add comments at each ProbeBW phase documenting:
- Entry conditions
- What the phase is trying to achieve
- Exit conditions
- Invariants maintained during the phase

Locations: `updateCyclePhase()`, `startProbeBWDown()`, `startProbeBWCruise()`, `startProbeBWRefill()`, `startProbeBWUp()`

---

### 2. Naming Changes

#### 2a. Bandwidth Model Terminology (RFC Alignment)

| Current | New | Rationale |
|---------|-----|-----------|
| `bwLo` | `bwShortterm` | RFC §5.5.10 "short-term model" |
| `bwHi` | `bwLongterm` | RFC "long-term model" (max_bw filter) |
| `inflightLo` | `inflightShortterm` | Consistent with bw naming |
| `inflightHi` | `inflightLongterm` | Consistent with bw naming |
| `undoBwLo` | `undoBwShortterm` | Follows bwLo rename |
| `undoInflightLo` | `undoInflightShortterm` | Follows inflightLo rename |
| `undoInflightHi` | `undoInflightLongterm` | Follows inflightHi rename |

#### 2b. Full Bandwidth Estimator Clarity

| Current | New | Rationale |
|---------|-----|-----------|
| `fullBandwidth` | `fullBwEstimate` | The estimated bandwidth value |
| `fullBandwidthReached` | `fullBwReached` | Boolean flag |
| `fullBandwidthCount` | `fullBwCount` | Counter for plateau detection |
| `fullBandwidthNow` | `fullBwNow` | This-round flag |

---

### 3. Struct Extractions

#### 2c. Pending ACK Event State

Extract 12 fields into embedded `bbrPendingAckState` struct:

```go
type bbrPendingAckState struct {
    valid           bool
    eventTime       monotime.Time
    ackedBytes      protocol.ByteCount
    priorInFlight   protocol.ByteCount
    priorDelivered  uint64
    priorTime       monotime.Time
    sendElapsed     time.Duration
    txInFlight      protocol.ByteCount
    isAppLimited    bool
    totalLostAtSend uint64
    ceBytes         protocol.ByteCount
    newestSentTime  monotime.Time
    newestPacketNum protocol.PacketNumber
}
```

Access pattern changes from `bbr.pendingAckedBytes` to `bbr.pendingAck.ackedBytes`.

#### 2d. Loss Episode State

Extract 6 fields into embedded `bbrLossEpisode` struct:

```go
type bbrLossEpisode struct {
    active        bool
    packets       map[protocol.PacketNumber]protocol.ByteCount
    totalBytes    protocol.ByteCount
    spuriousBytes protocol.ByteCount
}
```

Access pattern changes from `bbr.lossEpisodeActive` to `bbr.episode.active`.

---

### 4. processPendingAckEvent Refactor

#### 3b. Two-Phase Model/Control Separation

Extract two methods to match RFC §4.2's structure:

**`updateModel(rs bbrRateSample, now monotime.Time)`** contains:
- `updateRoundStart(rs)`
- `updateECNAlpha(rs)`
- `updateLatestDeliverySignals(rs)`
- `updateCongestionSignals(rs)`
- `updateAckAggregation(rs, now)`
- `checkLossTooHighInStartup(rs)`
- `checkFullBwReached(rs)`
- `checkDrain(rs, now)`
- `updateCyclePhase(rs, now)`
- `updateMinRTT(now)`

**`updateControlOutputs(rs bbrRateSample)`** contains:
- `updateGains()`
- `setPacingRateWithGain(bbr.pacingGain)`
- `setSendQuantum()`
- `setCwnd(rs)`

Resulting `processPendingAckEvent()` becomes a thin orchestrator calling `updateModel()` then `updateControlOutputs()`.

---

### 5. Test Additions

#### 6a. Migration Mid-Episode Test

Test `OnConnectionMigration()` clears episode state when called during an active loss episode:
- Trigger loss to start episode (`episode.active == true`)
- Call `OnConnectionMigration()`
- Assert episode cleared (`episode.active == false`, `episode.packets == nil`)

#### 6b. Spurious Loss Startup Restoration Test

Test the `undoState == BBRStartup` path in `restoreBoundsForSpuriousEpisode()`:
- Put BBRv3 in Startup state
- Trigger loss that exits Startup (saves undo state)
- Detect spurious loss with >50% threshold
- Assert restoration returns to Startup with `STARTUP_PACING_GAIN` and `STARTUP_CWND_GAIN`

#### 6c. ECN Eligibility Transition Test

Test alpha baseline seeding on eligibility transition:
- Send packets, accumulate delivered bytes before ECN eligibility
- Trigger ECN eligibility (valid minRTT within RTT envelope)
- Assert `alphaLastDelivered == totalBytesAcked` at transition
- Assert subsequent CE ratio calculation uses fresh baseline

---

### 6. Minor Cleanups

#### 7a. RNG Seed Consistency (line 652)

```go
// Before
bbr.rng = rand.New(rand.NewSource(time.Now().UnixNano()))

// After
bbr.rng = rand.New(rand.NewSource(monotime.Now().Nanoseconds()))
```

#### 7b. Redundant max() (line 2278)

```go
// Before
bbr.sendQuantum = max(2*bbr.maxDatagramSize, bbr.maxDatagramSize)

// After
bbr.sendQuantum = 2 * bbr.maxDatagramSize
```

#### 7c. Variable Rename in isRenoCoexistenceProbeTime() (line 2853)

```go
// Before
rounds := uint64(min(...))

// After
targetRounds := uint64(min(...))
```

---

## Execution Order

1. **Documentation** (1a, 1c, 3c) — establishes terminology
2. **Naming changes** (2a, 2b) — uses new terminology
3. **Struct extractions** (2c, 2d) — groups related fields
4. **Refactor** (3b) — highest-touch change
5. **Minor cleanups** (7a, 7b, 7c) — trivial fixes
6. **Tests** (6a, 6b, 6c) — verifies nothing broke

## Risk Assessment

**Overall risk:** Low-medium

| Item | Risk | Rationale |
|------|------|-----------|
| Documentation | None | Additive only |
| Naming changes | Low | Global rename, compiler catches misses |
| Struct extractions | Low | Compiler catches all access site updates |
| Refactor (3b) | Medium | Touches critical path; must preserve exact call order |
| Minor cleanups | None | Trivial changes |
| Tests | None | Additive only |

## Validation

- All existing tests must pass
- New tests must pass
- Manual inspection of `processPendingAckEvent()` call order preserved
- Verify qlog field names updated where struct fields renamed

## Files Affected

- `internal/congestion/bbr_v3.go` — all changes except tests
- `internal/congestion/bbr_v3_test.go` — new tests (6a, 6b, 6c)
