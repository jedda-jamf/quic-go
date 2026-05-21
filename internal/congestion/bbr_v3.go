package congestion

import (
	"math"
	"math/rand"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

// BBRv3 Constants
//
// These constants are aligned with:
// - RFC draft-ietf-ccwg-bbr-05 (IETF BBR specification)
// - Google tcp_bbr.c v3 (Linux kernel reference implementation)
//
// Where the RFC and tcp_bbr.c differ, this implementation follows the RFC text.
// The Linux implementation is used as an implementation reference where it does
// not conflict with the RFC.
const (
	// ==========================================================================
	// PACING AND CWND GAINS
	// ==========================================================================

	// STARTUP_PACING_GAIN = 2.77 (4*ln(2)) per RFC draft-ietf-ccwg-bbr-05 §2.4
	// This value allows pacing rate to double each RTT, matching un-paced Reno.
	// See also: tcp_bbr.c:bbr_startup_pacing_gain = BBR_UNIT * 277 / 100 + 1
	STARTUP_PACING_GAIN = 2.77

	// STARTUP_CWND_GAIN = 2 per RFC draft-ietf-ccwg-bbr-05 §2.5
	// Allows 2*BDP worth of data in flight during startup for burst tolerance.
	// See also: tcp_bbr.c:bbr_startup_cwnd_gain = BBR_UNIT * 2
	STARTUP_CWND_GAIN = 2.0

	// DRAIN_PACING_GAIN = 0.5 per RFC draft-ietf-ccwg-bbr-05 §5.3.2.
	// This is the RFC-specified drain gain for reducing queue occupancy after Startup.
	DRAIN_PACING_GAIN = 0.5

	// CWND_GAIN_DEFAULT = 2 per RFC draft-ietf-ccwg-bbr-05 §2.5
	// Default cwnd gain used in ProbeBW steady state.
	// See also: tcp_bbr.c:bbr_cwnd_gain = BBR_UNIT * 2
	CWND_GAIN_DEFAULT = 2.0

	// PROBE_BW_UP_GAIN = 1.25 per RFC draft-ietf-ccwg-bbr-05 §5.3.3.4.4
	// Used during ProbeBW UP phase to probe for additional bandwidth.
	// See also: tcp_bbr.c:bbr_pacing_gain[] = {BBR_UNIT * 5 / 4, ...}
	PROBE_BW_UP_GAIN = 1.25

	// PROBE_BW_DOWN_GAIN = 0.90 per RFC draft-ietf-ccwg-bbr-05 §5.3.3.4.2.
	// Used during ProbeBW DOWN phase to drain any excess queue.
	PROBE_BW_DOWN_GAIN = 0.90

	// PROBE_BW_BASE_GAIN = 1.0
	// Used during ProbeBW CRUISE and REFILL phases.
	PROBE_BW_BASE_GAIN = 1.0

	// PROBE_BW_UP_CWND_GAIN = 2.25 per RFC draft-ietf-ccwg-bbr-05 §5.6.1
	// ProbeBW_UP gets extra cwnd headroom (2.0 + 0.25) to allow probing above BDP.
	// See also: tcp_bbr.c:bw_probe_cwnd_gain = BBR_UNIT * 5 / 4 (adds 0.25 to default)
	PROBE_BW_UP_CWND_GAIN = 2.25

	// PROBE_RTT_CWND_GAIN = 0.5 per RFC draft-ietf-ccwg-bbr-05 §2.13.2
	// Reduces cwnd to 0.5*BDP during ProbeRTT to allow queue drain.
	// See also: tcp_bbr.c:bbr_probe_rtt_cwnd_gain = BBR_UNIT / 2
	PROBE_RTT_CWND_GAIN = 0.5

	// ==========================================================================
	// TIMING CONSTANTS
	// ==========================================================================

	// PROBE_RTT_DURATION = 200ms per RFC draft-ietf-ccwg-bbr-05 §2.13.2
	// Duration to hold reduced cwnd during ProbeRTT.
	// See also: tcp_bbr.c:bbr_probe_rtt_mode_ms = 200
	PROBE_RTT_DURATION = 200 * time.Millisecond

	// PROBE_RTT_INTERVAL = 5s per RFC draft-ietf-ccwg-bbr-05 §2.13.2
	// Time between ProbeRTT phases to refresh min_rtt estimate.
	// See also: tcp_bbr.c:bbr_probe_rtt_interval_ms = 5000
	PROBE_RTT_INTERVAL = 5 * time.Second

	// MIN_RTT_FILTER_LEN = 10s per RFC draft-ietf-ccwg-bbr-05 §2.13.1
	// Window length for min_rtt filter.
	// See also: tcp_bbr.c:bbr_min_rtt_win_sec = 10
	MIN_RTT_FILTER_LEN = 10 * time.Second

	// PROBE_WAIT_BASE = 2s per tcp_bbr.c
	// Base time between bandwidth probes in ProbeBW.
	// See also: tcp_bbr.c:bbr_bw_probe_base_us = 2 * USEC_PER_SEC
	PROBE_WAIT_BASE = 2 * time.Second

	// PROBE_WAIT_RAND_MAX = 1s per tcp_bbr.c
	// Random jitter added to probe wait time.
	// See also: tcp_bbr.c:bbr_bw_probe_rand_us = USEC_PER_SEC
	PROBE_WAIT_RAND_MAX = 1 * time.Second

	// ==========================================================================
	// MODEL AND THRESHOLD CONSTANTS
	// ==========================================================================

	// FULL_BW_GROWTH_THRESHOLD = 1.25 per tcp_bbr.c
	// Delivery rate must grow by 25% to indicate bandwidth still increasing.
	// See also: tcp_bbr.c:bbr_full_bw_thresh = BBR_UNIT * 5 / 4
	FULL_BW_GROWTH_THRESHOLD = 1.25

	// FULL_BW_ROUNDS = 3 per tcp_bbr.c
	// Consecutive rounds without 25% growth to declare full bandwidth reached.
	// See also: tcp_bbr.c:bbr_full_bw_cnt = 3
	FULL_BW_ROUNDS = 3

	// STARTUP_FULL_LOSS_COUNT = 6 per tcp_bbr.c
	// Loss events per round to trigger early startup exit.
	// See also: tcp_bbr.c:bbr_startup_full_loss_cnt = 6
	STARTUP_FULL_LOSS_COUNT = 6

	// LOSS_THRESH = 0.02 (2%) per RFC draft-ietf-ccwg-bbr-05 §2.7
	// Loss rate threshold for detecting inflight_too_high.
	// See also: tcp_bbr.c:bbr_loss_thresh = BBR_UNIT * 2 / 100
	LOSS_THRESH = 0.02

	// BETA_REDUCTION = 0.30 per tcp_bbr.c
	// Multiplicative decrease factor on loss/ECN (reduce by 30%).
	// Note: RFC §2.7 defines BBR.Beta=0.7 as *remaining* fraction (1-0.30=0.70).
	// See also: tcp_bbr.c:bbr_beta = BBR_UNIT * 30 / 100
	BETA_REDUCTION = 0.30

	// INFLIGHT_HEADROOM = 0.15 (15%) per RFC draft-ietf-ccwg-bbr-05 §2.7
	// Headroom below inflight_hi for steady-state operation.
	// See also: tcp_bbr.c:bbr_inflight_headroom = BBR_UNIT * 15 / 100
	INFLIGHT_HEADROOM = 0.15

	// ==========================================================================
	// ECN CONSTANTS
	// ==========================================================================
	//
	// RFC draft-ietf-ccwg-bbr-05 §3.7 states: "This draft does not specify a
	// specific response to ECN, and instead leaves it as an area for future work."
	//
	// IMPLEMENTATION CHOICE: We align with Google's tcp_bbr.c (Linux kernel BBRv3):
	//   - Track ECN marking ratio via EWMA with gain = 1/16
	//   - Reduce inflightLo by (ecn_alpha * 1/3) when ECN observed in round
	//
	// This approach is tested in bbr_v3_test.go Part 2 (Implementation Strategy Tests).

	// ECN_ALPHA_UNIT is the fixed-point scale for ecnAlpha, matching BBR_UNIT
	// naming convention from tcp_bbr.c. ecnAlpha / ECN_ALPHA_UNIT gives [0, 1].
	ECN_ALPHA_UNIT = 1 << 16

	// ECN_ALPHA_GAIN_SHIFT implements g=1/16 via bit-shift for the EWMA.
	// Source: tcp_bbr.c bbr_ecn_alpha_gain = BBR_UNIT / 16
	ECN_ALPHA_GAIN_SHIFT = 4

	// ECN_FACTOR is the inflightLo reduction multiplier.
	// Source: tcp_bbr.c bbr_ecn_factor = BBR_UNIT / 3
	ECN_FACTOR = 1.0 / 3.0

	// ECN_THRESH = 0.5 per tcp_bbr.c
	// CE ratio threshold for inflight_too_high detection.
	// See also: tcp_bbr.c:bbr_ecn_thresh = BBR_UNIT / 2
	ECN_THRESH = 0.5

	// FULL_ECN_ROUNDS = 2 per tcp_bbr.c
	// Consecutive rounds with high ECN to exit startup.
	// See also: tcp_bbr.c logic in bbr_check_ecn_too_high_in_startup
	FULL_ECN_ROUNDS = 2

	// ECN_MAX_RTT = 5ms per tcp_bbr.c
	// Max RTT for ECN eligibility (low-latency paths only).
	// See also: tcp_bbr.c:bbr_ecn_max_rtt_us = 5000
	ECN_MAX_RTT = 5 * time.Millisecond

	// ==========================================================================
	// PACING AND FILTER CONSTANTS
	// ==========================================================================

	// BBR_PACING_MARGIN = 0.99 (1% below estimate) per tcp_bbr.c
	// Slight underpacing to avoid building queues.
	// See also: tcp_bbr.c pacing calculations
	BBR_PACING_MARGIN = 0.99

	// EXTRA_ACKED_WIN_RTS = 5 per Google BBRv3 tcp_bbr.c (bbr_extra_acked_win_rtts).
	// Draft-ietf-ccwg-bbr-05 §5.5.9 specifies BBRExtraAckedFilterLen = 10 packet-timed
	// round trips. The two-slot windowed-max approximation rotates every 5 rounds,
	// covering ~5–10 rounds, which approximates the spec's 10-round filter length.
	EXTRA_ACKED_WIN_RTS = 5

	// EXTRA_ACKED_MAX_US = 100ms per tcp_bbr.c
	// Max extra_acked contribution in time units.
	// See also: tcp_bbr.c:bbr_extra_acked_max_us = 100000
	EXTRA_ACKED_MAX_US = 100 * time.Millisecond

	// BW_PROBE_RAND_ROUNDS = 2 per tcp_bbr.c
	// Random rounds offset for probe timing.
	BW_PROBE_RAND_ROUNDS = 2

	// BW_PROBE_MAX_ROUNDS = 63 per tcp_bbr.c
	// Max rounds between bandwidth probes (Reno coexistence).
	// See also: tcp_bbr.c:bbr_bw_probe_max_rounds = 63
	BW_PROBE_MAX_ROUNDS = 63

	// DRAIN_MAX_ROUNDS = 3 per RFC draft-ietf-ccwg-bbr-05 §5.3.2
	// Fallback exit from Drain if inflight has not dropped below BDP within 3 rounds.
	// Handles cases where bandwidth was overestimated in Startup (e.g., due to competing
	// flows), preventing the connection from stalling in Drain indefinitely.
	DRAIN_MAX_ROUNDS = 3

	// EXTRA_ACKED_WIN_RTS_STARTUP = 1 per RFC draft-ietf-ccwg-bbr-05 §5.5.9.
	// In Startup, remember only one packet-timed round trip of aggregation.
	EXTRA_ACKED_WIN_RTS_STARTUP = 1

	// MAX_BW_FILTER_SLOTS = 2 per RFC draft-ietf-ccwg-bbr-05 §2.10
	// Two-slot windowed max filter for bandwidth estimate.
	MAX_BW_FILTER_SLOTS = 2

	// maxBBRv3CongestionWindow is the maximum allowed cwnd.
	maxBBRv3CongestionWindow = protocol.ByteCount(256 * 1024 * 1024)

	// ==========================================================================
	// SPURIOUS LOSS RECOVERY
	// ==========================================================================

	// spuriousLossRecoveryThreshold defines the minimum number of spurious losses
	// required before restoring saved state per RFC §5.5.11. A value of 0 means
	// recover on any spurious loss detection (spuriousCount >= 1). Higher values
	// can prevent ping-ponging in scenarios with mixed reordering and real loss.
	spuriousLossRecoveryThreshold = 0

	// ==========================================================================
	// PACKET REORDERING TOLERANCE
	// ==========================================================================

	// packetReorderingThreshold overrides the default RFC 9002 kPacketThreshold (3)
	// for loss detection. Higher values tolerate more reordering before declaring
	// loss, reducing false positives on paths with intentional or natural reordering.
	// A value of 10 allows packets to arrive up to 10 positions out of order before
	// being considered lost via the packet threshold mechanism.
	packetReorderingThreshold = 10
)

// bbrProbeBWPhase represents the sub-phases within ProbeBW state.
// Per RFC §5.3.3, ProbeBW cycles through: DOWN -> CRUISE -> REFILL -> UP -> DOWN
//
// Each phase serves a distinct purpose in steady-state bandwidth utilization:
//   - DOWN (§5.3.3.1):   Decelerate to drain queue, leave headroom
//   - CRUISE (§5.3.3.2): Match sending rate to delivery rate
//   - REFILL (§5.3.3.3): Reset short-term model, refill pipe
//   - UP (§5.3.3.4):     Probe for higher bandwidth
type bbrProbeBWPhase uint8

const (
	probeBWUp     bbrProbeBWPhase = iota // §5.3.3.4: pacing_gain=1.25, cwnd_gain=2.25
	probeBWDown                          // §5.3.3.1: pacing_gain=0.90, cwnd_gain=2.0
	probeBWCruise                        // §5.3.3.2: pacing_gain=1.0, cwnd_gain=2.0
	probeBWRefill                        // §5.3.3.3: pacing_gain=1.0, cwnd_gain=2.0
)

func (p bbrProbeBWPhase) String() string {
	switch p {
	case probeBWUp:
		return "up"
	case probeBWDown:
		return "down"
	case probeBWCruise:
		return "cruise"
	case probeBWRefill:
		return "refill"
	default:
		return "unknown"
	}
}

// bbrAckPhase tracks ACK processing state within a bandwidth probe cycle.
// Per RFC §5.3.3.6 (ProbeBW Algorithm Details), the ack_phase state machine
// coordinates between probing phases and the max_bw filter rotation:
//
//   - INIT:           Default state, not in a probe cycle
//   - REFILLING:      In REFILL phase, waiting for round to complete
//   - PROBE_STARTING: Entered UP phase, waiting for round to deliver feedback
//   - PROBE_FEEDBACK: Receiving samples from UP probing
//   - PROBE_STOPPING: In DOWN phase, waiting to advance max_bw filter
//
// The key function is in adaptUpperBounds: when PROBE_STOPPING && round_start,
// we advance the max_bw filter to rotate out stale samples from the previous cycle.
type bbrAckPhase uint8

const (
	ackPhaseInit          bbrAckPhase = iota // Default: not in probe cycle
	ackPhaseRefilling                        // REFILL: waiting for round
	ackPhaseProbeStarting                    // UP: waiting for feedback
	ackPhaseProbeFeedback                    // UP: receiving probe samples
	ackPhaseProbeStopping                    // DOWN: will advance max_bw filter
)

// BBRState represents the top-level BBR state machine states.
// Per RFC §5.1 (State Machine) and §5.1.1 (State Transition Diagram):
//
//	              |
//	              V
//	     +---> Startup  ------+
//	     |        |           |
//	     |        V           |
//	     |     Drain  --------+
//	     |        |           |
//	     |        V           |
//	     +---> ProbeBW <------+
//	     |                    |
//	     +---- ProbeRTT <-----+
//
// State purposes:
//   - Startup (§5.3.1): Exponential search for available bandwidth
//   - Drain (§5.3.2):   Drain queue created during Startup
//   - ProbeBW (§5.3.3): Steady-state bandwidth probing with 4-phase cycle
//   - ProbeRTT (§5.3.4): Cooperative RTT measurement by draining queue
type BBRState int

const (
	BBRStartup  BBRState = iota // §5.3.1: pacing_gain=2.77, cwnd_gain=2.0
	BBRDrain                    // §5.3.2: pacing_gain=0.5, cwnd_gain=2.0
	BBRProbeBW                  // §5.3.3: steady-state with 4-phase cycle
	BBRProbeRTT                 // §5.3.4: pacing_gain=1.0, cwnd_gain=0.5
)

// String returns the string representation of BBRState.
func (s BBRState) String() string {
	switch s {
	case BBRStartup:
		return "startup"
	case BBRDrain:
		return "drain"
	case BBRProbeBW:
		return "probe_bw"
	case BBRProbeRTT:
		return "probe_rtt"
	default:
		return "unknown"
	}
}

// bbrSentPacketState tracks per-packet delivery sampler snapshots.
// Per RFC §4.1.2.1.2 (Per-packet (P) state), each transmitted packet stores:
//   - P.delivered      (bytes):      C.delivered at send time
//   - P.delivered_time (time):       C.delivered_time at send time
//   - P.first_send_time (time):      C.first_send_time at send time
//   - P.send_time       (time):      scheduled transmission time
//   - P.tx_in_flight   (bytes):      C.inflight immediately after transmission
//   - P.is_app_limited (bool):       true if C.app_limited != 0 at send time
//   - P.lost           (bytes):      C.lost at send time (for loss-round detection)
//
// These fields enable delivery rate calculation per RFC §4.1.2.3 (Upon receiving an ACK).
type bbrSentPacketState struct {
	bytes          protocol.ByteCount // P.data_length: packet size for volume accounting
	delivered      uint64             // P.delivered: C.delivered snapshot at send time
	deliveredTime  monotime.Time      // P.delivered_time: C.delivered_time snapshot
	firstSentTime  monotime.Time      // P.first_send_time: origin of send_elapsed interval
	sentTime       monotime.Time      // P.send_time: scheduled pacing departure time
	txInFlight     protocol.ByteCount // P.tx_in_flight: C.inflight after this packet
	isAppLimited   bool               // P.is_app_limited: app-limited bubble active at send
	totalBytesLost uint64             // P.lost: C.lost at send time (§5.5.10 loss-round)
}

// bbrRateSample holds per-ACK delivery rate sample output.
// Per RFC §4.1.2.1.3 (Rate Sample (rs) Output), this structure captures:
//   - RS.delivery_rate:     delivery rate sample (RS.delivered / RS.interval)
//   - RS.is_app_limited:    P.is_app_limited from newest delivered packet
//   - RS.interval:          sampling interval (max of send_elapsed, ack_elapsed)
//   - RS.delivered:         C.delivered - P.delivered (volume delivered)
//   - RS.prior_delivered:   P.delivered from newest delivered packet
//   - RS.prior_time:        P.delivered_time from newest delivered packet
//   - RS.send_elapsed:      P.send_time - P.first_send_time
//   - RS.ack_elapsed:       C.delivered_time - P.delivered_time
//
// Additional fields beyond RFC for BBRv3 congestion signal tracking:
//   - RS.tx_in_flight:      P.tx_in_flight for loss rate calculation (§2.7)
//   - RS.lost:              volume lost since packet send (§5.5.10)
//   - RS.newly_acked:       volume acked in this ACK event
//   - RS.delivered_ce:      CE-marked bytes for ECN response (tcp_bbr.c)
type bbrRateSample struct {
	newlyAcked     protocol.ByteCount // RS.newly_acked: volume acked in this event
	delivered      protocol.ByteCount // RS.delivered: C.delivered - P.delivered
	deliveredCE    protocol.ByteCount // CE-marked bytes (ECN, tcp_bbr.c extension)
	deliveryRate   protocol.ByteCount // RS.delivery_rate: bytes/s
	interval       time.Duration      // RS.interval: max(send_elapsed, ack_elapsed)
	sendElapsed    time.Duration      // RS.send_elapsed: P.send_time - P.first_send_time
	ackElapsed     time.Duration      // RS.ack_elapsed: C.delivered_time - P.delivered_time
	txInFlight     protocol.ByteCount // RS.tx_in_flight: P.tx_in_flight for loss calc
	bytesInFlight  protocol.ByteCount // C.inflight after ACK processing
	priorInFlight  protocol.ByteCount // C.inflight before ACK processing
	priorDelivered uint64             // RS.prior_delivered: P.delivered snapshot
	lost           protocol.ByteCount // RS.lost: bytes lost since send (§5.5.10)
	isAppLimited   bool               // RS.is_app_limited: app-limited at send
}

// BBRv3 implements the send-side congestion controller.
//
// This implementation is aligned with:
// - Linux BBRv3 reference: google/bbr v3 net/ipv4/tcp_bbr.c
// - IETF specification: draft-ietf-ccwg-bbr-05
//
// QUIC Adaptation Notes:
//   - QUIC ackhandler invokes callbacks per-packet, while Linux BBR updates
//     its model once per ACK event. We emulate this by coalescing per-packet
//     callbacks by ACK timestamp and running one model update at OnAckEventEnd().
//   - C.SMSS maps to maxDatagramSize (QUIC datagram size) per RFC §2.1
//   - No TSO/GRO offload budget complexity (QUIC runs in userspace)
type BBRv3 struct {
	rttStats *utils.RTTStats
	pacer    *pacer

	maxDatagramSize  protocol.ByteCount
	congestionWindow protocol.ByteCount
	minPipeCwnd      protocol.ByteCount
	initialCwnd      protocol.ByteCount
	sendQuantum      protocol.ByteCount
	offloadBudget    protocol.ByteCount

	state        BBRState
	probeBWPhase bbrProbeBWPhase
	ackPhase     bbrAckPhase

	pacingGain float64
	cwndGain   float64
	pacingRate protocol.ByteCount // bytes/s

	fullBandwidthReached bool
	fullBandwidthNow     bool
	fullBandwidth        protocol.ByteCount
	fullBandwidthCount   int
	startupECNRounds     int

	// Bandwidth model: bwHi is a 2-slot windowed max filter per RFC §2.10
	//
	// Naming glossary (Go field → RFC term):
	//   bwHi[0:2]  → max_bw filter slots (RFC §2.10)
	//   bwLo       → bw_shortterm (RFC §5.5.10.2)
	//   inflightLo → inflight_shortterm (RFC §5.5.10.2)
	//   inflightHi → inflight_hi (RFC §5.5.10.1)
	//   bwLatest   → bw_latest (RFC §5.5.2)
	// Field names follow tcp_bbr.c conventions to aid cross-referencing.
	bwHi           [MAX_BW_FILTER_SLOTS]protocol.ByteCount
	bwLo           protocol.ByteCount
	bwLatest       protocol.ByteCount
	inflightHi     protocol.ByteCount
	inflightLo     protocol.ByteCount
	inflightLatest protocol.ByteCount

	roundCount           uint64
	roundsSinceProbe     uint64
	nextRoundDelivered   uint64
	roundStart           bool
	cwndLimitedInRound   bool
	cwndLimitedPrevRound bool

	lossRoundDelivered      uint64
	lossRoundStart          bool
	lossInRound       bool
	ecnInRound        bool
	lossInCycle       bool
	lossEventsInRound int
	lossEventCountedThisACK bool // Ensures we count at most one loss event per ACK event
	bytesLostInRound        protocol.ByteCount

	// Drain state baseline round_count for the RFC §5.3.2 fallback exit.
	drainStartRound uint64

	totalBytesSent    uint64
	totalBytesAcked   uint64
	totalBytesLost    uint64
	totalBytesAckedCE uint64
	ecnAckedECT0      int64
	ecnAckedECT1      int64
	ecnAckedCE        int64

	alphaLastDelivered   uint64
	alphaLastDeliveredCE uint64
	ecnAlpha             uint32 // fixed-point alpha scaled by ECN_ALPHA_UNIT
	ecnEligible          bool

	minRTT            time.Duration
	minRTTStamp       monotime.Time
	probeRTTMinDelay  time.Duration
	probeRTTMinStamp  monotime.Time
	probeRTTDoneStamp monotime.Time
	probeRTTRoundDone bool

	priorCwnd   protocol.ByteCount
	idleRestart bool
	ptoRecovery bool

	cycleStamp        monotime.Time
	phaseStartStamp   monotime.Time
	probeWait         time.Duration
	prevProbeTooHigh  bool
	stoppedRiskyProbe bool
	bwProbeSamples    bool
	bwProbeUpRounds uint8
	// bwProbeUpCnt controls the rate at which ProbeBW_UP raises inflight_hi.
	// Sentinels:
	//   0                     — uninitialized; first ACK in UP triggers raiseInflightHiSlope.
	//   protocol.MaxByteCount — upward probing disabled (set on Down/Refill entry).
	//   any other value       — acked bytes per +1 packet of inflight_hi growth.
	bwProbeUpCnt  protocol.ByteCount
	bwProbeUpAcks protocol.ByteCount

	ackEpochStart     monotime.Time
	ackEpochAcked     protocol.ByteCount
	extraAcked        [2]protocol.ByteCount
	extraAckedWinRTTs uint8
	extraAckedWinIdx  uint8

	sentPackets map[protocol.PacketNumber]bbrSentPacketState
	// collisionPNs tracks raw PacketNumbers that have experienced PN-space
	// collisions. Once a raw PN collides, all future packets with that PN
	// (from any space) are ignored by the sampler.
	collisionPNs  map[protocol.PacketNumber]struct{}
	firstSentTime monotime.Time
	deliveredTime monotime.Time

	// Pending ACK-event state (coalesced over one ACK frame timestamp).
	// This implements the "one model update per ACK event" semantics from Linux.
	pendingAckEventValid   bool
	pendingAckEventTime    monotime.Time
	pendingAckedBytes      protocol.ByteCount
	pendingPriorInFlight   protocol.ByteCount
	pendingPriorDelivered  uint64
	pendingPriorTime       monotime.Time
	pendingSendElapsed     time.Duration
	pendingTxInFlight      protocol.ByteCount
	pendingIsAppLimited    bool
	pendingTotalLostAtSend uint64
	pendingCEBytes         protocol.ByteCount
	pendingNewestSentTime  monotime.Time
	pendingNewestPacketNum protocol.PacketNumber

	// Pending ECN feedback associated with next ACK event timestamp.
	pendingECNEventValid bool
	pendingECNEventTime  monotime.Time
	pendingECNCEBytes    protocol.ByteCount

	// App-limited bubble tracking per RFC §4.1.1.3.
	// When the application has a send opportunity but no data to send, we record
	// the delivery count at which the "bubble" ends. Samples sent before this point
	// are marked app-limited. This is distinct from cwnd-limited detection.
	appLimitedUntil uint64

	// ACK-event state from OnAckEventStart (post-loss, pre-ACK-callback).
	// This provides BBRv3 with correct bytesInFlight for phase transitions.
	ackEventBytesInFlight protocol.ByteCount
	ackEventTime          monotime.Time

	rng *rand.Rand

	qlogger        qlogwriter.Recorder
	lastState      BBRState
	lastPhase      bbrProbeBWPhase
	lastRoundCount uint64

	// Spurious loss recovery state per RFC §5.5.11.
	// When loss is first detected in a round, we save state so it can be
	// restored if the loss is later determined to be spurious.
	// This prevents BBRv3 from permanently reducing its model bounds due to
	// reordering that was misclassified as loss.
	undoState        BBRState
	undoProbeBWPhase bbrProbeBWPhase
	undoBwLo         protocol.ByteCount
	undoInflightLo   protocol.ByteCount
	undoInflightHi   protocol.ByteCount
	undoCwnd         protocol.ByteCount
}

var (
	_ SendAlgorithm                     = &BBRv3{}
	_ SendAlgorithmWithRTTStats         = &BBRv3{}
	_ SendAlgorithmWithDebugInfos       = &BBRv3{}
	_ AckEventHandler                   = &BBRv3{}
	_ LossDetectionHandler              = &BBRv3{}
	_ ECNFeedbackHandler                = &BBRv3{}
	_ AppLimitedHandler                 = &BBRv3{}
	_ SpuriousLossHandler               = &BBRv3{}
	_ PTOHandler                        = &BBRv3{}
	_ ConnectionMigrationHandler        = &BBRv3{}
	_ PacketReorderingThresholdProvider = &BBRv3{}
)

// NewBBRV3 creates a new BBRv3 congestion controller.
func NewBBRV3(
	_ Clock,
	rttStats *utils.RTTStats,
	_ *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	_ bool,
	logger any,
) *BBRv3 {
	var qlogger qlogwriter.Recorder
	if l, ok := logger.(qlogwriter.Recorder); ok {
		qlogger = l
	}
	bbr := &BBRv3{
		rttStats: rttStats,
		qlogger:  qlogger,
	}
	bbr.resetControllerState(initialMaxDatagramSize, monotime.Now())
	return bbr
}

func (bbr *BBRv3) OnConnectionMigration(initialMaxDatagramSize protocol.ByteCount) {
	bbr.resetControllerState(initialMaxDatagramSize, monotime.Now())
}

// GetPacketReorderThreshold returns the packet reordering threshold for loss detection.
// This overrides the default RFC 9002 kPacketThreshold (3) to better tolerate paths
// with natural or intentional packet reordering, reducing false loss declarations
// that would otherwise trigger unnecessary congestion response.
func (bbr *BBRv3) GetPacketReorderThreshold() protocol.PacketNumber {
	return packetReorderingThreshold
}

func (bbr *BBRv3) resetControllerState(initialMaxDatagramSize protocol.ByteCount, now monotime.Time) {
	rttStats := bbr.rttStats
	qlogger := bbr.qlogger

	*bbr = BBRv3{}
	bbr.rttStats = rttStats
	bbr.qlogger = qlogger

	bbr.maxDatagramSize = initialMaxDatagramSize
	bbr.congestionWindow = initialMaxDatagramSize * initialCongestionWindow
	bbr.minPipeCwnd = 4 * initialMaxDatagramSize
	bbr.initialCwnd = initialMaxDatagramSize * initialCongestionWindow
	bbr.sendQuantum = 2 * initialMaxDatagramSize
	bbr.offloadBudget = bbr.sendQuantum
	bbr.state = BBRStartup
	bbr.probeBWPhase = probeBWDown
	bbr.ackPhase = ackPhaseInit
	bbr.pacingGain = STARTUP_PACING_GAIN
	bbr.cwndGain = STARTUP_CWND_GAIN
	bbr.bwLo = protocol.MaxByteCount
	bbr.inflightHi = protocol.MaxByteCount
	bbr.inflightLo = protocol.MaxByteCount
	bbr.ecnAlpha = ECN_ALPHA_UNIT
	bbr.sentPackets = make(map[protocol.PacketNumber]bbrSentPacketState)
	bbr.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	bbr.lastState = BBRStartup
	bbr.lastPhase = probeBWDown
	bbr.ackEpochStart = now
	bbr.undoBwLo = protocol.MaxByteCount
	bbr.undoInflightLo = protocol.MaxByteCount
	bbr.undoInflightHi = protocol.MaxByteCount
	if bbr.congestionWindow < bbr.minPipeCwnd {
		bbr.congestionWindow = bbr.minPipeCwnd
	}

	// Note: We intentionally do NOT initialize minRTT from rttStats.MinRTT() here.
	// The RTT stats may have a default value (e.g., 100ms) that isn't a real measurement.
	// BBR's minRTT should only be set from actual RTT samples in updateMinRTT().
	bbr.pacer = newPacer(bbr.bandwidthEstimateForPacer)
	bbr.initPacingRate()

	if bbr.qlogger != nil {
		bbr.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
		bbr.qlogger.RecordEvent(qlog.BBRv3StateUpdated{
			State:      bbr.state.String(),
			Phase:      "",
			RoundCount: bbr.roundCount,
		})
		bbr.qlogger.RecordEvent(bbr.qlogModelUpdate("init"))
		bbr.qlogger.RecordEvent(bbr.qlogControlUpdate("init"))
	}
}

// Name returns the name of this congestion controller.
func (bbr *BBRv3) Name() string { return "BBRv3" }

// TimeUntilSend returns the time when the next packet can be sent.
func (bbr *BBRv3) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return bbr.pacer.TimeUntilSend()
}

// HasPacingBudget returns true if there's budget to send at least one packet.
func (bbr *BBRv3) HasPacingBudget(now monotime.Time) bool {
	return bbr.pacer.Budget(now) >= bbr.maxDatagramSize
}

// CanSend returns true if bytes_in_flight is below the congestion window.
func (bbr *BBRv3) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < bbr.congestionWindow
}

// OnPacketSent is called when a packet is sent.
func (bbr *BBRv3) OnPacketSent(
	sentTime monotime.Time,
	bytesInFlight protocol.ByteCount,
	packetNumber protocol.PacketNumber,
	bytes protocol.ByteCount,
	isRetransmittable bool,
) {
	bbr.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}

	priorInFlight := protocol.ByteCount(0)
	if bytesInFlight > bytes {
		priorInFlight = bytesInFlight - bytes
	}
	// When nothing is in flight, initialize the delivery sampler timestamps.
	// This is needed for correct delivery rate calculation on first send and
	// after the pipe drains completely.
	if priorInFlight == 0 {
		bbr.firstSentTime = sentTime
		bbr.deliveredTime = sentTime
	}
	// RFC §5.4.1: idle restart requires BOTH zero inflight AND app-limited.
	// The app-limited condition distinguishes true idle (no data to send) from
	// transient zero-inflight (e.g., loss recovery draining the pipe).
	if priorInFlight == 0 && bbr.appLimitedUntil != 0 {
		bbr.idleRestart = true
		// RFC §5.4.1: reset ACK aggregation interval on idle restart.
		// Stale ackEpochStart from before idle would skew extra_acked calculation.
		bbr.ackEpochStart = sentTime
		bbr.ackEpochAcked = 0
		if bbr.state == BBRProbeBW {
			bbr.setPacingRateWithGain(1.0)
		} else if bbr.state == BBRProbeRTT {
			bbr.checkProbeRTTDone(sentTime)
		}
	}
	if bbr.isCwndLimitedInstantaneous(priorInFlight) {
		bbr.cwndLimitedInRound = true
	}

	// COLLISION DETECTION: PN-space collision during handshake.
	// BBR keys sentPackets by raw PacketNumber, which collides across QUIC's three
	// packet-number spaces (Initial, Handshake, AppData). During handshake,
	// Initial[0], Handshake[0], and 1-RTT[0] all map to key 0.
	if _, exists := bbr.sentPackets[packetNumber]; exists {
		if bbr.collisionPNs == nil {
			bbr.collisionPNs = make(map[protocol.PacketNumber]struct{})
		}
		bbr.collisionPNs[packetNumber] = struct{}{}
		delete(bbr.sentPackets, packetNumber)
		return
	}

	// Check if this PN has collided before
	if bbr.collisionPNs != nil {
		if _, isCollision := bbr.collisionPNs[packetNumber]; isCollision {
			return
		}
	}

	// App-limited detection per RFC §4.1.1.3: use bubble semantics, not cwnd utilization.
	// A packet is app-limited if sent while the app-limited bubble is active.
	// The bubble is set by MarkAppLimited() when send was allowed but no data available.
	isAppLimited := bbr.appLimitedUntil != 0
	bbr.sentPackets[packetNumber] = bbrSentPacketState{
		bytes:          bytes,
		delivered:      bbr.totalBytesAcked,
		deliveredTime:  bbr.deliveredTime,
		firstSentTime:  bbr.firstSentTime,
		sentTime:       sentTime,
		txInFlight:     bytesInFlight,
		isAppLimited:   isAppLimited,
		totalBytesLost: bbr.totalBytesLost,
	}
	bbr.totalBytesSent += uint64(bytes)
}

// MaybeExitSlowStart is called to potentially exit slow start.
// BBRv3 manages state transitions internally via model updates.
func (bbr *BBRv3) MaybeExitSlowStart() {
	// Managed by model/state updates on ACKs.
}

// OnPacketAcked is called when a packet is acknowledged.
// Per-packet ACKs are coalesced into ACK events and processed in OnAckEventEnd().
func (bbr *BBRv3) OnPacketAcked(
	ackedPacketNumber protocol.PacketNumber,
	ackedBytes protocol.ByteCount,
	priorInFlight protocol.ByteCount,
	eventTime monotime.Time,
) {
	if ackedBytes <= 0 {
		return
	}
	if bbr.pendingAckEventValid && !bbr.pendingAckEventTime.Equal(eventTime) {
		bbr.processPendingAckEvent(bbr.pendingAckEventTime)
	}

	st, ok := bbr.sentPackets[ackedPacketNumber]
	if !ok {
		// This packet was either:
		// 1. Part of a PN-space collision (detected on send, state never stored)
		// 2. Already processed and deleted
		// 3. A non-retransmittable packet (state never stored)
		//
		// We cannot make a meaningful observation about this packet. Make it
		// invisible to BBR's sampler, but preserve transport-level priorInFlight
		// which comes from the QUIC ackhandler, not BBR's per-packet tracking.
		//
		// NOTE: We intentionally do NOT consume pending ECN bytes here. In a
		// mixed ACK event (miss + real packets), consuming ECN on the miss would
		// steal CE bytes from real packets processed later in the same event.
		// All-miss events are cleaned up in OnAckEventEnd.
		if priorInFlight > bbr.pendingPriorInFlight {
			bbr.pendingPriorInFlight = priorInFlight
		}
		return
	}

	bbr.totalBytesAcked += uint64(ackedBytes)
	bbr.deliveredTime = eventTime

	// Clear app-limited bubble when we've delivered past the bubble boundary.
	// Per RFC §4.1.1.3: samples are app-limited until delivered > C.app_limited.
	if bbr.appLimitedUntil != 0 && bbr.totalBytesAcked > bbr.appLimitedUntil {
		bbr.appLimitedUntil = 0
	}

	if !bbr.pendingAckEventValid {
		bbr.pendingAckEventValid = true
		bbr.pendingAckEventTime = eventTime
		bbr.pendingPriorInFlight = priorInFlight
		bbr.pendingPriorDelivered = st.delivered
		bbr.pendingPriorTime = st.deliveredTime
		bbr.pendingSendElapsed = st.sentTime.Sub(st.firstSentTime)
		bbr.pendingTxInFlight = st.txInFlight
		bbr.pendingIsAppLimited = st.isAppLimited
		bbr.pendingTotalLostAtSend = st.totalBytesLost
		bbr.pendingNewestSentTime = st.sentTime
		bbr.pendingNewestPacketNum = ackedPacketNumber
		bbr.pendingCEBytes = bbr.consumePendingECNBytes(eventTime)
	} else {
		if priorInFlight > bbr.pendingPriorInFlight {
			bbr.pendingPriorInFlight = priorInFlight
		}
		if st.sentTime.After(bbr.pendingNewestSentTime) ||
			(st.sentTime.Equal(bbr.pendingNewestSentTime) && ackedPacketNumber > bbr.pendingNewestPacketNum) {
			bbr.pendingPriorDelivered = st.delivered
			bbr.pendingPriorTime = st.deliveredTime
			bbr.pendingSendElapsed = st.sentTime.Sub(st.firstSentTime)
			bbr.pendingTxInFlight = st.txInFlight
			bbr.pendingIsAppLimited = st.isAppLimited
			bbr.pendingTotalLostAtSend = st.totalBytesLost
			bbr.pendingNewestSentTime = st.sentTime
			bbr.pendingNewestPacketNum = ackedPacketNumber
		}
	}
	bbr.pendingAckedBytes += ackedBytes

	delete(bbr.sentPackets, ackedPacketNumber)
}

// OnCongestionEvent is called when a packet is declared lost.
func (bbr *BBRv3) OnCongestionEvent(
	packetNumber protocol.PacketNumber,
	lostBytes protocol.ByteCount,
	_ protocol.ByteCount,
) {
	if lostBytes <= 0 {
		return
	}
	// COLLISION CHECK: Skip loss processing for collided PNs.
	// PN-space collisions during handshake mean we don't have reliable state
	// for this packet number, so we must not corrupt the loss model.
	if bbr.collisionPNs != nil {
		if _, isCollision := bbr.collisionPNs[packetNumber]; isCollision {
			return
		}
	}

	bbr.totalBytesLost += uint64(lostBytes)
	bbr.bytesLostInRound += lostBytes
	bbr.noteLoss()
	// Count loss events per loss-detection pass, not per packet, per RFC §5.3.1.3.
	// Startup loss exit requires BBRStartupFullLossCnt=6 discontiguous loss events
	// per round trip. Multiple packets lost in the same pass count as one event.
	if !bbr.lossEventCountedThisACK && bbr.lossEventsInRound < math.MaxInt32 {
		bbr.lossEventsInRound++
		bbr.lossEventCountedThisACK = true
	}

	st, ok := bbr.sentPackets[packetNumber]
	if !ok {
		return
	}
	defer delete(bbr.sentPackets, packetNumber)

	if !bbr.bwProbeSamples {
		return
	}

	rs := bbrRateSample{
		txInFlight:   st.txInFlight,
		lost:         protocol.ByteCount(bbr.totalBytesLost - st.totalBytesLost),
		isAppLimited: st.isAppLimited,
	}
	if bbr.isInflightTooHigh(rs) {
		rs.txInFlight = bbr.inflightHiFromLostPacket(rs, lostBytes)
		bbr.handleInflightTooHigh(rs)
	}
}

// OnRetransmissionTimeout is a legacy hook on the SendAlgorithm interface.
// QUIC ackhandler drives RTO/PTO recovery via OnPTO with bytesInFlight.
// This method is intentionally a no-op for BBRv3.
func (bbr *BBRv3) OnRetransmissionTimeout(_ bool) {
	// The previous implementation called enterTimeoutRecovery(0), which
	// violated §5.6.4.4's requirement that cwnd = inflight + 1 SMSS.
	// Rather than pass incorrect state, we do nothing — the correct path
	// is OnPTO, which receives bytesInFlight from the ackhandler.
}

func (bbr *BBRv3) OnPTO(bytesInFlight protocol.ByteCount) {
	bbr.enterTimeoutRecovery(bytesInFlight)
}

func (bbr *BBRv3) enterTimeoutRecovery(bytesInFlight protocol.ByteCount) {
	if !bbr.ptoRecovery {
		bbr.saveCwnd()
		bbr.saveStateUponLoss()
		bbr.ptoRecovery = true
	} else {
		bbr.priorCwnd = max(bbr.priorCwnd, bbr.congestionWindow)
	}
	bbr.congestionWindow = max(bytesInFlight+bbr.maxDatagramSize, bbr.maxDatagramSize)
}

// SetMaxDatagramSize updates the max datagram size.
func (bbr *BBRv3) SetMaxDatagramSize(size protocol.ByteCount) {
	if size == bbr.maxDatagramSize {
		return
	}
	old := bbr.maxDatagramSize
	if old > 0 && bbr.congestionWindow > old {
		bbr.congestionWindow = bbr.congestionWindow * size / old
	}
	bbr.maxDatagramSize = size
	bbr.minPipeCwnd = 4 * size
	if bbr.congestionWindow < bbr.minPipeCwnd {
		bbr.congestionWindow = bbr.minPipeCwnd
	}
	bbr.pacer.SetMaxDatagramSize(size)
}

// InSlowStart returns true if in BBRStartup state.
func (bbr *BBRv3) InSlowStart() bool { return bbr.state == BBRStartup }

// InRecovery returns true if loss or ECN signals are present.
func (bbr *BBRv3) InRecovery() bool {
	return bbr.lossInRound || bbr.lossInCycle
}

// GetCongestionWindow returns the current congestion window.
func (bbr *BBRv3) GetCongestionWindow() protocol.ByteCount {
	return bbr.congestionWindow
}

// BandwidthEstimate returns the current pacing rate (gain-adjusted, with 1%
// margin applied per §5.6.2). This is the logical rate BBR uses for control
// decisions. The actual pacer may apply additional multipliers — see
// bandwidthEstimateForPacer() for the rate passed to the shared pacer.
func (bbr *BBRv3) BandwidthEstimate() Bandwidth {
	if bbr.pacingRate > 0 {
		return Bandwidth(bbr.pacingRate) * BytesPerSecond
	}
	return Bandwidth(max(bbr.nominalBandwidth(), 1)) * BytesPerSecond
}

// bandwidthEstimateForPacer returns the rate the shared pacer should schedule at.
// The shared pacer applies a Reno-era 5/4 multiplier to compensate for RTT
// variation in controllers that don't compute a dynamic pacing gain. BBRv3
// already encodes pacing_gain and the 1% margin in bbr.pacingRate per
// draft-ietf-ccwg-bbr-05 §5.6.2, so we pre-divide by 5/4 here to neutralize
// the pacer's multiplier.
// This method exists only because the pacer applies a Reno-era 5/4 multiplier;
// remove when newPacer accepts a multiplier parameter.
func (bbr *BBRv3) bandwidthEstimateForPacer() Bandwidth {
	rate := bbr.pacingRate
	if rate <= 0 {
		rate = max(bbr.nominalBandwidth(), 1)
	}
	// Note: rate * 4 / 5 (multiply-then-divide) preserves integer precision for
	// byte-count math. Do not reorder to rate / 5 * 4.
	rate = rate * 4 / 5
	return Bandwidth(max(rate, 1)) * BytesPerSecond
}

// OnAckEventEnd flushes the ACK-event coalescing bucket for the current ACK frame.
// This implements Linux-like "one model update per ACK event" semantics.
func (bbr *BBRv3) OnAckEventEnd(eventTime monotime.Time) {
	if bbr.pendingAckEventValid && bbr.pendingAckEventTime.Equal(eventTime) {
		bbr.processPendingAckEvent(eventTime)
	}
	// If the ACK event contained only missed/collided packets, no real pending
	// ACK event was created and therefore no packet consumed pending ECN bytes.
	// Clear ECN state for this event so stale CE bytes cannot leak into a later
	// same-timestamp event, while preserving ECN for mixed miss+real events.
	if !bbr.pendingAckEventValid &&
		bbr.pendingECNEventValid &&
		bbr.pendingECNEventTime.Equal(eventTime) {
		bbr.pendingECNEventValid = false
		bbr.pendingECNCEBytes = 0
	}
}

// OnLossDetectionStart is called by ackhandler before each loss-detection pass
// (both ACK-driven and timer-driven). This resets per-pass loss event counting
// so that multiple lost packets in the same pass count as one loss event.
// Per RFC §5.3.1.3, Startup loss exit uses event count, not packet count.
func (bbr *BBRv3) OnLossDetectionStart() {
	bbr.lossEventCountedThisACK = false
}

// OnAckEventStart is called by ackhandler after loss detection but before ACK callbacks.
// This captures the post-loss bytesInFlight and ACK event timing for accurate phase transitions.
// Per RFC §4.2, BBR needs the correct inflight state when making model/phase decisions.
func (bbr *BBRv3) OnAckEventStart(eventTime monotime.Time, bytesInFlight protocol.ByteCount) {
	bbr.ackEventBytesInFlight = bytesInFlight
	bbr.ackEventTime = eventTime
}

// MarkAppLimited implements RFC §4.1.2.4 (Detecting application-limited phases).
//
// An "app-limited bubble" begins when the application could send but has no data:
//   - Congestion window allows sending (C.inflight < C.cwnd)
//   - Pacing rate allows sending
//   - Yet there is no data to send (NoUnsentData() && pending_transmissions == 0)
//
// Per RFC: "This idle time means that any delivery rate sample obtained from
// this data packet, and any rate sample from a packet that follows it in the
// next round trip, is an application-limited sample that potentially
// underestimates the true available bandwidth."
//
// The bubble extends until C.delivered > C.app_limited (the bubble has "exited"
// the data pipeline). Samples sent during the bubble have P.is_app_limited=true
// and are excluded from the full-bandwidth estimator in checkFullBwReached().
func (bbr *BBRv3) MarkAppLimited(bytesInFlight protocol.ByteCount) {
	// Per RFC §4.1.1.3: app_limited = (delivered + bytes_in_flight) ? : 1
	// The bubble ends when we've delivered past this point.
	bbr.appLimitedUntil = bbr.totalBytesAcked + uint64(bytesInFlight)
	if bbr.appLimitedUntil == 0 {
		bbr.appLimitedUntil = 1 // Ensure non-zero to indicate app-limited state
	}
}

// OnECNFeedback provides ACK-frame ECN counters from ackhandler.
// Converts absolute counters into deltas for internal tracking.
func (bbr *BBRv3) OnECNFeedback(
	ackedBytes protocol.ByteCount,
	ect0Total, ect1Total, ceTotal int64,
	_ protocol.ByteCount,
	eventTime monotime.Time,
) {
	if ackedBytes <= 0 {
		return
	}
	ect0Delta := max(ect0Total-bbr.ecnAckedECT0, int64(0))
	ect1Delta := max(ect1Total-bbr.ecnAckedECT1, int64(0))
	ceDelta := max(ceTotal-bbr.ecnAckedCE, int64(0))
	if ect0Total > bbr.ecnAckedECT0 {
		bbr.ecnAckedECT0 = ect0Total
	}
	if ect1Total > bbr.ecnAckedECT1 {
		bbr.ecnAckedECT1 = ect1Total
	}
	if ceTotal > bbr.ecnAckedCE {
		bbr.ecnAckedCE = ceTotal
	}

	total := ect0Delta + ect1Delta + ceDelta
	if total <= 0 {
		return
	}

	// Surgical guard: do not feed ECN into the BBR model until minRTT is real
	// AND within the low-RTT eligibility envelope.
	// Per M1a: minRTT == 0 means no RTT sample yet, so we cannot trust ECN feedback.
	if bbr.minRTT <= 0 || (ECN_MAX_RTT != 0 && bbr.minRTT > ECN_MAX_RTT) {
		return // Don't store pendingECNCEBytes before eligibility
	}
	// On eligibility transition: seed alpha baseline from current totals.
	// Without this, the first CE ratio would be diluted by historical bytes
	// delivered before ECN feedback was trustworthy.
	if !bbr.ecnEligible {
		bbr.alphaLastDelivered = bbr.totalBytesAcked
		bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE
	}
	bbr.ecnEligible = true

	ceBytes := protocol.ByteCount(uint64(ackedBytes) * uint64(ceDelta) / uint64(max(total, int64(1))))
	bbr.pendingECNEventValid = true
	bbr.pendingECNEventTime = eventTime
	bbr.pendingECNCEBytes = ceBytes
}

// SetRTTStats allows late binding of RTT stats for custom controllers.
func (bbr *BBRv3) SetRTTStats(rttStats *utils.RTTStats) {
	bbr.rttStats = rttStats
}

// processPendingAckEvent processes the coalesced ACK event.
// This is the main model update path, following Linux tcp_bbr.c structure.
func (bbr *BBRv3) processPendingAckEvent(now monotime.Time) {
	if !bbr.pendingAckEventValid || bbr.pendingAckedBytes == 0 {
		bbr.clearPendingAckEvent()
		return
	}

	bytesInFlight := bbr.bytesInFlightForAckEvent()

	rs := bbrRateSample{
		newlyAcked:     bbr.pendingAckedBytes,
		delivered:      protocol.ByteCount(bbr.totalBytesAcked - bbr.pendingPriorDelivered),
		deliveredCE:    bbr.pendingCEBytes,
		sendElapsed:    bbr.pendingSendElapsed,
		ackElapsed:     now.Sub(bbr.pendingPriorTime),
		txInFlight:     bbr.pendingTxInFlight,
		priorInFlight:  bbr.pendingPriorInFlight,
		bytesInFlight:  bytesInFlight,
		priorDelivered: bbr.pendingPriorDelivered,
		lost:           protocol.ByteCount(bbr.totalBytesLost - bbr.pendingTotalLostAtSend),
		isAppLimited:   bbr.pendingIsAppLimited,
	}
	rs.interval = maxDuration(rs.sendElapsed, rs.ackElapsed)
	if rs.interval > 0 && rs.delivered > 0 {
		rs.deliveryRate = protocol.ByteCount(uint64(rs.delivered) * uint64(time.Second) / uint64(rs.interval))
	}
	// Per RFC §4.1.2.3, suppress delivery_rate when interval < min_rtt.
	// The ACK still carries valid delivered-volume and round-boundary signals;
	// only the rate sample itself is unreliable.
	if bbr.minRTT > 0 && rs.interval < bbr.minRTT {
		rs.deliveryRate = 0
	}
	bbr.totalBytesAckedCE += uint64(rs.deliveredCE)

	// Linux-v3 model update order (collapsed from tcp_bbr.c helpers):
	// 1) round / delivery signal bookkeeping
	// 2) ECN alpha + congestion signals
	// 3) bounds adaptation (lower + upper)
	// 4) state transitions (STARTUP/DRAIN/PROBE_BW/PROBE_RTT)
	// 5) control outputs (pacing, send quantum, cwnd)
	bbr.updateRoundStart(rs)
	bbr.updateECNAlpha(rs)
	bbr.updateLatestDeliverySignals(rs)
	bbr.updateCongestionSignals(rs)
	bbr.updateAckAggregation(rs, now)
	bbr.checkLossTooHighInStartup(rs)
	bbr.checkFullBwReached(rs)
	bbr.checkDrain(rs, now)
	bbr.updateCyclePhase(rs, now)
	bbr.updateMinRTT(now)
	bbr.updateGains()
	bbr.setPacingRateWithGain(bbr.pacingGain)
	bbr.setSendQuantum()
	bbr.setCwnd(rs)
	bbr.advanceLatestDeliverySignals(rs)

	if rs.delivered > 0 {
		bbr.idleRestart = false
		bbr.ptoRecovery = false
	}
	// RFC §4.1.2.3 UpdateRateSample(): after processing the newest packet in the
	// ACK event, C.first_send_time becomes that packet's send_time. Future packets
	// sent while data remains in flight must inherit this updated origin so that
	// send_elapsed measures from the latest delivery-curve knee, not from an
	// increasingly stale connection-start timestamp.
	if !bbr.pendingNewestSentTime.IsZero() {
		bbr.firstSentTime = bbr.pendingNewestSentTime
	}
	bbr.maybeQlogStateChange()
	bbr.maybeQlogRoundUpdate(rs)
	bbr.clearPendingAckEvent()
}

func (bbr *BBRv3) clearPendingAckEvent() {
	bbr.pendingAckEventValid = false
	bbr.pendingAckedBytes = 0
	bbr.pendingPriorInFlight = 0
	bbr.pendingPriorDelivered = 0
	bbr.pendingPriorTime = 0
	bbr.pendingSendElapsed = 0
	bbr.pendingTxInFlight = 0
	bbr.pendingIsAppLimited = false
	bbr.pendingTotalLostAtSend = 0
	bbr.pendingCEBytes = 0
	bbr.pendingNewestSentTime = 0
	bbr.pendingNewestPacketNum = 0
	// Clear ACK-event state from OnAckEventStart
	bbr.ackEventBytesInFlight = 0
	bbr.ackEventTime = 0
}

func (bbr *BBRv3) consumePendingECNBytes(t monotime.Time) protocol.ByteCount {
	if !bbr.pendingECNEventValid || !bbr.pendingECNEventTime.Equal(t) {
		return 0
	}
	v := bbr.pendingECNCEBytes
	bbr.pendingECNEventValid = false
	bbr.pendingECNCEBytes = 0
	return v
}

func (bbr *BBRv3) bytesInFlightAfterACK() protocol.ByteCount {
	if bbr.pendingPriorInFlight <= bbr.pendingAckedBytes {
		return 0
	}
	return bbr.pendingPriorInFlight - bbr.pendingAckedBytes
}

func (bbr *BBRv3) bytesInFlightForAckEvent() protocol.ByteCount {
	if !bbr.ackEventTime.IsZero() {
		if bbr.ackEventBytesInFlight <= bbr.pendingAckedBytes {
			return 0
		}
		return bbr.ackEventBytesInFlight - bbr.pendingAckedBytes
	}
	return bbr.bytesInFlightAfterACK()
}

// updateRoundStart checks for packet-timed round trip boundary crossing.
// Per RFC §5.5.1 (BBR.round_count: Tracking Packet-Timed Round Trips):
//
// A round trip ends when the ACK for a packet sent after the start of the
// current round arrives. We track this by:
//   1. On round start, set next_round_delivered = C.delivered
//   2. When an ACK has P.delivered >= next_round_delivered, the round ends
//
// This is fundamentally different from wall-clock RTT: it measures the time
// for a flight of data to traverse the path, providing a natural unit for
// bandwidth probing and model updates that is robust to ACK compression/delays.
func (bbr *BBRv3) updateRoundStart(rs bbrRateSample) {
	bbr.roundStart = false
	if rs.priorDelivered < bbr.nextRoundDelivered {
		return
	}
	bbr.roundStart = true
	bbr.cwndLimitedPrevRound = bbr.cwndLimitedInRound
	bbr.cwndLimitedInRound = false
	bbr.roundCount++
	if bbr.roundsSinceProbe < math.MaxUint64 {
		bbr.roundsSinceProbe++
	}
	bbr.nextRoundDelivered = bbr.totalBytesAcked
}

// updateECNAlpha updates the ECN alpha EWMA using fixed-point bit-shift arithmetic.
// This is an IMPLEMENTATION CHOICE following tcp_bbr.c bbr_update_ecn_alpha().
// The RFC does not mandate this formula - see §3.7.
func (bbr *BBRv3) updateECNAlpha(_ bbrRateSample) {
	if !bbr.roundStart || !bbr.ecnEligible {
		return
	}
	delivered := bbr.totalBytesAcked - bbr.alphaLastDelivered
	deliveredCE := bbr.totalBytesAckedCE - bbr.alphaLastDeliveredCE
	if delivered == 0 {
		return
	}
	// ceRatioScaled is CE ratio in fixed-point [0, ECN_ALPHA_UNIT].
	ceRatioScaled := uint32(deliveredCE * ECN_ALPHA_UNIT / delivered)
	if ceRatioScaled > ECN_ALPHA_UNIT {
		ceRatioScaled = ECN_ALPHA_UNIT
	}
	// EWMA: alpha = alpha - (alpha >> 4) + (ceRatio >> 4), i.e. g = 1/16.
	oldAlpha := bbr.ecnAlpha
	bbr.ecnAlpha = bbr.ecnAlpha - (bbr.ecnAlpha >> ECN_ALPHA_GAIN_SHIFT) + (ceRatioScaled >> ECN_ALPHA_GAIN_SHIFT)
	if bbr.ecnAlpha > ECN_ALPHA_UNIT {
		bbr.ecnAlpha = ECN_ALPHA_UNIT
	}
	bbr.alphaLastDelivered = bbr.totalBytesAcked
	bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE

	// Qlog ECN update if alpha changed significantly (threshold ~1% of full scale)
	alphaThresh := uint32(ECN_ALPHA_UNIT / 100)
	var diff uint32
	if bbr.ecnAlpha > oldAlpha {
		diff = bbr.ecnAlpha - oldAlpha
	} else {
		diff = oldAlpha - bbr.ecnAlpha
	}
	if bbr.qlogger != nil && (oldAlpha == ECN_ALPHA_UNIT || diff > alphaThresh) {
		bbr.qlogger.RecordEvent(qlog.BBRv3ECNUpdated{
			ECNAlpha:    float64(bbr.ecnAlpha) / float64(ECN_ALPHA_UNIT),
			ECNEligible: bbr.ecnEligible,
		})
	}

	// Check for excessive ECN in startup per tcp_bbr.c
	ceRatioFloat := float64(ceRatioScaled) / float64(ECN_ALPHA_UNIT)
	if bbr.state == BBRStartup && !bbr.fullBandwidthReached {
		if ceRatioFloat >= ECN_THRESH {
			bbr.startupECNRounds++
		} else {
			bbr.startupECNRounds = 0
		}
		if bbr.startupECNRounds >= FULL_ECN_ROUNDS {
			bbr.handleQueueTooHighInStartup()
		}
	}
}

func (bbr *BBRv3) updateLatestDeliverySignals(rs bbrRateSample) {
	bbr.lossRoundStart = false
	if rs.newlyAcked <= 0 {
		return
	}
	if rs.deliveryRate > 0 {
		bbr.bwLatest = max(bbr.bwLatest, rs.deliveryRate)
	}
	bbr.inflightLatest = max(bbr.inflightLatest, rs.delivered)
	if rs.priorDelivered >= bbr.lossRoundDelivered {
		bbr.lossRoundDelivered = bbr.totalBytesAcked
		bbr.lossRoundStart = true
	}
}

func (bbr *BBRv3) advanceLatestDeliverySignals(rs bbrRateSample) {
	if bbr.lossRoundStart {
		// Guard: only reset bwLatest from valid samples (not suppressed by min_rtt)
		if rs.deliveryRate > 0 {
			bbr.bwLatest = rs.deliveryRate
		}
		bbr.inflightLatest = rs.delivered
		bbr.bytesLostInRound = 0
	}
}

func (bbr *BBRv3) updateCongestionSignals(rs bbrRateSample) {
	// Note: Invalid samples (interval < min_rtt) are already suppressed at the source
	// in processPendingAckEvent(), so rs.deliveryRate == 0 for such samples.
	if rs.deliveryRate > 0 && (!rs.isAppLimited || rs.deliveryRate >= bbr.maxBandwidth()) {
		bbr.takeMaxBwSample(rs.deliveryRate)
	}
	bbr.lossInRound = bbr.lossInRound || rs.lost > 0
	bbr.ecnInRound = bbr.ecnInRound || rs.deliveredCE > 0
	if !bbr.lossRoundStart {
		return
	}
	bbr.adaptLowerBounds(rs)
	bbr.lossInRound = false
	bbr.ecnInRound = false
}

// adaptLowerBounds implements short-term model adaptation per RFC §5.5.10.
//
// The short-term model (bw_shortterm, inflight_shortterm) responds to recent
// congestion signals, while the long-term model (max_bw, inflight_longterm)
// maintains a robust history for probing. This function adapts the short-term
// model on loss_round boundaries (not every ACK).
//
// Loss response (§5.5.10.1):
//   bwLo = max(bwLatest, bwLo * (1 - BETA))           ; BETA = 0.30
//   inflightLo = max(inflightLatest, inflightLo * (1 - BETA))
//
// ECN response (tcp_bbr.c bbr_adapt_lower_bounds, not RFC-specified):
//   inflightLo = inflightLo * (1 - ecnAlpha * ECN_FACTOR) ; ECN_FACTOR = 1/3
//
// Note: Probing phases (Startup, REFILL, UP) skip lower-bound adaptation
// to allow aggressive probing per isProbingBandwidth().
func (bbr *BBRv3) adaptLowerBounds(bbrRateSample) {
	if bbr.isProbingBandwidth() {
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
		bbr.initLowerBounds(true)
		cut := 1.0 - BETA_REDUCTION
		bbr.bwLo = max(bbr.bwLatest, protocol.ByteCount(float64(bbr.bwLo)*cut))
		bbr.inflightLo = max(bbr.inflightLatest, protocol.ByteCount(float64(bbr.inflightLo)*cut))
	}
	if ecnInflightLo != protocol.MaxByteCount {
		bbr.inflightLo = min(bbr.inflightLo, ecnInflightLo)
	}
	if bbr.bwLo == 0 {
		bbr.bwLo = 1
	}
}

func (bbr *BBRv3) isProbingBandwidth() bool {
	if bbr.state == BBRStartup {
		return true
	}
	return bbr.state == BBRProbeBW && (bbr.probeBWPhase == probeBWUp || bbr.probeBWPhase == probeBWRefill)
}

func (bbr *BBRv3) initLowerBounds(initBW bool) {
	if initBW && bbr.bwLo == protocol.MaxByteCount {
		bbr.bwLo = bbr.maxBandwidth()
	}
	if bbr.inflightLo == protocol.MaxByteCount {
		bbr.inflightLo = bbr.congestionWindow
	}
}

func (bbr *BBRv3) resetLowerBounds() {
	bbr.bwLo = protocol.MaxByteCount
	bbr.inflightLo = protocol.MaxByteCount
}

func (bbr *BBRv3) takeMaxBwSample(bw protocol.ByteCount) {
	bbr.bwHi[1] = max(bw, bbr.bwHi[1])
}

func (bbr *BBRv3) advanceMaxBwFilter() {
	if bbr.bwHi[1] == 0 {
		return
	}
	bbr.bwHi[0] = bbr.bwHi[1]
	bbr.bwHi[1] = 0
}

func (bbr *BBRv3) maxBandwidth() protocol.ByteCount {
	return max(bbr.bwHi[0], bbr.bwHi[1])
}

func (bbr *BBRv3) boundedBandwidth() protocol.ByteCount {
	bw := bbr.maxBandwidth()
	if bbr.bwLo != protocol.MaxByteCount {
		bw = min(bw, bbr.bwLo)
	}
	return max(bw, protocol.ByteCount(1))
}

// checkLossTooHighInStartup checks for excessive loss in startup per tcp_bbr.c.
// The RFC §5.3.1.3 checks "in fast recovery for at least one full round trip".
// This implementation encodes that criterion differently: noteLoss() snapshots
// lossRoundDelivered on first loss, and lossRoundStart only becomes true after
// delivery crosses that point — which is the equivalent of one full round.
func (bbr *BBRv3) checkLossTooHighInStartup(rs bbrRateSample) {
	if bbr.fullBandwidthReached {
		return
	}
	// State-gate: this estimator only applies to Startup. ProbeRTT can be entered
	// before fullBandwidthReached (via probe_rtt_interval expiry), and loss during
	// ProbeRTT's reduced cwnd must not trigger Startup's high-loss exit.
	if bbr.state != BBRStartup {
		return
	}
	if bbr.lossRoundStart && bbr.lossEventsInRound >= STARTUP_FULL_LOSS_COUNT {
		s := rs
		s.lost = bbr.bytesLostInRound
		if s.txInFlight == 0 {
			s.txInFlight = max(rs.priorInFlight, rs.txInFlight)
		}
		if bbr.isInflightTooHigh(s) {
			bbr.handleQueueTooHighInStartup()
		}
	}
	if bbr.lossRoundStart {
		bbr.lossEventsInRound = 0
	}
}

func (bbr *BBRv3) handleQueueTooHighInStartup() {
	bbr.fullBandwidthReached = true
	bdp := bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0)
	bbr.inflightHi = max(bdp, bbr.inflightLatest)
}

// checkFullBwReached implements the "filled pipe" estimator per
// RFC §5.3.1.2 (Exiting Acceleration Based on Bandwidth Plateau).
//
// The algorithm detects bandwidth saturation by looking for a plateau in
// RS.delivery_rate across multiple packet-timed round trips:
//   1. If delivery_rate >= full_bw * 1.25 (25% growth), reset counter
//   2. Otherwise, increment full_bw_count
//   3. After 3 consecutive rounds without 25% growth, declare filled pipe
//
// CRITICAL: This function MUST only run on round_start boundaries.
// Per RFC §5.3.1.2: "upon an ACK...when the delivery rate sample is not
// application-limited, BBR runs the 'full pipe' estimator."
// The round_start gate ensures bandwidth growth is evaluated once per
// round trip, not on every ACK. Without this gate, intra-round delivery
// rate fluctuations would repeatedly reset the counter, preventing Startup
// from ever detecting a bandwidth plateau.
//
// State-gate: this estimator only applies to Startup. ProbeRTT can be entered
// before fullBandwidthReached (via probe_rtt_interval expiry), and the reduced
// cwnd would cause spurious bandwidth plateaus. ProbeBW_UP has its own plateau
// detection in updateCyclePhase().
func (bbr *BBRv3) checkFullBwReached(rs bbrRateSample) {
	if bbr.state != BBRStartup {
		return
	}
	if bbr.fullBandwidthNow || !bbr.roundStart || rs.isAppLimited || rs.deliveryRate == 0 {
		return
	}
	thresh := protocol.ByteCount(float64(max(bbr.fullBandwidth, 1)) * FULL_BW_GROWTH_THRESHOLD)
	if rs.deliveryRate >= thresh {
		bbr.resetFullBw()
		bbr.fullBandwidth = rs.deliveryRate
		return
	}
	bbr.fullBandwidthCount++
	bbr.fullBandwidthNow = bbr.fullBandwidthCount >= FULL_BW_ROUNDS
	if bbr.fullBandwidthNow {
		bbr.fullBandwidthReached = true
	}
}

func (bbr *BBRv3) resetFullBw() {
	bbr.fullBandwidth = 0
	bbr.fullBandwidthCount = 0
	bbr.fullBandwidthNow = false
}

// checkDrain implements STARTUP -> DRAIN -> ProbeBW state transitions.
// Per RFC §5.3.2 (Drain):
//
// When full_bw_reached becomes true, Startup has filled the pipe and
// potentially created a queue of up to (cwnd_gain - 1) * BDP ≈ 1 * BDP.
// Drain state aims to quickly drain this queue by using pacing_gain = 0.5.
//
// Exit conditions (RFC §5.3.2 BBRCheckDrainDone):
//   1. Normal exit: C.inflight <= BDP (queue drained)
//   2. Fallback exit: round_count > drain_start_round + 3 (bandwidth overestimated)
//
// The fallback handles Startup bandwidth overestimation due to competing flows.
// After 3 rounds, the max_bw filter will advance during the next probing cycle.
func (bbr *BBRv3) checkDrain(rs bbrRateSample, now monotime.Time) {
	if bbr.state == BBRStartup && bbr.fullBandwidthReached {
		bbr.state = BBRDrain
		bbr.drainStartRound = bbr.roundCount
		bbr.resetCongestionSignals()
	}
	if bbr.state == BBRDrain {
		// draft-ietf-ccwg-bbr-05 §5.3.2 exits Drain when inflight drops to BDP,
		// or when round_count advances more than 3 rounds past drain_start_round.
		if rs.bytesInFlight <= bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0) ||
			bbr.roundCount > bbr.drainStartRound+DRAIN_MAX_ROUNDS {
			bbr.state = BBRProbeBW
			bbr.startProbeBWDown(now)
		}
	}
}

// updateCyclePhase implements ProbeBW phase cycling per RFC §5.3.3.
//
// ProbeBW uses a four-phase cycle: DOWN -> CRUISE -> REFILL -> UP -> DOWN
// Each phase serves a specific purpose in the steady-state algorithm:
//
//   DOWN (§5.3.3.1):   Decelerate (pacing_gain=0.90) to drain any queue built
//                      during UP, leave headroom for other flows.
//
//   CRUISE (§5.3.3.2): Match sending rate to delivery rate (pacing_gain=1.0),
//                      respond to loss/ECN by reducing bw_shortterm/inflight_shortterm.
//
//   REFILL (§5.3.3.3): Reset short-term model, refill pipe at pacing_gain=1.0
//                      for one round to avoid premature loss when probing.
//
//   UP (§5.3.3.4):     Probe for bandwidth (pacing_gain=1.25, cwnd_gain=2.25),
//                      exit on full_bw_now or loss rate > 2%.
func (bbr *BBRv3) updateCyclePhase(rs bbrRateSample, now monotime.Time) {
	if !bbr.fullBandwidthReached {
		return
	}
	// ProbeBW phase machine:
	// CRUISE -> (time/reno trigger) -> REFILL -> (round) -> UP -> (full_bw or too_high) -> DOWN -> CRUISE
	if bbr.adaptUpperBounds(rs, now) {
		return
	}
	if bbr.state != BBRProbeBW {
		return
	}

	switch bbr.probeBWPhase {
	case probeBWCruise:
		if bbr.checkTimeToProbeBW(now) {
			bbr.startProbeBWRefill(now, 0)
		}
	case probeBWRefill:
		if bbr.roundStart {
			bbr.bwProbeSamples = true
			bbr.startProbeBWUp(now, rs.deliveryRate)
		}
	case probeBWUp:
		if bbr.prevProbeTooHigh && rs.bytesInFlight >= bbr.inflightHi {
			bbr.stoppedRiskyProbe = true
			bbr.prevProbeTooHigh = false
			bbr.startProbeBWDown(now)
			return
		}
		if bbr.isRoundCwndLimited(rs.priorInFlight) && bbr.congestionWindow >= bbr.inflightHi {
			bbr.resetFullBw()
			// Guard: only seed fullBandwidth from valid samples (not suppressed by min_rtt)
			if rs.deliveryRate > 0 {
				bbr.fullBandwidth = rs.deliveryRate
			}
		} else if bbr.fullBandwidthNow {
			bbr.prevProbeTooHigh = false
			bbr.startProbeBWDown(now)
		}
	case probeBWDown:
		if bbr.checkTimeToProbeBW(now) {
			bbr.startProbeBWRefill(now, 0)
			return
		}
		if bbr.checkTimeToCruise(rs.bytesInFlight) {
			bbr.startProbeBWCruise(now)
		}
	}
}

// adaptUpperBounds implements upper-bound adaptation per tcp_bbr.c bbr_adapt_upper_bounds().
func (bbr *BBRv3) adaptUpperBounds(rs bbrRateSample, now monotime.Time) bool {
	if bbr.ackPhase == ackPhaseProbeStarting && bbr.roundStart {
		bbr.ackPhase = ackPhaseProbeFeedback
	}
	if bbr.ackPhase == ackPhaseProbeStopping && bbr.roundStart {
		bbr.bwProbeSamples = false
		bbr.ackPhase = ackPhaseInit
		if bbr.state == BBRProbeBW && !rs.isAppLimited {
			bbr.advanceMaxBwFilter()
		}
		if bbr.state == BBRProbeBW && bbr.stoppedRiskyProbe && !bbr.prevProbeTooHigh {
			bbr.startProbeBWRefill(now, 0)
			return true
		}
	}

	if bbr.isInflightTooHigh(rs) {
		if bbr.bwProbeSamples {
			bbr.handleInflightTooHigh(rs)
		}
		return false
	}

	if bbr.inflightHi == protocol.MaxByteCount {
		return false
	}
	if rs.txInFlight > bbr.inflightHi {
		bbr.inflightHi = rs.txInFlight
	}
	if bbr.state == BBRProbeBW && bbr.probeBWPhase == probeBWUp {
		bbr.probeInflightHiUpward(rs)
	}
	return false
}

func (bbr *BBRv3) handleInflightTooHigh(rs bbrRateSample) {
	bbr.prevProbeTooHigh = true
	bbr.bwProbeSamples = false
	if !rs.isAppLimited {
		target := protocol.ByteCount(float64(bbr.targetInflight()) * (1.0 - BETA_REDUCTION))
		bbr.inflightHi = max(rs.txInFlight, target)
	}
	if bbr.state == BBRProbeBW && bbr.probeBWPhase == probeBWUp {
		// Use the ACK event time from OnAckEventStart when available.
		// This provides correct timing when loss triggers phase transition.
		eventTime := bbr.ackEventTime
		if eventTime.IsZero() {
			eventTime = bbr.pendingAckEventTime
		}
		bbr.startProbeBWDown(eventTime)
	}
}

func (bbr *BBRv3) probeInflightHiUpward(rs bbrRateSample) {
	if !bbr.isRoundCwndLimited(rs.priorInFlight) || bbr.congestionWindow < bbr.inflightHi {
		return
	}
	// Convert bytes to packets (round up to avoid under-counting)
	// Per RFC/tcp_bbr.c, this logic works in packet units, not bytes.
	mss := max(bbr.maxDatagramSize, 1)
	ackedPkts := (rs.newlyAcked + mss - 1) / mss
	bbr.bwProbeUpAcks += ackedPkts
	if bbr.bwProbeUpCnt == 0 {
		bbr.raiseInflightHiSlope()
	}
	if bbr.bwProbeUpCnt > 0 && bbr.bwProbeUpAcks >= bbr.bwProbeUpCnt {
		delta := bbr.bwProbeUpAcks / bbr.bwProbeUpCnt
		bbr.bwProbeUpAcks -= delta * bbr.bwProbeUpCnt
		// Grow inflightHi by delta * MSS (packet-sized steps)
		bbr.inflightHi += protocol.ByteCount(delta) * mss
	}
	if bbr.roundStart {
		bbr.raiseInflightHiSlope()
	}
}

func (bbr *BBRv3) raiseInflightHiSlope() {
	// Per tcp_bbr.c: probe_up_cnt is in packets
	growthThisRound := protocol.ByteCount(1) << bbr.bwProbeUpRounds
	if bbr.bwProbeUpRounds < 30 {
		bbr.bwProbeUpRounds++
	}
	// Convert cwnd to packets for the calculation
	mss := max(bbr.maxDatagramSize, 1)
	cwndPkts := bbr.congestionWindow / mss
	cnt := cwndPkts / max(growthThisRound, 1)
	bbr.bwProbeUpCnt = max(cnt, 1)
}

func (bbr *BBRv3) checkTimeToProbeBW(now monotime.Time) bool {
	if !bbr.cycleStamp.IsZero() && now.Sub(bbr.cycleStamp) > bbr.probeWait {
		return true
	}
	if bbr.isRenoCoexistenceProbeTime() {
		return true
	}
	return false
}

func (bbr *BBRv3) checkTimeToCruise(inflight protocol.ByteCount) bool {
	if inflight > bbr.inflightWithHeadroom() {
		return false
	}
	return inflight <= bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0)
}

func (bbr *BBRv3) isRenoCoexistenceProbeTime() bool {
	rounds := uint64(min(protocol.ByteCount(BW_PROBE_MAX_ROUNDS), bbr.targetInflight()/max(bbr.maxDatagramSize, 1)))
	if rounds == 0 {
		rounds = 1
	}
	return bbr.roundsSinceProbe >= rounds
}

func (bbr *BBRv3) startProbeBWDown(now monotime.Time) {
	bbr.resetCongestionSignals()
	bbr.bwProbeUpCnt = protocol.MaxByteCount
	bbr.pickProbeWait()
	bbr.cycleStamp = now
	bbr.phaseStartStamp = now
	bbr.ackPhase = ackPhaseProbeStopping
	bbr.startRoundNow()
	bbr.probeBWPhase = probeBWDown
}

func (bbr *BBRv3) startProbeBWCruise(now monotime.Time) {
	if bbr.inflightLo != protocol.MaxByteCount {
		bbr.inflightLo = min(bbr.inflightLo, bbr.inflightHi)
	}
	bbr.probeBWPhase = probeBWCruise
	bbr.phaseStartStamp = now
}

// startProbeBWCruiseAfterProbeRTT re-enters ProbeBW from ProbeRTT without
// arming ACKS_PROBE_STOPPING. ProbeRTT is not the end of a bandwidth-probe
// cycle, so the first low post-ProbeRTT samples must not rotate the max_bw
// filter and discard the previous cycle's high samples.
func (bbr *BBRv3) startProbeBWCruiseAfterProbeRTT(now monotime.Time) {
	bbr.resetCongestionSignals()
	bbr.bwProbeUpCnt = protocol.MaxByteCount
	bbr.pickProbeWait()
	bbr.cycleStamp = now
	bbr.phaseStartStamp = now
	bbr.ackPhase = ackPhaseInit
	bbr.nextRoundDelivered = bbr.totalBytesAcked
	bbr.roundStart = false
	bbr.startProbeBWCruise(now)
}

func (bbr *BBRv3) startProbeBWRefill(now monotime.Time, probeUpRounds uint8) {
	bbr.resetLowerBounds()
	bbr.bwProbeUpRounds = probeUpRounds
	bbr.bwProbeUpAcks = 0
	bbr.stoppedRiskyProbe = false
	bbr.ackPhase = ackPhaseRefilling
	bbr.startRoundNow()
	bbr.probeBWPhase = probeBWRefill
	bbr.phaseStartStamp = now
}

func (bbr *BBRv3) startProbeBWUp(now monotime.Time, sampleBW protocol.ByteCount) {
	bbr.ackPhase = ackPhaseProbeStarting
	bbr.startRoundNow()
	bbr.resetFullBw()
	bbr.fullBandwidth = sampleBW
	bbr.probeBWPhase = probeBWUp
	bbr.phaseStartStamp = now
	bbr.bwProbeSamples = true
	bbr.raiseInflightHiSlope()
}

func (bbr *BBRv3) startRoundNow() {
	bbr.nextRoundDelivered = bbr.totalBytesAcked
	bbr.roundStart = true
}

func (bbr *BBRv3) pickProbeWait() {
	bbr.roundsSinceProbe = uint64(bbr.rng.Intn(BW_PROBE_RAND_ROUNDS))
	randJitter := time.Duration(0)
	if PROBE_WAIT_RAND_MAX > 0 {
		randJitter = time.Duration(bbr.rng.Int63n(int64(PROBE_WAIT_RAND_MAX)))
	}
	bbr.probeWait = PROBE_WAIT_BASE + randJitter
}

// updateMinRTT implements min_rtt tracking and ProbeRTT state per RFC §5.3.4.
//
// BBR maintains two RTT filters with different time scales (§2.13):
//   1. probe_rtt_min_delay: 5-second filter for ProbeRTT scheduling
//   2. min_rtt: 10-second filter for BDP estimation
//
// When probe_rtt_min_delay expires without refresh (from idle or lower sample),
// BBR enters ProbeRTT state to cooperatively drain the queue with other BBR flows.
//
// ProbeRTT algorithm (§5.3.4.3 BBRUpdateMinRTT/BBRCheckProbeRTT):
//   1. Entry: probe_rtt_expired && !idle_restart && state != ProbeRTT
//   2. Reduce cwnd to ProbeRTTCwndGain * BDP (0.5 * BDP)
//   3. Wait for: C.inflight <= probeRTTCwnd AND 200ms AND one round
//   4. Exit to ProbeBW (if full_bw_reached) or Startup
//
// Per §5.3.4.3, this uses the per-event RTT from pendingNewestSentTime,
// not the potentially stale rttStats.LatestRTT().
func (bbr *BBRv3) updateMinRTT(now monotime.Time) {
	// Per draft-ietf-ccwg-bbr-05 §5.3.4.3, use the RTT from the current ACK event,
	// not LatestRTT which may be stale if this ACK didn't update rttStats.
	rttSample := time.Duration(0)
	if !bbr.pendingNewestSentTime.IsZero() {
		rttSample = now.Sub(bbr.pendingNewestSentTime)
	}
	// Guard: rttSample <= 0 means pendingNewestSentTime is unset/zero, or clock
	// went backwards. A zero or negative sample is not a valid basis for min_rtt
	// or ProbeRTT scheduling.
	if rttSample <= 0 {
		return
	}
	probeExpired := bbr.probeRTTMinStamp.IsZero() || now.Sub(bbr.probeRTTMinStamp) > PROBE_RTT_INTERVAL
	if bbr.probeRTTMinDelay == 0 || rttSample < bbr.probeRTTMinDelay || probeExpired {
		bbr.probeRTTMinDelay = rttSample
		bbr.probeRTTMinStamp = now
	}

	minExpired := bbr.minRTTStamp.IsZero() || now.Sub(bbr.minRTTStamp) > MIN_RTT_FILTER_LEN
	if bbr.minRTT == 0 || bbr.probeRTTMinDelay < bbr.minRTT || minExpired {
		bbr.minRTT = bbr.probeRTTMinDelay
		bbr.minRTTStamp = bbr.probeRTTMinStamp
	}

	if probeExpired && !bbr.idleRestart && bbr.state != BBRProbeRTT {
		bbr.state = BBRProbeRTT
		bbr.saveCwnd()
		bbr.probeRTTDoneStamp = 0
		bbr.probeRTTRoundDone = false
		bbr.ackPhase = ackPhaseProbeStopping
		bbr.startRoundNow()
	}

	if bbr.state == BBRProbeRTT {
		bytesInFlight := bbr.bytesInFlightForAckEvent()
		// RFC §5.3.4.3 / tcp_bbr.c:bbr_update_min_rtt() refreshes the
		// app-limited bubble on every ACK during ProbeRTT so the low-rate
		// drain/refill samples do not poison max_bw.
		bbr.MarkAppLimited(bytesInFlight)
		probeRTTCwnd := bbr.probeRTTCwnd()
		if bbr.probeRTTDoneStamp.IsZero() && bytesInFlight <= probeRTTCwnd {
			bbr.probeRTTDoneStamp = now.Add(PROBE_RTT_DURATION)
			bbr.probeRTTRoundDone = false
			bbr.startRoundNow()
		} else if !bbr.probeRTTDoneStamp.IsZero() {
			if bbr.roundStart {
				bbr.probeRTTRoundDone = true
			}
			if bbr.probeRTTRoundDone {
				bbr.checkProbeRTTDone(now)
			}
		}
	}
}

func (bbr *BBRv3) checkProbeRTTDone(now monotime.Time) {
	if bbr.probeRTTDoneStamp.IsZero() || now.Before(bbr.probeRTTDoneStamp) {
		return
	}
	bbr.probeRTTMinStamp = now
	bbr.restoreCwnd()
	bbr.exitProbeRTT(now)
}

func (bbr *BBRv3) exitProbeRTT(now monotime.Time) {
	bbr.resetLowerBounds()
	if bbr.fullBandwidthReached {
		bbr.state = BBRProbeBW
		bbr.startProbeBWCruiseAfterProbeRTT(now)
		return
	}
	bbr.state = BBRStartup
}

func (bbr *BBRv3) noteLoss() {
	if !bbr.lossInRound {
		bbr.lossRoundDelivered = bbr.totalBytesAcked
		// First loss in this round - save state for potential spurious loss recovery.
		// Per RFC §5.5.11.1, we save state when loss recovery starts so we can
		// restore it if the loss is later determined to be spurious.
		bbr.saveStateUponLoss()
	}
	bbr.lossInRound = true
	bbr.lossInCycle = true
}

// saveStateUponLoss saves BBRv3 model state for potential spurious loss recovery.
// Per RFC §5.5.11.1 (BBRSaveStateUponLoss), this is called on first loss in a round.
func (bbr *BBRv3) saveStateUponLoss() {
	bbr.undoState = bbr.state
	bbr.undoProbeBWPhase = bbr.probeBWPhase
	bbr.undoBwLo = bbr.bwLo
	bbr.undoInflightLo = bbr.inflightLo
	bbr.undoInflightHi = bbr.inflightHi
	bbr.undoCwnd = bbr.congestionWindow
}

// OnSpuriousLossDetected reacts to spurious-loss signals at the per-packet
// level. Draft-ietf-ccwg-bbr-05 §5.2.5 / §5.5.11 specify episode-level
// semantics: the model should be undone only when an entire recovery episode
// is determined to have been spurious, not on the first reordered packet.
//
// Current behavior: first spurious packet triggers model restoration.
// Spec behavior: wait until entire episode is determined spurious.
//
// Implementing the spec correctly requires sent_packet_handler to expose
// recovery-episode boundaries (episode start, episode end, episode-was-spurious)
// to the congestion controller. This is tracked as a follow-up item.
//
// Pinned by TestBBRv3SpuriousLossPinsPerPacketSemantics.
func (bbr *BBRv3) OnSpuriousLossDetected(_ protocol.PacketNumber, _ protocol.PacketNumber) {
	// The current transport hook delivers one callback per spuriously lost
	// packet, so thresholds greater than 1 effectively disable this recovery
	// path until BBR grows an explicit accumulator.
	if spuriousLossRecoveryThreshold > 1 {
		return
	}

	// Clear loss-in-round flag since the loss was spurious
	bbr.lossInRound = false

	// Reset full bandwidth estimator to re-probe after spurious loss
	bbr.resetFullBw()

	// Restore bounds to max of current and saved values per RFC §5.5.11.2:
	//   BBR.bw_shortterm = max(BBR.bw_shortterm, BBR.undo_bw_shortterm)
	// If the saved value is MaxByteCount (bounds were unconstrained before loss),
	// this restores the unconstrained state, fully reversing the loss-driven reduction.
	if bbr.undoBwLo > bbr.bwLo {
		bbr.bwLo = bbr.undoBwLo
	}
	if bbr.undoInflightLo > bbr.inflightLo {
		bbr.inflightLo = bbr.undoInflightLo
	}
	if bbr.undoInflightHi > bbr.inflightHi {
		bbr.inflightHi = bbr.undoInflightHi
	}

	// Restore cwnd to max of current and saved values, then apply bounds.
	// This allows cwnd to recover immediately rather than waiting for slow growth.
	if bbr.undoCwnd > bbr.congestionWindow {
		bbr.congestionWindow = bbr.undoCwnd
	}
	bbr.boundCwndForInflightModel()

	// If we were probing bandwidth when loss occurred, return to that state.
	// Per RFC §5.5.11.2, we restore probing state if not in ProbeRTT.
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

	// Emit qlog event for debugging/analysis
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

// isInflightTooHigh checks for congestion signal threshold violations.
// Per RFC §2.7 (Core Algorithm Design Parameters):
//
// Loss threshold: BBR.LossThresh = 2%
//   If RS.lost / RS.tx_in_flight > 2%, inflight is too high
//
// ECN threshold (tcp_bbr.c, not RFC-specified): ECN_THRESH = 50%
//   If RS.delivered_ce / RS.delivered > 50%, inflight is too high
//
// These thresholds balance responsiveness to congestion against robustness
// to transient noise. The 2% loss threshold allows BBR to tolerate moderate
// random loss (e.g., from shallow buffers) while still detecting persistent
// overload. The 50% ECN threshold is aggressive because ECN is an early signal.
func (bbr *BBRv3) isInflightTooHigh(rs bbrRateSample) bool {
	if rs.txInFlight > 0 && rs.lost > 0 {
		if float64(rs.lost) > float64(rs.txInFlight)*LOSS_THRESH {
			return true
		}
	}
	if bbr.ecnEligible && rs.delivered > 0 && rs.deliveredCE > 0 {
		if float64(rs.deliveredCE) > float64(rs.delivered)*ECN_THRESH {
			return true
		}
	}
	return false
}

func (bbr *BBRv3) inflightHiFromLostPacket(rs bbrRateSample, lostPacketSize protocol.ByteCount) protocol.ByteCount {
	if rs.txInFlight <= lostPacketSize {
		return rs.txInFlight
	}
	inflightPrev := float64(rs.txInFlight - lostPacketSize)
	lostPrev := float64(max(rs.lost-lostPacketSize, protocol.ByteCount(0)))
	lossBudget := inflightPrev * LOSS_THRESH
	var lostPrefix float64
	if lostPrev >= lossBudget {
		lostPrefix = 0
	} else {
		den := 1.0 - LOSS_THRESH
		if den <= 0 {
			return rs.txInFlight
		}
		lostPrefix = (lossBudget - lostPrev) / den
	}
	return protocol.ByteCount(inflightPrev + lostPrefix)
}

// updateGains sets pacing and cwnd gains based on current state.
// Per RFC §5.6.1 (Summary of Control Behavior in the State Machine):
//
// State/Phase       pacing_gain  cwnd_gain
// ─────────────────────────────────────────
// Startup           2.77         2.0
// Drain             0.50         2.0
// ProbeBW_DOWN      0.90         2.0
// ProbeBW_CRUISE    1.0          2.0
// ProbeBW_REFILL    1.0          2.0
// ProbeBW_UP        1.25         2.25
// ProbeRTT          1.0          0.5
//
// pacing_gain controls sending rate relative to BBR.bw.
// cwnd_gain controls max inflight relative to BDP.
func (bbr *BBRv3) updateGains() {
	switch bbr.state {
	case BBRStartup:
		bbr.pacingGain = STARTUP_PACING_GAIN
		bbr.cwndGain = STARTUP_CWND_GAIN
	case BBRDrain:
		bbr.pacingGain = DRAIN_PACING_GAIN
		bbr.cwndGain = STARTUP_CWND_GAIN
	case BBRProbeBW:
		switch bbr.probeBWPhase {
		case probeBWUp:
			bbr.pacingGain = PROBE_BW_UP_GAIN
			bbr.cwndGain = PROBE_BW_UP_CWND_GAIN // 2.25 per RFC §5.6.1
		case probeBWDown:
			bbr.pacingGain = PROBE_BW_DOWN_GAIN
			bbr.cwndGain = CWND_GAIN_DEFAULT
		default:
			bbr.pacingGain = PROBE_BW_BASE_GAIN
			bbr.cwndGain = CWND_GAIN_DEFAULT
		}
	case BBRProbeRTT:
		bbr.pacingGain = 1.0
		bbr.cwndGain = PROBE_RTT_CWND_GAIN
	}
}

func (bbr *BBRv3) setPacingRateWithGain(gain float64) {
	// Per RFC §5.6.1 table: during accelerating phases (Startup, REFILL, UP),
	// pacing uses unbounded max_bw. During decelerating/cruising phases
	// (DOWN, CRUISE, DRAIN, ProbeRTT), pacing is bounded by bw_shortterm.
	var bw protocol.ByteCount
	if bbr.isProbingBandwidth() {
		bw = bbr.maxBandwidth()
	} else {
		bw = bbr.boundedBandwidth()
	}
	if bw <= 0 {
		return
	}
	rate := protocol.ByteCount(float64(bw) * gain * BBR_PACING_MARGIN)
	if rate <= 0 {
		rate = 1
	}
	// Pre-fullBandwidthReached, the pacing rate ratchets up only. This matches
	// tcp_bbr.c — during the Startup ramp the rate must not be allowed to fall.
	if bbr.fullBandwidthReached || rate > bbr.pacingRate {
		bbr.pacingRate = rate
	}
}

func (bbr *BBRv3) setSendQuantum() {
	if bbr.pacingRate == 0 {
		bbr.sendQuantum = max(2*bbr.maxDatagramSize, bbr.maxDatagramSize)
		// Per RFC §5.5.8.2: QUIC (non-offloaded) uses offload_budget = send_quantum.
		// TCP (with TSO/GSO offloading) uses 3 * send_quantum per §5.5.8.1.
		bbr.offloadBudget = bbr.sendQuantum
		return
	}
	q := protocol.ByteCount(uint64(bbr.pacingRate) * uint64(time.Millisecond) / uint64(time.Second))
	q = min(q, protocol.ByteCount(64*1024))
	q = max(q, 2*bbr.maxDatagramSize)
	bbr.sendQuantum = q
	// Per RFC §5.5.8.2: QUIC (non-offloaded) uses offload_budget = send_quantum.
	// TCP (with TSO/GSO offloading) uses 3 * send_quantum per §5.5.8.1.
	bbr.offloadBudget = q
}

func (bbr *BBRv3) setCwnd(rs bbrRateSample) {
	// Per RFC §5.6.4.2, use maxInflight() which adds extra_acked BEFORE quantization.
	target := bbr.maxInflight()
	if bbr.fullBandwidthReached {
		bbr.congestionWindow = min(bbr.congestionWindow+rs.newlyAcked, target)
	} else if bbr.congestionWindow < target || protocol.ByteCount(bbr.totalBytesAcked) < bbr.initialCwnd {
		bbr.congestionWindow += rs.newlyAcked
	}

	bbr.congestionWindow = max(bbr.congestionWindow, bbr.minPipeCwnd)
	if bbr.state == BBRProbeRTT {
		bbr.congestionWindow = min(bbr.congestionWindow, bbr.probeRTTCwnd())
	}
	bbr.boundCwndForInflightModel()
	bbr.congestionWindow = min(max(bbr.congestionWindow, bbr.minPipeCwnd), maxBBRv3CongestionWindow)
}

func (bbr *BBRv3) boundCwndForInflightModel() {
	cap := protocol.MaxByteCount
	if bbr.state == BBRProbeBW && bbr.probeBWPhase != probeBWCruise {
		cap = bbr.inflightHi
	} else if bbr.state == BBRProbeRTT || (bbr.state == BBRProbeBW && bbr.probeBWPhase == probeBWCruise) {
		cap = bbr.inflightWithHeadroom()
	}
	cap = min(cap, bbr.inflightLo)
	cap = max(cap, bbr.minPipeCwnd)
	bbr.congestionWindow = min(bbr.congestionWindow, cap)
}

func (bbr *BBRv3) targetInflight() protocol.ByteCount {
	bdp := bbr.inflightFromBWGain(bbr.boundedBandwidth(), 1.0)
	return min(bdp, bbr.congestionWindow)
}

func (bbr *BBRv3) targetCwnd(gain float64) protocol.ByteCount {
	inflight := bbr.inflightFromBWGain(bbr.boundedBandwidth(), gain)
	inflight = bbr.quantizationBudget(inflight)
	return inflight
}

// maxInflight implements BBRUpdateMaxInflight() per RFC §5.6.4.2:
//
//	inflight_cap = BBRBDPMultiple(BBR.cwnd_gain)  // BDP * cwnd_gain
//	inflight_cap += BBR.extra_acked               // add aggregation headroom
//	BBR.max_inflight = BBRQuantizationBudget(inflight_cap)  // apply floors
//
// This is the target cwnd for steady-state operation. The algorithm:
//   1. Compute BDP-based inflight with cwnd_gain multiplier
//   2. Add extra_acked to accommodate ACK aggregation (§5.5.9)
//   3. Apply quantization budget (§5.6.4.2): max(inflight, offload_budget, minPipeCwnd)
//
// CRITICAL: extra_acked is added BEFORE quantization, not after.
// This ensures quantization floors apply to the sum of BDP and aggregation
// headroom, matching the RFC pseudocode exactly.
func (bbr *BBRv3) maxInflight() protocol.ByteCount {
	inflight := bbr.inflightFromBWGain(bbr.boundedBandwidth(), bbr.cwndGain)
	if bbr.fullBandwidthReached {
		inflight += bbr.maxExtraAcked()
	}
	return bbr.quantizationBudget(inflight)
}

// probeRTTCwnd implements draft-ietf-ccwg-bbr-05 §5.6.4.5 BBRProbeRTTCwnd():
//   probe_rtt_cwnd = BBRBDPMultiple(BBR.bw, BBR.ProbeRTTCwndGain)
// where BBR.bw = min(BBR.max_bw, BBR.bw_shortterm) per §5.5.10. We use
// boundedBandwidth() (= BBR.bw) here per the draft, NOT maxBandwidth()
// (= BBR.max_bw). Linux tcp_bbr.c uses bbr_max_bw at this site as a
// deliberate divergence from the IETF text; quic-go follows the draft.
func (bbr *BBRv3) probeRTTCwnd() protocol.ByteCount {
	return max(bbr.inflightFromBWGain(bbr.boundedBandwidth(), PROBE_RTT_CWND_GAIN), bbr.minPipeCwnd)
}

// bwTimeProduct computes bw * duration using microsecond intermediate precision.
// This pattern prevents uint64 overflow at extreme BDPs (safe to ~14.4 Tbps at any RTT).
func bwTimeProduct(bw protocol.ByteCount, d time.Duration) protocol.ByteCount {
	return protocol.ByteCount(uint64(bw) * uint64(d/time.Microsecond) / 1_000_000)
}

func (bbr *BBRv3) inflightFromBWGain(bw protocol.ByteCount, gain float64) protocol.ByteCount {
	if bw <= 0 {
		return max(bbr.initialCwnd, bbr.minPipeCwnd)
	}
	if bbr.minRTT <= 0 {
		return max(bbr.congestionWindow, bbr.minPipeCwnd)
	}
	bdp := bwTimeProduct(bw, bbr.minRTT)
	inflight := protocol.ByteCount(float64(bdp) * gain)
	return max(inflight, bbr.minPipeCwnd)
}

func (bbr *BBRv3) quantizationBudget(inflight protocol.ByteCount) protocol.ByteCount {
	inflight = max(inflight, bbr.offloadBudget)
	inflight = max(inflight, bbr.minPipeCwnd)
	if bbr.state == BBRProbeBW && bbr.probeBWPhase == probeBWUp {
		inflight += 2 * bbr.maxDatagramSize
	}
	return inflight
}

func (bbr *BBRv3) inflightWithHeadroom() protocol.ByteCount {
	if bbr.inflightHi == protocol.MaxByteCount {
		return protocol.MaxByteCount
	}
	headroom := protocol.ByteCount(float64(bbr.inflightHi) * INFLIGHT_HEADROOM)
	headroom = max(headroom, bbr.maxDatagramSize)
	if bbr.inflightHi <= headroom {
		return bbr.minPipeCwnd
	}
	return max(bbr.inflightHi-headroom, bbr.minPipeCwnd)
}

func (bbr *BBRv3) updateAckAggregation(rs bbrRateSample, now monotime.Time) {
	if rs.newlyAcked <= 0 {
		return
	}
	if bbr.roundStart {
		bbr.extraAckedWinRTTs = min(bbr.extraAckedWinRTTs+1, uint8(31))
		// RFC §5.5.9 uses a 1-RTT aggregation window in Startup and the full
		// BBRExtraAckedFilterLen window after full_bw_reached.
		winThresh := uint8(EXTRA_ACKED_WIN_RTS)
		if bbr.state == BBRStartup {
			winThresh = EXTRA_ACKED_WIN_RTS_STARTUP
		}
		if bbr.extraAckedWinRTTs >= winThresh {
			bbr.extraAckedWinRTTs = 0
			bbr.extraAckedWinIdx ^= 1
			bbr.extraAcked[bbr.extraAckedWinIdx] = 0
		}
	}

	epoch := now.Sub(bbr.ackEpochStart)
	expected := protocol.ByteCount(0)
	if epoch > 0 {
		expected = bwTimeProduct(bbr.boundedBandwidth(), epoch)
	}
	// IMPLEMENTATION CHOICE: The RFC does not specify a saturation guard for the
	// ack epoch counter. Linux tcp_bbr.c uses BBR_ACK_EPOCH_ACKED_MAX = (1<<20) - 1
	// (~1M packets) to prevent overflow. We follow this approach as a safe default,
	// scaling by maxDatagramSize since quic-go tracks bytes rather than packets.
	// This could be tuned or removed without affecting RFC compliance.
	resetThresh := protocol.ByteCount(1<<20) * bbr.maxDatagramSize
	satCap := max(resetThresh-1, 0)

	if bbr.ackEpochAcked <= expected || bbr.ackEpochAcked+rs.newlyAcked >= resetThresh {
		bbr.ackEpochAcked = 0
		bbr.ackEpochStart = now
		expected = 0
	}
	bbr.ackEpochAcked = min(bbr.ackEpochAcked+rs.newlyAcked, satCap)
	extra := bbr.ackEpochAcked - expected
	extra = min(extra, bbr.congestionWindow)
	if extra > bbr.extraAcked[bbr.extraAckedWinIdx] {
		bbr.extraAcked[bbr.extraAckedWinIdx] = extra
	}
}

func (bbr *BBRv3) maxExtraAcked() protocol.ByteCount {
	v := max(bbr.extraAcked[0], bbr.extraAcked[1])
	cap := protocol.ByteCount(0)
	if bbr.boundedBandwidth() > 0 {
		cap = bwTimeProduct(bbr.boundedBandwidth(), EXTRA_ACKED_MAX_US)
	}
	if cap > 0 {
		v = min(v, cap)
	}
	return v
}

func (bbr *BBRv3) resetCongestionSignals() {
	bbr.lossInRound = false
	bbr.ecnInRound = false
	bbr.lossInCycle = false
	// Note: tcp_bbr.c tracks ecnInCycle for faster re-probing after ECN-only
	// congestion clears (shorter probe_wait when !lossInCycle && ecnInCycle).
	// This optimization is not implemented because RFC §3.7 leaves ECN response
	// unspecified, and the current ecnInRound-based inflightLo adaptation is
	// sufficient for congestion response. Future work could add this if needed.
	bbr.bwLatest = 0
	bbr.inflightLatest = 0
	bbr.bytesLostInRound = 0
}

// saveCwnd captures cwnd before a phase transition that may compress it.
// Draft-ietf-ccwg-bbr-05 §5.6.4.4 uses !InLossRecovery() && state != ProbeRTT;
// this implementation uses !lossInRound && state != BBRProbeRTT instead.
// The two differ during long recovery episodes that span multiple rounds:
// - Spec's InLossRecovery() is true for the entire recovery episode
// - Our lossInRound resets each round, allowing priorCwnd capture mid-episode
// This is a deliberate QUIC adaptation that allows faster cwnd restoration
// after partial recovery. Pinned by TestBBRv3SaveCwndPinsRoundScopedPredicate.
func (bbr *BBRv3) saveCwnd() {
	if bbr.state != BBRProbeRTT && !bbr.lossInRound {
		bbr.priorCwnd = bbr.congestionWindow
		return
	}
	bbr.priorCwnd = max(bbr.priorCwnd, bbr.congestionWindow)
}

func (bbr *BBRv3) restoreCwnd() {
	bbr.congestionWindow = max(bbr.congestionWindow, bbr.priorCwnd)
}

func (bbr *BBRv3) nominalBandwidth() protocol.ByteCount {
	if bbr.maxBandwidth() > 0 {
		return bbr.maxBandwidth()
	}
	srtt := utils.DefaultInitialRTT
	if bbr.rttStats != nil && bbr.rttStats.SmoothedRTT() > 0 {
		srtt = bbr.rttStats.SmoothedRTT()
	}
	if srtt <= 0 {
		srtt = time.Millisecond
	}
	return max(protocol.ByteCount(uint64(bbr.congestionWindow)*uint64(time.Second)/uint64(srtt)), 1)
}

func (bbr *BBRv3) initPacingRate() {
	rtt := time.Millisecond
	if bbr.rttStats != nil && bbr.rttStats.SmoothedRTT() > 0 {
		rtt = bbr.rttStats.SmoothedRTT()
	}
	nominal := max(protocol.ByteCount(uint64(bbr.initialCwnd)*uint64(time.Second)/uint64(rtt)), 1)
	bbr.pacingRate = protocol.ByteCount(float64(nominal) * STARTUP_PACING_GAIN)
}

func (bbr *BBRv3) isRoundCwndLimited(bytesInFlight protocol.ByteCount) bool {
	return bbr.cwndLimitedPrevRound || bbr.cwndLimitedInRound || bbr.isCwndLimitedInstantaneous(bytesInFlight)
}

func (bbr *BBRv3) isCwndLimitedInstantaneous(bytesInFlight protocol.ByteCount) bool {
	if bytesInFlight >= bbr.congestionWindow {
		return true
	}
	available := bbr.congestionWindow - bytesInFlight
	// Allow a small packet-scheduling tolerance below cwnd. In quic-go the pacer
	// and packetization path can leave a few packets of slack even when the flow
	// is effectively cwnd-limited. The maxBurstPackets (3) headroom is ~0.4% of
	// typical ProbeBW cwnd and does not materially affect throughput.
	return available <= maxBurstPackets*bbr.maxDatagramSize
}

// maybeQlogStateChange emits qlog events on state/phase transitions.
func (bbr *BBRv3) maybeQlogStateChange() {
	if bbr.qlogger == nil {
		return
	}
	stateChanged := bbr.state != bbr.lastState
	phaseChanged := bbr.state == BBRProbeBW && bbr.probeBWPhase != bbr.lastPhase

	if stateChanged || phaseChanged {
		bbr.lastState = bbr.state
		bbr.lastPhase = bbr.probeBWPhase

		// Emit standard congestion state event
		state := qlog.CongestionStateApplicationLimited
		switch bbr.state {
		case BBRStartup:
			state = qlog.CongestionStateSlowStart
		case BBRDrain:
			// Drain is post-Startup queue drainage, not loss recovery. Map to
			// congestion_avoidance for generic qlog consumers; recovery:bbr_state_updated
			// is the authoritative event for BBR-specific state.
			state = qlog.CongestionStateCongestionAvoidance
		case BBRProbeBW:
			state = qlog.CongestionStateCongestionAvoidance
		case BBRProbeRTT:
			state = qlog.CongestionStateApplicationLimited
		}
		bbr.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: state})

		// Emit BBRv3-specific state event
		phase := bbr.qlogPhase()
		bbr.qlogger.RecordEvent(qlog.BBRv3StateUpdated{
			State:      bbr.state.String(),
			Phase:      phase,
			RoundCount: bbr.roundCount,
		})

		bbr.qlogger.RecordEvent(bbr.qlogModelUpdate("state_change"))
		bbr.qlogger.RecordEvent(bbr.qlogControlUpdate("state_change"))
	}
}

// maybeQlogRoundUpdate emits qlog events on round boundaries.
func (bbr *BBRv3) maybeQlogRoundUpdate(rs bbrRateSample) {
	if bbr.qlogger == nil || !bbr.roundStart || bbr.roundCount == bbr.lastRoundCount {
		return
	}
	bbr.lastRoundCount = bbr.roundCount
	bbr.qlogger.RecordEvent(bbr.qlogRoundUpdate(rs))
	if bbr.state == BBRStartup {
		bbr.qlogger.RecordEvent(bbr.qlogModelUpdate("startup_round"))
		bbr.qlogger.RecordEvent(bbr.qlogControlUpdate("startup_round"))
	}
}

func (bbr *BBRv3) qlogPhase() string {
	if bbr.state != BBRProbeBW {
		return ""
	}
	return bbr.probeBWPhase.String()
}

func (bbr *BBRv3) qlogModelUpdate(trigger string) qlog.BBRv3ModelUpdated {
	var bwLoVal, bwHiVal, inflightLoVal, inflightHiVal uint64
	if bbr.bwLo != protocol.MaxByteCount {
		bwLoVal = uint64(bbr.bwLo)
	}
	if bbr.bwHi[0] > 0 || bbr.bwHi[1] > 0 {
		bwHiVal = uint64(bbr.maxBandwidth())
	}
	if bbr.inflightLo != protocol.MaxByteCount {
		inflightLoVal = uint64(bbr.inflightLo)
	}
	if bbr.inflightHi != protocol.MaxByteCount {
		inflightHiVal = uint64(bbr.inflightHi)
	}
	return qlog.BBRv3ModelUpdated{
		Trigger:       trigger,
		MaxBW:         uint64(bbr.maxBandwidth()),
		BwLo:          bwLoVal,
		BwHi:          bwHiVal,
		MinRTT:        bbr.minRTT,
		InflightHi:    inflightHiVal,
		InflightLo:    inflightLoVal,
		BDP:           uint64(bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0)),
		FullBWReached: bbr.fullBandwidthReached,
	}
}

func (bbr *BBRv3) qlogControlUpdate(trigger string) qlog.BBRv3ControlUpdated {
	return qlog.BBRv3ControlUpdated{
		Trigger:    trigger,
		PacingRate: uint64(bbr.pacingRate),
		Cwnd:       uint64(bbr.congestionWindow),
		PacingGain: bbr.pacingGain,
		CwndGain:   bbr.cwndGain,
	}
}

func (bbr *BBRv3) qlogRoundUpdate(rs bbrRateSample) qlog.BBRv3RoundUpdated {
	return qlog.BBRv3RoundUpdated{
		State:              bbr.state.String(),
		Phase:              bbr.qlogPhase(),
		RoundCount:         bbr.roundCount,
		RoundStart:         bbr.roundStart,
		LossInRound:        bbr.lossInRound,
		ECNInRound:         bbr.ecnInRound,
		BytesLostInRound:   uint64(bbr.bytesLostInRound),
		DeliveryRate:       uint64(rs.deliveryRate),
		DeliveryRateValid:  bbr.isRateSampleValid(rs),
		AppLimited:         rs.isAppLimited,
		FullBW:             uint64(bbr.fullBandwidth),
		FullBWCount:        uint64(bbr.fullBandwidthCount),
		FullBWNow:          bbr.fullBandwidthNow,
		FullBWReached:      bbr.fullBandwidthReached,
		PacingRate:         uint64(bbr.pacingRate),
		BytesInFlight:      uint64(rs.bytesInFlight),
		Cwnd:               uint64(bbr.congestionWindow),
		SendElapsed:        rs.sendElapsed,
		AckElapsed:         rs.ackElapsed,
		RateSampleInterval: rs.interval,
	}
}

func (bbr *BBRv3) isRateSampleValid(rs bbrRateSample) bool {
	if rs.delivered == 0 || rs.interval <= 0 {
		return false
	}
	return bbr.minRTT == 0 || rs.interval >= bbr.minRTT
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
