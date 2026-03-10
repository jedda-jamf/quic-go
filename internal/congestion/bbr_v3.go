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
// Where values differ between RFC and tcp_bbr.c, we follow tcp_bbr.c for
// proven real-world performance while noting the RFC value in comments.
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

	// DRAIN_PACING_GAIN = 1/2.885 ≈ 0.347 per tcp_bbr.c
	// RFC recommends ≤0.5 (§2.4). tcp_bbr.c uses 1/2.885 for symmetry with startup.
	// This drains the queue created during startup in approximately one RTT.
	// See also: tcp_bbr.c:bbr_drain_gain = BBR_UNIT * 1000 / 2885
	DRAIN_PACING_GAIN = 1.0 / 2.885

	// CWND_GAIN_DEFAULT = 2 per RFC draft-ietf-ccwg-bbr-05 §2.5
	// Default cwnd gain used in ProbeBW steady state.
	// See also: tcp_bbr.c:bbr_cwnd_gain = BBR_UNIT * 2
	CWND_GAIN_DEFAULT = 2.0

	// PROBE_BW_UP_GAIN = 1.25 per tcp_bbr.c
	// Used during ProbeBW UP phase to probe for additional bandwidth.
	// See also: tcp_bbr.c:bbr_pacing_gain[] = {BBR_UNIT * 5 / 4, ...}
	PROBE_BW_UP_GAIN = 1.25

	// PROBE_BW_DOWN_GAIN = 0.91 per tcp_bbr.c
	// Used during ProbeBW DOWN phase to drain any excess queue.
	// See also: tcp_bbr.c:bbr_pacing_gain[] = {..., BBR_UNIT * 91 / 100}
	PROBE_BW_DOWN_GAIN = 0.91

	// PROBE_BW_BASE_GAIN = 1.0
	// Used during ProbeBW CRUISE and REFILL phases.
	PROBE_BW_BASE_GAIN = 1.0

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

	// ECN_ALPHA_GAIN = 1/16 per tcp_bbr.c
	// EWMA gain for ecn_alpha updates.
	// See also: tcp_bbr.c:bbr_ecn_alpha_gain = BBR_UNIT / 16
	ECN_ALPHA_GAIN = 1.0 / 16.0

	// ECN_FACTOR = 1/3 per tcp_bbr.c
	// Factor for ECN-driven inflight_lo reduction.
	// See also: tcp_bbr.c:bbr_ecn_factor = BBR_UNIT / 3
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

	// EXTRA_ACKED_WIN_RTS = 5 per tcp_bbr.c
	// Note: RFC §2.11 suggests 10, but tcp_bbr.c uses 5 for conservative tracking.
	// See also: tcp_bbr.c:bbr_extra_acked_win_rtts = 5
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
)

// bbrProbeBWPhase represents the sub-phases within ProbeBW state.
// Per RFC §5.3.3, ProbeBW cycles through: DOWN -> CRUISE -> REFILL -> UP -> DOWN
type bbrProbeBWPhase uint8

const (
	probeBWUp bbrProbeBWPhase = iota
	probeBWDown
	probeBWCruise
	probeBWRefill
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

// bbrAckPhase tracks probe feedback timing within a bandwidth probe cycle.
type bbrAckPhase uint8

const (
	ackPhaseInit bbrAckPhase = iota
	ackPhaseRefilling
	ackPhaseProbeStarting
	ackPhaseProbeFeedback
	ackPhaseProbeStopping
)

// BBRState represents the top-level BBR state machine states.
// Per RFC §5.1: Startup -> Drain -> ProbeBW <-> ProbeRTT
type BBRState int

const (
	BBRStartup BBRState = iota
	BBRDrain
	BBRProbeBW
	BBRProbeRTT
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
// This enables delivery rate calculation per RFC §4.2 (Delivery Rate Sampling).
type bbrSentPacketState struct {
	bytes          protocol.ByteCount
	delivered      uint64
	deliveredTime  monotime.Time
	firstSentTime  monotime.Time
	sentTime       monotime.Time
	txInFlight     protocol.ByteCount
	isAppLimited   bool
	totalBytesLost uint64
}

// bbrRateSample holds per-ACK delivery rate information.
// Corresponds to RFC §4.2 delivery rate calculation.
type bbrRateSample struct {
	newlyAcked     protocol.ByteCount
	delivered      protocol.ByteCount
	deliveredCE    protocol.ByteCount
	deliveryRate   protocol.ByteCount // bytes/s
	interval       time.Duration
	sendElapsed    time.Duration
	ackElapsed     time.Duration
	txInFlight     protocol.ByteCount
	bytesInFlight  protocol.ByteCount
	priorInFlight  protocol.ByteCount
	priorDelivered uint64
	lost           protocol.ByteCount
	isAppLimited   bool
}

// BBRv3 implements the send-side congestion controller.
//
// This implementation is aligned with:
// - Linux BBRv3 reference: google/bbr v3 net/ipv4/tcp_bbr.c
// - IETF specification: draft-ietf-ccwg-bbr-05
//
// QUIC Adaptation Notes:
// - QUIC ackhandler invokes callbacks per-packet, while Linux BBR updates
//   its model once per ACK event. We emulate this by coalescing per-packet
//   callbacks by ACK timestamp and running one model update at OnAckEventEnd().
// - C.SMSS maps to maxDatagramSize (QUIC datagram size) per RFC §2.1
// - No TSO/GRO offload budget complexity (QUIC runs in userspace)
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
	bwHi           [MAX_BW_FILTER_SLOTS]protocol.ByteCount
	bwLo           protocol.ByteCount
	bwLatest       protocol.ByteCount
	inflightHi     protocol.ByteCount
	inflightLo     protocol.ByteCount
	inflightLatest protocol.ByteCount

	roundCount         uint64
	roundsSinceProbe   uint64
	nextRoundDelivered uint64
	roundStart         bool

	lossRoundDelivered uint64
	lossRoundStart     bool
	lossInRound        bool
	ecnInRound         bool
	lossInCycle        bool
	ecnInCycle         bool
	lossEventsInRound  int
	bytesLostInRound   protocol.ByteCount

	totalBytesSent    uint64
	totalBytesAcked   uint64
	totalBytesLost    uint64
	totalBytesAckedCE uint64
	ecnAckedECT0      int64
	ecnAckedECT1      int64
	ecnAckedCE        int64

	alphaLastDelivered   uint64
	alphaLastDeliveredCE uint64
	ecnAlpha             float64
	ecnEligible          bool

	minRTT            time.Duration
	minRTTStamp       monotime.Time
	probeRTTMinDelay  time.Duration
	probeRTTMinStamp  monotime.Time
	probeRTTDoneStamp monotime.Time
	probeRTTRoundDone bool

	priorCwnd   protocol.ByteCount
	idleRestart bool

	cycleStamp        monotime.Time
	phaseStartStamp   monotime.Time
	probeWait         time.Duration
	prevProbeTooHigh  bool
	stoppedRiskyProbe bool
	bwProbeSamples    bool
	bwProbeUpRounds   uint8
	bwProbeUpCnt      protocol.ByteCount
	bwProbeUpAcks     protocol.ByteCount

	ackEpochStart     monotime.Time
	ackEpochAcked     protocol.ByteCount
	extraAcked        [2]protocol.ByteCount
	extraAckedWinRTTs uint8
	extraAckedWinIdx  uint8

	sentPackets   map[protocol.PacketNumber]bbrSentPacketState
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

	// Pending ECN feedback associated with next ACK event timestamp.
	pendingECNEventValid bool
	pendingECNEventTime  monotime.Time
	pendingECNCEBytes    protocol.ByteCount

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
	undoState      BBRState
	undoProbeBWPhase bbrProbeBWPhase
	undoBwLo       protocol.ByteCount
	undoInflightLo protocol.ByteCount
	undoInflightHi protocol.ByteCount
}

var (
	_ SendAlgorithm               = &BBRv3{}
	_ SendAlgorithmWithRTTStats   = &BBRv3{}
	_ SendAlgorithmWithDebugInfos = &BBRv3{}
	_ SpuriousLossHandler         = &BBRv3{}
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

	now := monotime.Now()
	bbr := &BBRv3{
		rttStats:         rttStats,
		maxDatagramSize:  initialMaxDatagramSize,
		congestionWindow: initialMaxDatagramSize * initialCongestionWindow,
		minPipeCwnd:      4 * initialMaxDatagramSize, // MIN_PIPE_CWND = 4*SMSS per RFC §2.7
		initialCwnd:      initialMaxDatagramSize * initialCongestionWindow,
		sendQuantum:      2 * initialMaxDatagramSize,
		state:            BBRStartup,
		probeBWPhase:     probeBWDown,
		ackPhase:         ackPhaseInit,
		pacingGain:       STARTUP_PACING_GAIN,
		cwndGain:         STARTUP_CWND_GAIN,
		bwLo:             protocol.MaxByteCount,
		inflightHi:       protocol.MaxByteCount,
		inflightLo:       protocol.MaxByteCount,
		ecnAlpha:         1.0,
		sentPackets:      make(map[protocol.PacketNumber]bbrSentPacketState),
		rng:              rand.New(rand.NewSource(time.Now().UnixNano())),
		qlogger:          qlogger,
		lastState:        BBRStartup,
		lastPhase:        probeBWDown,
		ackEpochStart:    now,
		// Initialize undo state to "no saved state"
		undoBwLo:       protocol.MaxByteCount,
		undoInflightLo: protocol.MaxByteCount,
		undoInflightHi: protocol.MaxByteCount,
	}
	if bbr.congestionWindow < bbr.minPipeCwnd {
		bbr.congestionWindow = bbr.minPipeCwnd
	}

	if rttStats != nil {
		if mrtt := rttStats.MinRTT(); mrtt > 0 {
			bbr.minRTT = mrtt
			bbr.minRTTStamp = now
			bbr.probeRTTMinDelay = mrtt
			bbr.probeRTTMinStamp = now
		}
	}

	bbr.pacer = newPacer(bbr.BandwidthEstimate)
	bbr.initPacingRate()

	if bbr.qlogger != nil {
		bbr.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: qlog.CongestionStateSlowStart})
		bbr.qlogger.RecordEvent(qlog.BBRv3StateUpdated{
			State:      bbr.state.String(),
			Phase:      "",
			RoundCount: bbr.roundCount,
		})
	}
	return bbr
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
	if priorInFlight == 0 {
		bbr.firstSentTime = sentTime
		bbr.deliveredTime = sentTime
		bbr.idleRestart = true
		if bbr.state == BBRProbeBW {
			bbr.setPacingRateWithGain(1.0)
		} else if bbr.state == BBRProbeRTT {
			bbr.checkProbeRTTDone(sentTime)
		}
	}

	isAppLimited := !bbr.isCwndLimited(bytesInFlight)
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
		st = bbrSentPacketState{
			bytes:          ackedBytes,
			delivered:      bbr.totalBytesAcked,
			deliveredTime:  bbr.deliveredTime,
			firstSentTime:  eventTime,
			sentTime:       eventTime,
			txInFlight:     priorInFlight,
			totalBytesLost: bbr.totalBytesLost,
		}
	}

	bbr.totalBytesAcked += uint64(ackedBytes)
	bbr.deliveredTime = eventTime

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
		bbr.pendingCEBytes = bbr.consumePendingECNBytes(eventTime)
	} else {
		if priorInFlight > bbr.pendingPriorInFlight {
			bbr.pendingPriorInFlight = priorInFlight
		}
		if st.sentTime.After(bbr.pendingNewestSentTime) {
			bbr.pendingPriorDelivered = st.delivered
			bbr.pendingPriorTime = st.deliveredTime
			bbr.pendingSendElapsed = st.sentTime.Sub(st.firstSentTime)
			bbr.pendingTxInFlight = st.txInFlight
			bbr.pendingIsAppLimited = st.isAppLimited
			bbr.pendingTotalLostAtSend = st.totalBytesLost
			bbr.pendingNewestSentTime = st.sentTime
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
	bbr.totalBytesLost += uint64(lostBytes)
	bbr.bytesLostInRound += lostBytes
	bbr.noteLoss()
	if bbr.lossEventsInRound < math.MaxInt32 {
		bbr.lossEventsInRound++
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

// OnRetransmissionTimeout is called when a retransmission timeout occurs.
func (bbr *BBRv3) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	bbr.saveCwnd()
	if bbr.minPipeCwnd > 0 {
		bbr.congestionWindow = bbr.minPipeCwnd
	}
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

// BandwidthEstimate returns the current bandwidth estimate.
func (bbr *BBRv3) BandwidthEstimate() Bandwidth {
	if bbr.pacingRate > 0 {
		return Bandwidth(bbr.pacingRate) * BytesPerSecond
	}
	return Bandwidth(max(bbr.nominalBandwidth(), 1)) * BytesPerSecond
}

// OnAckEventEnd flushes the ACK-event coalescing bucket for the current ACK frame.
// This implements Linux-like "one model update per ACK event" semantics.
func (bbr *BBRv3) OnAckEventEnd(eventTime monotime.Time) {
	if bbr.pendingAckEventValid && bbr.pendingAckEventTime.Equal(eventTime) {
		bbr.processPendingAckEvent(eventTime)
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
	if total > 0 && (bbr.minRTT <= ECN_MAX_RTT || ECN_MAX_RTT == 0) {
		bbr.ecnEligible = true
	}

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

	rs := bbrRateSample{
		newlyAcked:     bbr.pendingAckedBytes,
		delivered:      protocol.ByteCount(bbr.totalBytesAcked - bbr.pendingPriorDelivered),
		deliveredCE:    bbr.pendingCEBytes,
		sendElapsed:    bbr.pendingSendElapsed,
		ackElapsed:     now.Sub(bbr.pendingPriorTime),
		txInFlight:     bbr.pendingTxInFlight,
		priorInFlight:  bbr.pendingPriorInFlight,
		bytesInFlight:  bbr.bytesInFlightAfterACK(),
		priorDelivered: bbr.pendingPriorDelivered,
		lost:           protocol.ByteCount(bbr.totalBytesLost - bbr.pendingTotalLostAtSend),
		isAppLimited:   bbr.pendingIsAppLimited,
	}
	rs.interval = maxDuration(rs.sendElapsed, rs.ackElapsed)
	if rs.interval > 0 && rs.delivered > 0 {
		rs.deliveryRate = protocol.ByteCount(uint64(rs.delivered) * uint64(time.Second) / uint64(rs.interval))
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
	}
	bbr.maybeQlogStateChange()
	bbr.maybeQlogRoundUpdate()
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

// updateRoundStart checks for round boundary crossing per RFC §5.2.
func (bbr *BBRv3) updateRoundStart(rs bbrRateSample) {
	bbr.roundStart = false
	if rs.priorDelivered < bbr.nextRoundDelivered {
		return
	}
	bbr.roundStart = true
	bbr.roundCount++
	if bbr.roundsSinceProbe < math.MaxUint64 {
		bbr.roundsSinceProbe++
	}
	bbr.nextRoundDelivered = bbr.totalBytesAcked
}

// updateECNAlpha updates the ECN alpha EWMA per tcp_bbr.c bbr_update_ecn_alpha().
func (bbr *BBRv3) updateECNAlpha(rs bbrRateSample) {
	if !bbr.roundStart || !bbr.ecnEligible {
		return
	}
	// ECN alpha EWMA: alpha = (1-g)*alpha + g*ce_ratio, with g=1/16.
	delivered := float64(bbr.totalBytesAcked - bbr.alphaLastDelivered)
	deliveredCE := float64(bbr.totalBytesAckedCE - bbr.alphaLastDeliveredCE)
	if delivered <= 0 {
		return
	}
	ceRatio := deliveredCE / delivered
	if ceRatio < 0 {
		ceRatio = 0
	}
	if ceRatio > 1 {
		ceRatio = 1
	}
	oldAlpha := bbr.ecnAlpha
	bbr.ecnAlpha = (1.0-ECN_ALPHA_GAIN)*bbr.ecnAlpha + ECN_ALPHA_GAIN*ceRatio
	if bbr.ecnAlpha < 0 {
		bbr.ecnAlpha = 0
	}
	if bbr.ecnAlpha > 1 {
		bbr.ecnAlpha = 1
	}
	bbr.alphaLastDelivered = bbr.totalBytesAcked
	bbr.alphaLastDeliveredCE = bbr.totalBytesAckedCE

	// Qlog ECN update if alpha changed significantly
	if bbr.qlogger != nil && (oldAlpha == 1.0 || math.Abs(bbr.ecnAlpha-oldAlpha) > 0.01) {
		bbr.qlogger.RecordEvent(qlog.BBRv3ECNUpdated{
			ECNAlpha:    bbr.ecnAlpha,
			ECNEligible: bbr.ecnEligible,
		})
	}

	// Check for excessive ECN in startup per tcp_bbr.c
	if bbr.state == BBRStartup && !bbr.fullBandwidthReached {
		if ceRatio >= ECN_THRESH {
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
	if rs.deliveryRate <= 0 || rs.newlyAcked <= 0 {
		return
	}
	bbr.bwLatest = max(bbr.bwLatest, rs.deliveryRate)
	bbr.inflightLatest = max(bbr.inflightLatest, rs.delivered)
	if rs.priorDelivered >= bbr.lossRoundDelivered {
		bbr.lossRoundDelivered = bbr.totalBytesAcked
		bbr.lossRoundStart = true
	}
}

func (bbr *BBRv3) advanceLatestDeliverySignals(rs bbrRateSample) {
	if bbr.lossRoundStart {
		bbr.bwLatest = rs.deliveryRate
		bbr.inflightLatest = rs.delivered
		bbr.bytesLostInRound = 0
	}
}

func (bbr *BBRv3) updateCongestionSignals(rs bbrRateSample) {
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

// adaptLowerBounds implements lower-bound adaptation per tcp_bbr.c bbr_adapt_lower_bounds().
// The rate sample parameter is reserved for future use (e.g., advanced loss analysis).
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
		ecnInflightLo = protocol.ByteCount(float64(bbr.inflightLo) * (1.0 - bbr.ecnAlpha*ECN_FACTOR))
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
func (bbr *BBRv3) checkLossTooHighInStartup(rs bbrRateSample) {
	if bbr.fullBandwidthReached {
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

// checkFullBwReached implements full bandwidth detection per tcp_bbr.c bbr_check_full_bw_reached().
func (bbr *BBRv3) checkFullBwReached(rs bbrRateSample) {
	if bbr.fullBandwidthNow || rs.isAppLimited || rs.deliveryRate == 0 {
		return
	}
	thresh := protocol.ByteCount(float64(max(bbr.fullBandwidth, 1)) * FULL_BW_GROWTH_THRESHOLD)
	if rs.deliveryRate >= thresh {
		bbr.resetFullBw()
		bbr.fullBandwidth = rs.deliveryRate
		return
	}
	if !bbr.roundStart {
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

// checkDrain implements STARTUP->DRAIN->PROBE_BW transitions per RFC §5.3.
func (bbr *BBRv3) checkDrain(rs bbrRateSample, now monotime.Time) {
	if bbr.state == BBRStartup && bbr.fullBandwidthReached {
		bbr.state = BBRDrain
		bbr.resetCongestionSignals()
	}
	if bbr.state == BBRDrain {
		if rs.bytesInFlight <= bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0) {
			bbr.state = BBRProbeBW
			bbr.startProbeBWDown(now)
		}
	}
}

// updateCyclePhase implements ProbeBW phase cycling per RFC §5.3.3.
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
			bbr.startProbeBWUp(now)
		}
	case probeBWUp:
		if bbr.prevProbeTooHigh && rs.bytesInFlight >= bbr.inflightHi {
			bbr.stoppedRiskyProbe = true
			bbr.prevProbeTooHigh = false
			bbr.startProbeBWDown(now)
			return
		}
		if bbr.isCwndLimited(rs.priorInFlight) && bbr.congestionWindow >= bbr.inflightHi {
			bbr.resetFullBw()
			bbr.fullBandwidth = rs.deliveryRate
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
		bbr.startProbeBWDown(bbr.pendingAckEventTime)
	}
}

func (bbr *BBRv3) probeInflightHiUpward(rs bbrRateSample) {
	if !bbr.isCwndLimited(rs.priorInFlight) || bbr.congestionWindow < bbr.inflightHi {
		return
	}
	bbr.bwProbeUpAcks += rs.newlyAcked
	if bbr.bwProbeUpCnt == 0 {
		bbr.raiseInflightHiSlope()
	}
	if bbr.bwProbeUpCnt > 0 && bbr.bwProbeUpAcks >= bbr.bwProbeUpCnt {
		delta := bbr.bwProbeUpAcks / bbr.bwProbeUpCnt
		bbr.bwProbeUpAcks -= delta * bbr.bwProbeUpCnt
		bbr.inflightHi += delta
	}
	if bbr.roundStart {
		bbr.raiseInflightHiSlope()
	}
}

func (bbr *BBRv3) raiseInflightHiSlope() {
	growthThisRound := protocol.ByteCount(1) << bbr.bwProbeUpRounds
	if bbr.bwProbeUpRounds < 30 {
		bbr.bwProbeUpRounds++
	}
	cnt := bbr.congestionWindow / max(growthThisRound, 1)
	bbr.bwProbeUpCnt = max(cnt, bbr.maxDatagramSize)
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

func (bbr *BBRv3) startProbeBWUp(now monotime.Time) {
	bbr.ackPhase = ackPhaseProbeStarting
	bbr.startRoundNow()
	bbr.resetFullBw()
	bbr.fullBandwidth = bbr.bwLatest
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
func (bbr *BBRv3) updateMinRTT(now monotime.Time) {
	if bbr.rttStats == nil {
		return
	}
	rttSample := bbr.rttStats.LatestRTT()
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
		probeRTTCwnd := bbr.probeRTTCwnd()
		if bbr.probeRTTDoneStamp.IsZero() && bbr.bytesInFlightAfterACK() <= probeRTTCwnd {
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
		bbr.startProbeBWDown(now)
		bbr.startProbeBWCruise(now)
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
}

// OnSpuriousLossDetected implements SpuriousLossHandler.
// Called when the transport detects that previously declared losses were spurious.
// Per RFC §5.5.11.2 (BBRHandleSpuriousLossDetection), we restore model bounds
// to their pre-loss values to undo loss-driven reductions that were triggered
// by reordering rather than actual congestion.
func (bbr *BBRv3) OnSpuriousLossDetected(spuriousCount int) {
	// Threshold check: only recover if enough spurious losses detected.
	// spuriousLossRecoveryThreshold=0 means recover on any spurious loss (count >= 1).
	// Higher values require that many spurious losses before triggering recovery.
	if spuriousCount < spuriousLossRecoveryThreshold {
		return
	}

	// Clear loss-in-round flag since the loss was spurious
	bbr.lossInRound = false

	// Reset full bandwidth estimator to re-probe after spurious loss
	bbr.resetFullBw()

	// Restore bounds to max of current and saved values.
	// Using max() ensures we only raise bounds, never lower them.
	// This prevents ping-ponging if some losses were real and some spurious.
	if bbr.undoBwLo != protocol.MaxByteCount && bbr.undoBwLo > bbr.bwLo {
		bbr.bwLo = bbr.undoBwLo
	}
	if bbr.undoInflightLo != protocol.MaxByteCount && bbr.undoInflightLo > bbr.inflightLo {
		bbr.inflightLo = bbr.undoInflightLo
	}
	if bbr.undoInflightHi != protocol.MaxByteCount && bbr.undoInflightHi > bbr.inflightHi {
		bbr.inflightHi = bbr.undoInflightHi
	}

	// If we were probing bandwidth when loss occurred, return to that state.
	// Per RFC §5.5.11.2, we restore probing state if not in ProbeRTT.
	if bbr.state != BBRProbeRTT && bbr.state != bbr.undoState {
		if bbr.undoState == BBRStartup {
			bbr.state = BBRStartup
			bbr.pacingGain = STARTUP_PACING_GAIN
			bbr.cwndGain = STARTUP_CWND_GAIN
			bbr.fullBandwidthReached = false
		} else if bbr.undoState == BBRProbeBW && bbr.undoProbeBWPhase == probeBWUp {
			bbr.startProbeBWUp(monotime.Now())
		}
	}

	// Recalculate cwnd with restored bounds
	bbr.setCwnd(bbrRateSample{})

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
			SpuriousCount:      spuriousCount,
			RestoredBwLo:       bwLoVal,
			RestoredInflightLo: inflightLoVal,
			RestoredInflightHi: inflightHiVal,
			RestoredCwnd:       uint64(bbr.congestionWindow),
		})
	}
}

// isInflightTooHigh checks for loss/ECN threshold violations per RFC §2.7.
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
		case probeBWDown:
			bbr.pacingGain = PROBE_BW_DOWN_GAIN
		default:
			bbr.pacingGain = PROBE_BW_BASE_GAIN
		}
		bbr.cwndGain = CWND_GAIN_DEFAULT
	case BBRProbeRTT:
		bbr.pacingGain = 1.0
		bbr.cwndGain = 1.0
	}
}

func (bbr *BBRv3) setPacingRateWithGain(gain float64) {
	bw := bbr.boundedBandwidth()
	if bw <= 0 {
		return
	}
	rate := protocol.ByteCount(float64(bw) * gain * BBR_PACING_MARGIN)
	if rate <= 0 {
		rate = 1
	}
	if bbr.fullBandwidthReached || rate > bbr.pacingRate {
		bbr.pacingRate = rate
	}
}

func (bbr *BBRv3) setSendQuantum() {
	if bbr.pacingRate == 0 {
		bbr.sendQuantum = max(2*bbr.maxDatagramSize, bbr.maxDatagramSize)
		bbr.offloadBudget = 3 * bbr.sendQuantum
		return
	}
	q := protocol.ByteCount(uint64(bbr.pacingRate) * uint64(time.Millisecond) / uint64(time.Second))
	q = min(q, protocol.ByteCount(64*1024))
	q = max(q, 2*bbr.maxDatagramSize)
	bbr.sendQuantum = q
	bbr.offloadBudget = 3 * q
}

func (bbr *BBRv3) setCwnd(rs bbrRateSample) {
	target := bbr.targetCwnd(bbr.cwndGain)
	if bbr.fullBandwidthReached {
		target += bbr.maxExtraAcked()
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

func (bbr *BBRv3) probeRTTCwnd() protocol.ByteCount {
	return max(bbr.inflightFromBWGain(bbr.maxBandwidth(), PROBE_RTT_CWND_GAIN), bbr.minPipeCwnd)
}

func (bbr *BBRv3) inflightFromBWGain(bw protocol.ByteCount, gain float64) protocol.ByteCount {
	if bw <= 0 {
		return max(bbr.initialCwnd, bbr.minPipeCwnd)
	}
	if bbr.minRTT <= 0 {
		return max(bbr.congestionWindow, bbr.minPipeCwnd)
	}
	bdp := protocol.ByteCount(uint64(bw) * uint64(bbr.minRTT) / uint64(time.Second))
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
		if bbr.extraAckedWinRTTs >= EXTRA_ACKED_WIN_RTS {
			bbr.extraAckedWinRTTs = 0
			if bbr.extraAckedWinIdx == 0 {
				bbr.extraAckedWinIdx = 1
			} else {
				bbr.extraAckedWinIdx = 0
			}
			bbr.extraAcked[bbr.extraAckedWinIdx] = 0
		}
	}

	epoch := now.Sub(bbr.ackEpochStart)
	expected := protocol.ByteCount(0)
	if epoch > 0 {
		expected = protocol.ByteCount(uint64(bbr.boundedBandwidth()) * uint64(epoch) / uint64(time.Second))
	}
	if bbr.ackEpochAcked <= expected || bbr.ackEpochAcked+rs.newlyAcked >= (1<<20) {
		bbr.ackEpochAcked = 0
		bbr.ackEpochStart = now
		expected = 0
	}
	bbr.ackEpochAcked = min(bbr.ackEpochAcked+rs.newlyAcked, protocol.ByteCount((1<<20)-1))
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
		cap = protocol.ByteCount(uint64(bbr.boundedBandwidth()) * uint64(EXTRA_ACKED_MAX_US) / uint64(time.Second))
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
	bbr.ecnInCycle = false
	bbr.bwLatest = 0
	bbr.inflightLatest = 0
	bbr.bytesLostInRound = 0
}

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

func (bbr *BBRv3) isCwndLimited(bytesInFlight protocol.ByteCount) bool {
	if bytesInFlight >= bbr.congestionWindow {
		return true
	}
	available := bbr.congestionWindow - bytesInFlight
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
			state = qlog.CongestionStateRecovery
		case BBRProbeBW:
			state = qlog.CongestionStateCongestionAvoidance
		case BBRProbeRTT:
			state = qlog.CongestionStateApplicationLimited
		}
		bbr.qlogger.RecordEvent(qlog.CongestionStateUpdated{State: state})

		// Emit BBRv3-specific state event
		phase := ""
		if bbr.state == BBRProbeBW {
			phase = bbr.probeBWPhase.String()
		}
		bbr.qlogger.RecordEvent(qlog.BBRv3StateUpdated{
			State:      bbr.state.String(),
			Phase:      phase,
			RoundCount: bbr.roundCount,
		})

		// Emit model update on state change
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
		bbr.qlogger.RecordEvent(qlog.BBRv3ModelUpdated{
			MaxBW:         uint64(bbr.maxBandwidth()),
			BwLo:          bwLoVal,
			BwHi:          bwHiVal,
			MinRTT:        bbr.minRTT,
			InflightHi:    inflightHiVal,
			InflightLo:    inflightLoVal,
			BDP:           uint64(bbr.inflightFromBWGain(bbr.maxBandwidth(), 1.0)),
			FullBWReached: bbr.fullBandwidthReached,
		})

		// Emit control update
		bbr.qlogger.RecordEvent(qlog.BBRv3ControlUpdated{
			PacingRate: uint64(bbr.pacingRate),
			Cwnd:       uint64(bbr.congestionWindow),
			PacingGain: bbr.pacingGain,
			CwndGain:   bbr.cwndGain,
		})
	}
}

// maybeQlogRoundUpdate emits qlog events on round boundaries.
func (bbr *BBRv3) maybeQlogRoundUpdate() {
	if bbr.qlogger == nil || !bbr.roundStart || bbr.roundCount == bbr.lastRoundCount {
		return
	}
	bbr.lastRoundCount = bbr.roundCount
	bbr.qlogger.RecordEvent(qlog.BBRv3RoundUpdated{
		RoundCount:       bbr.roundCount,
		LossInRound:      bbr.lossInRound,
		ECNInRound:       bbr.ecnInRound,
		BytesLostInRound: uint64(bbr.bytesLostInRound),
	})
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
