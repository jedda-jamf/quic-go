package congestion

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
)

const (
	// minReorderThreshold is the RFC 9002 default (kPacketThreshold).
	minReorderThreshold = 3
	// maxReorderThreshold is the practical maximum to prevent unbounded growth.
	maxReorderThreshold = 255
	// thresholdDecayInterval: decay threshold by 1 after this many genuine losses.
	thresholdDecayInterval = 10
)

// NewRenoRackSender implements a NewReno congestion controller with RACK-style
// adaptive reordering threshold. Instead of the fixed packet threshold of 3
// from RFC 9002, this implementation tracks observed packet reordering and
// increases the threshold when spurious losses are detected.
//
// This approach follows TCP-RACK's philosophy: use packet counting for fast
// loss detection, but adapt the threshold based on observed network behavior
// to avoid spurious loss events on networks with significant reordering
// (e.g., cellular dual-connectivity 4G+5G paths).
//
// The time-based loss detection threshold (9/8 × RTT) remains unchanged,
// ensuring eventual loss detection regardless of the packet threshold.
type NewRenoRackSender struct {
	*cubicSender // Embed for NewReno behavior (reno=true)

	// reorderThreshold is the current packet reordering threshold.
	// Starts at 3 (RFC 9002 default) and increases on spurious loss detection.
	reorderThreshold protocol.PacketNumber

	// spuriousLossCount is the cumulative count of spurious losses detected.
	spuriousLossCount uint64

	// genuineLossCount tracks genuine losses for threshold decay.
	genuineLossCount uint64

	// maxObservedReorder is the maximum packet reordering distance observed.
	maxObservedReorder protocol.PacketNumber

	qlogger qlogwriter.Recorder
}

var (
	_ SendAlgorithm               = &NewRenoRackSender{}
	_ SendAlgorithmWithDebugInfos = &NewRenoRackSender{}
)

// NewNewRenoRackSender creates a NewReno congestion controller with RACK-style
// adaptive reordering threshold. This is the algo/newreno-rack branch baseline.
func NewNewRenoRackSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *NewRenoRackSender {
	return &NewRenoRackSender{
		cubicSender: NewCubicSender(
			clock, rttStats, connStats,
			initialMaxDatagramSize,
			true, // reno=true for NewReno behavior
			qlogger,
		),
		reorderThreshold: minReorderThreshold,
		qlogger:          qlogger,
	}
}

// GetPacketReorderThreshold returns the current adaptive reordering threshold.
// This starts at 3 (RFC 9002 default) and increases when spurious losses are
// detected, up to maxReorderThreshold.
func (s *NewRenoRackSender) GetPacketReorderThreshold() protocol.PacketNumber {
	return s.reorderThreshold
}

// OnSpuriousLossDetected is called when a packet previously declared lost is
// acknowledged. This indicates the packet threshold was too aggressive for
// the current network conditions.
func (s *NewRenoRackSender) OnSpuriousLossDetected(pn protocol.PacketNumber, reordering protocol.PacketNumber) {
	s.spuriousLossCount++

	// Track maximum observed reordering
	if reordering > s.maxObservedReorder {
		s.maxObservedReorder = reordering
	}

	// Increase threshold to accommodate observed reordering + margin
	newThreshold := reordering + 1
	if newThreshold > s.reorderThreshold && newThreshold <= maxReorderThreshold {
		s.reorderThreshold = newThreshold
		s.emitThresholdUpdate()
	}
}

// OnCongestionEvent overrides cubicSender to track genuine losses and
// optionally decay the threshold back toward the RFC 9002 default.
func (s *NewRenoRackSender) OnCongestionEvent(pn protocol.PacketNumber, lostBytes, priorInFlight protocol.ByteCount) {
	s.genuineLossCount++

	// Decay threshold after sustained genuine losses
	if s.genuineLossCount > 0 && s.genuineLossCount%thresholdDecayInterval == 0 {
		if s.reorderThreshold > minReorderThreshold {
			s.reorderThreshold--
			s.emitThresholdUpdate()
		}
	}

	s.cubicSender.OnCongestionEvent(pn, lostBytes, priorInFlight)
}

func (s *NewRenoRackSender) emitThresholdUpdate() {
	if s.qlogger != nil {
		s.qlogger.RecordEvent(qlog.RACKThresholdUpdated{
			Threshold:          uint64(s.reorderThreshold),
			SpuriousLossCount:  s.spuriousLossCount,
			MaxObservedReorder: uint64(s.maxObservedReorder),
		})
	}
}
