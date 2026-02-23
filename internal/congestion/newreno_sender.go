package congestion

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

// NewNewRenoSender returns a NewReno congestion controller as described in
// RFC 5681 and RFC 6582. This is the algorithm used as the baseline for the
// quic-go A/B lab: additive increase (1 MSS per RTT in congestion avoidance),
// multiplicative decrease (CWND × 0.7 on loss), and RFC 6582 fast recovery.
//
// Internally this is the existing cubicSender with reno=true. The CUBIC
// window-growth code paths are compiled in but never reached. The name
// exists to make branch intent explicit: any connection using this branch
// is unambiguously running NewReno, not CUBIC.
func NewNewRenoSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) SendAlgorithmWithDebugInfos {
	return NewCubicSender(clock, rttStats, connStats, initialMaxDatagramSize, true, qlogger)
}
