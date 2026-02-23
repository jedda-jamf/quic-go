package congestion

import (
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

// NewCubicCongestionSender returns a TCP CUBIC congestion controller as
// described in RFC 8312. This is the algo/cubic branch baseline.
//
// CUBIC grows the congestion window as a cubic function of time since the
// last loss event, converging on W_max faster than linear Reno growth after
// a deep cut and more slowly when approaching W_max. On loss, CWND is
// reduced by beta=0.7 and W_max is recorded for the next epoch's K calculation.
// When CWND is small, TCP-friendliness ensures CUBIC never grows slower than
// an equivalent NewReno connection.
//
// The key difference from algo/newreno is post-loss recovery: CUBIC's cubic
// curve allows faster CWND restoration in high-bandwidth, high-RTT paths than
// Reno's linear AIMD, while the TCP-friendliness floor ensures fairness on
// lower-RTT links.
func NewCubicCongestionSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) SendAlgorithmWithDebugInfos {
	return NewCubicSender(clock, rttStats, connStats, initialMaxDatagramSize, false, qlogger)
}
