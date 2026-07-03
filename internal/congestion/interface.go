package congestion

import (
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// A SendAlgorithm performs congestion control
type SendAlgorithm interface {
	TimeUntilSend(bytesInFlight protocol.ByteCount) monotime.Time
	HasPacingBudget(now monotime.Time) bool
	OnPacketSent(sentTime monotime.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool)
	CanSend(bytesInFlight protocol.ByteCount) bool
	MaybeExitSlowStart()
	OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime monotime.Time)
	OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount)
	OnRetransmissionTimeout(packetsRetransmitted bool)
	SetMaxDatagramSize(protocol.ByteCount)
}

// A SendAlgorithmWithRTTStats is a SendAlgorithm that supports late RTT stats binding.
type SendAlgorithmWithRTTStats interface {
	SendAlgorithm
	SetRTTStats(*utils.RTTStats)
}

// A SendAlgorithmWithDebugInfos is a SendAlgorithm that exposes some debug infos
type SendAlgorithmWithDebugInfos interface {
	SendAlgorithm
	InSlowStart() bool
	InRecovery() bool
	GetCongestionWindow() protocol.ByteCount
}

// AckEventHandler is implemented by congestion controllers that need ACK-event
// boundaries instead of only per-packet callbacks.
type AckEventHandler interface {
	OnAckEventStart(eventTime monotime.Time, bytesInFlight protocol.ByteCount)
	OnAckEventEnd(eventTime monotime.Time)
}

// LossDetectionHandler is implemented by congestion controllers that need a
// callback before each loss-detection pass (both ACK-driven and timer-driven).
// now is the event time of the pass: the ACK receive time for ACK-driven
// passes, or the timer fire time for timer-driven passes. It gives the
// controller a valid clock for any state transition triggered from within the
// per-lost-packet path, where no ACK-event timestamp is available yet.
type LossDetectionHandler interface {
	OnLossDetectionStart(now monotime.Time)
}

// ECNFeedbackHandler is implemented by congestion controllers that consume
// QUIC ACK-frame ECN counters directly.
type ECNFeedbackHandler interface {
	OnECNFeedback(
		ackedBytes protocol.ByteCount,
		ect0Total, ect1Total, ceTotal int64,
		priorInFlight protocol.ByteCount,
		eventTime monotime.Time,
	)
}

// AppLimitedHandler is implemented by congestion controllers that track
// app-limited bubbles explicitly.
type AppLimitedHandler interface {
	MarkAppLimited(bytesInFlight protocol.ByteCount)
}

// SpuriousLossHandler is implemented by congestion controllers that can react
// to packets that were spuriously declared lost.
type SpuriousLossHandler interface {
	OnSpuriousLossDetected(packetNumber protocol.PacketNumber, packetReordering protocol.PacketNumber)
}

// PacketDiscardHandler is implemented by congestion controllers that track
// per-packet state and need to forget packets whose packet number space was
// dropped (Initial/Handshake completion, 0-RTT rejection). The packets were
// neither acked nor lost; they must simply become invisible to the
// controller's samplers. Without this signal, per-packet state keyed by raw
// packet number leaks, and later 1-RTT packets reusing the same raw PN can
// be misclassified as PN-space collisions (review F7, 2026-07-03).
type PacketDiscardHandler interface {
	OnPacketDiscarded(packetNumber protocol.PacketNumber)
}

// PTOHandler is implemented by congestion controllers that want an explicit
// QUIC PTO signal with live inflight. now is the time the PTO timer fired;
// controllers use it to validate that later-delivered data was sent after
// the PTO before restoring pre-PTO state (cf. RFC 9002 PTO semantics).
type PTOHandler interface {
	OnPTO(now monotime.Time, bytesInFlight protocol.ByteCount)
}

// ConnectionMigrationHandler is implemented by custom congestion controllers
// that want to reset themselves in place on path migration.
type ConnectionMigrationHandler interface {
	OnConnectionMigration(initialMaxDatagramSize protocol.ByteCount)
}
