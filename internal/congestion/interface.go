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
// callback before each loss-detection pass.
type LossDetectionHandler interface {
	OnLossDetectionStart()
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

// PacketReorderingThresholdProvider is implemented by congestion controllers
// that want to override the default RFC 9002 packet reordering threshold.
type PacketReorderingThresholdProvider interface {
	GetPacketReorderThreshold() protocol.PacketNumber
}

// PTOHandler is implemented by congestion controllers that want an explicit
// QUIC PTO signal with live inflight.
type PTOHandler interface {
	OnPTO(bytesInFlight protocol.ByteCount)
}

// ConnectionMigrationHandler is implemented by custom congestion controllers
// that want to reset themselves in place on path migration.
type ConnectionMigrationHandler interface {
	OnConnectionMigration(initialMaxDatagramSize protocol.ByteCount)
}
