package ackhandler

import (
	"testing"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestSentPacketHandlerMarkAppLimitedForwardsBytesInFlight(t *testing.T) {
	cong := &hookTrackingCongestion{}
	sph := NewSentPacketHandler(
		0,
		1200,
		utils.NewRTTStats(),
		&utils.ConnectionStats{},
		false,
		false,
		nil,
		protocol.PerspectiveClient,
		nil,
		cong,
		utils.DefaultLogger,
	).(*sentPacketHandler)
	sph.bytesInFlight = 4321

	sph.MarkAppLimited()

	require.Equal(t, []protocol.ByteCount{4321}, cong.appLimitedBytes)
}
