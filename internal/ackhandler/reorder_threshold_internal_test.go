package ackhandler

import (
    "testing"
    
    "github.com/quic-go/quic-go/internal/congestion"
    "github.com/quic-go/quic-go/internal/protocol"
    "github.com/quic-go/quic-go/internal/utils"
    "github.com/stretchr/testify/require"
)

func TestBBRv3ImplementsPacketReorderingThresholdProvider(t *testing.T) {
    rttStats := utils.NewRTTStats()
    bbr := congestion.NewBBRV3(
        congestion.DefaultClock{},
        rttStats,
        nil,
        1200,
        true,
        nil,
    )
    
    // Store as the interface type that ackhandler uses
    var sa congestion.SendAlgorithmWithDebugInfos = bbr
    
    // Check via SendAlgorithmWithDebugInfos (how ackhandler stores it)
    pth, ok := sa.(congestion.PacketReorderingThresholdProvider)
    require.True(t, ok, "BBRv3 via SendAlgorithmWithDebugInfos should implement PacketReorderingThresholdProvider")
    require.Equal(t, protocol.PacketNumber(10), pth.GetPacketReorderThreshold())
}
