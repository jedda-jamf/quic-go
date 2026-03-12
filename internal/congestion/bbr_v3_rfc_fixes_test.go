package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestBBRv3PTORecoveryUsesInflightAndPreservesPriorCwnd(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.state = BBRProbeBW
	bbr.congestionWindow = 20 * bbr.maxDatagramSize
	initialCwnd := bbr.congestionWindow

	bbr.OnPTO(8 * bbr.maxDatagramSize)
	require.True(t, bbr.ptoRecovery)
	require.Equal(t, initialCwnd, bbr.priorCwnd)
	require.Equal(t, 9*bbr.maxDatagramSize, bbr.congestionWindow)
	require.Equal(t, BBRProbeBW, bbr.undoState)

	bbr.OnPTO(2 * bbr.maxDatagramSize)
	require.Equal(t, initialCwnd, bbr.priorCwnd)
	require.Equal(t, 3*bbr.maxDatagramSize, bbr.congestionWindow)
}

func TestBBRv3GuardrailProbeRTTUsesAckEventInflightAfterLoss(t *testing.T) {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(25*time.Millisecond, 0)
	bbr := NewBBRV3(DefaultClock{}, rttStats, nil, initialMaxDatagramSize, false, nil)
	now := monotime.Now()

	bbr.state = BBRProbeRTT
	bbr.totalBytesAcked = 50_000
	bbr.pendingPriorInFlight = 10 * bbr.maxDatagramSize
	bbr.pendingAckedBytes = 2 * bbr.maxDatagramSize
	bbr.ackEventTime = now
	bbr.ackEventBytesInFlight = 6 * bbr.maxDatagramSize

	bbr.updateMinRTT(now)

	require.Equal(t, now.Add(PROBE_RTT_DURATION), bbr.probeRTTDoneStamp)
	require.Equal(t, bbr.totalBytesAcked+uint64(4*bbr.maxDatagramSize), bbr.appLimitedUntil)
}

func TestBBRv3ShortIntervalSamplesKeepLatestDeliveryBookkeeping(t *testing.T) {
	bbr := newTestBBRv3()
	bbr.bwLatest = 9_000
	bbr.inflightLatest = 3_000
	bbr.totalBytesAcked = 42_000
	bbr.lossRoundDelivered = 10_000

	bbr.updateLatestDeliverySignals(bbrRateSample{
		deliveryRate:   0,
		newlyAcked:     1200,
		delivered:      7_200,
		priorDelivered: 10_000,
	})

	require.Equal(t, protocol.ByteCount(9_000), bbr.bwLatest)
	require.Equal(t, protocol.ByteCount(7_200), bbr.inflightLatest)
	require.True(t, bbr.lossRoundStart)
	require.Equal(t, uint64(42_000), bbr.lossRoundDelivered)
}
