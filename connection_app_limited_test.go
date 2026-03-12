package quic

import (
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type appLimitedTrackingSentPacketHandler struct {
	*mockackhandler.MockSentPacketHandler
	marked int
}

func (h *appLimitedTrackingSentPacketHandler) MarkAppLimited() {
	h.marked++
}

func TestConnectionMaybeMarkAppLimitedOnResumptionNotifiesHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := &appLimitedTrackingSentPacketHandler{MockSentPacketHandler: mockackhandler.NewMockSentPacketHandler(ctrl)}
	tc := newServerTestConnection(t, ctrl, nil, false, connectionOptSentPacketHandler(sph))

	now := monotime.Now()
	sph.EXPECT().SendMode(now).Return(ackhandler.SendAny)

	tc.conn.maybeMarkAppLimitedOnResumption(now)

	require.Equal(t, 1, sph.marked)
}

func TestConnectionSendPacketsWithoutGSOMarksAppLimitedOnNothingToPack(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := &appLimitedTrackingSentPacketHandler{MockSentPacketHandler: mockackhandler.NewMockSentPacketHandler(ctrl)}
	tc := newServerTestConnection(t, ctrl, nil, false, connectionOptSentPacketHandler(sph))

	now := monotime.Now()
	sph.EXPECT().ECNMode(true).Return(protocol.ECNUnsupported)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), now, gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)

	require.NoError(t, tc.conn.sendPacketsWithoutGSO(now))
	require.Equal(t, 1, sph.marked)
}

func TestConnectionSendPacketsWithGSOMarksAppLimitedOnNothingToPack(t *testing.T) {
	ctrl := gomock.NewController(t)
	sph := &appLimitedTrackingSentPacketHandler{MockSentPacketHandler: mockackhandler.NewMockSentPacketHandler(ctrl)}
	tc := newServerTestConnection(t, ctrl, nil, true, connectionOptSentPacketHandler(sph))

	now := monotime.Now()
	sph.EXPECT().ECNMode(true).Return(protocol.ECNUnsupported)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), now, gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack)

	require.NoError(t, tc.conn.sendPacketsWithGSO(now))
	require.Equal(t, 1, sph.marked)
}
