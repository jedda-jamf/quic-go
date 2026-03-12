package ackhandler_test

import (
	"testing"

	"github.com/quic-go/quic-go/internal/ackhandler"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestNotifyAppLimitedNoopForPlainHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	handler := mockackhandler.NewMockSentPacketHandler(ctrl)

	require.NotPanics(t, func() {
		ackhandler.NotifyAppLimited(handler)
	})
}
