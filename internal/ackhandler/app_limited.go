package ackhandler

type appLimitedMarker interface {
	MarkAppLimited()
}

// NotifyAppLimited forwards a send-opportunity-without-data signal to the
// concrete sent packet handler when it supports app-limited tracking.
func NotifyAppLimited(h SentPacketHandler) {
	if marker, ok := h.(appLimitedMarker); ok {
		marker.MarkAppLimited()
	}
}
