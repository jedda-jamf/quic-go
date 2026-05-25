package ackhandler

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestLostPacketTracker(t *testing.T) {
	lt := newLostPacketTracker(4)

	start := monotime.Now()
	lt.Add(1, start, 1000)
	lt.Add(5, start.Add(time.Second), 1100)
	lt.Add(8, start.Add(2*time.Second), 1200)

	// Collect results into maps
	times := make(map[protocol.PacketNumber]monotime.Time)
	lengths := make(map[protocol.PacketNumber]protocol.ByteCount)
	lt.All()(func(pn protocol.PacketNumber, sendTime monotime.Time, length protocol.ByteCount) bool {
		times[pn] = sendTime
		lengths[pn] = length
		return true
	})
	require.Equal(t, map[protocol.PacketNumber]monotime.Time{
		1: start,
		5: start.Add(time.Second),
		8: start.Add(2 * time.Second),
	}, times)
	require.Equal(t, map[protocol.PacketNumber]protocol.ByteCount{
		1: 1000,
		5: 1100,
		8: 1200,
	}, lengths)

	// Lose 2 more packets. The first one should be removed.
	lt.Add(10, start.Add(3*time.Second), 1300)
	lt.Add(11, start.Add(4*time.Second), 1400)
	times = make(map[protocol.PacketNumber]monotime.Time)
	lt.All()(func(pn protocol.PacketNumber, sendTime monotime.Time, _ protocol.ByteCount) bool {
		times[pn] = sendTime
		return true
	})
	require.Equal(t, map[protocol.PacketNumber]monotime.Time{
		5:  start.Add(time.Second),
		8:  start.Add(2 * time.Second),
		10: start.Add(3 * time.Second),
		11: start.Add(4 * time.Second),
	}, times)

	lt.Delete(5)
	lt.Delete(10)
	times = make(map[protocol.PacketNumber]monotime.Time)
	lt.All()(func(pn protocol.PacketNumber, sendTime monotime.Time, _ protocol.ByteCount) bool {
		times[pn] = sendTime
		return true
	})
	require.Equal(t, map[protocol.PacketNumber]monotime.Time{
		8:  start.Add(2 * time.Second),
		11: start.Add(4 * time.Second),
	}, times)
}

func TestLostPacketTrackerDeleteBefore(t *testing.T) {
	lt := newLostPacketTracker(4)

	trackedPackets := func(lt *lostPacketTracker) []protocol.PacketNumber {
		var pns []protocol.PacketNumber
		lt.All()(func(pn protocol.PacketNumber, _ monotime.Time, _ protocol.ByteCount) bool {
			pns = append(pns, pn)
			return true
		})
		return pns
	}

	start := monotime.Now()
	lt.Add(1, start, 1000)
	lt.Add(5, start.Add(time.Second), 1100)
	lt.Add(8, start.Add(2*time.Second), 1200)
	lt.Add(10, start.Add(3*time.Second), 1300)

	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start) // this should be a no-op
	require.Equal(t, []protocol.PacketNumber{1, 5, 8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(2 * time.Second))
	require.Equal(t, []protocol.PacketNumber{8, 10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Second * 5 / 2))
	require.Equal(t, []protocol.PacketNumber{10}, trackedPackets(lt))

	lt.DeleteBefore(start.Add(time.Hour))
	require.Empty(t, trackedPackets(lt))
}
