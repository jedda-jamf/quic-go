package ackhandler

import (
	"slices"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
)

// Seq3 is a three-value iterator function, analogous to iter.Seq2.
type Seq3[K, V, W any] func(yield func(K, V, W) bool)

type lostPacket struct {
	PacketNumber protocol.PacketNumber
	SendTime     monotime.Time
	Length       protocol.ByteCount
}

type lostPacketTracker struct {
	maxLength   int
	lostPackets []lostPacket
}

func newLostPacketTracker(maxLength int) *lostPacketTracker {
	return &lostPacketTracker{
		maxLength: maxLength,
		// Preallocate a small slice only.
		// Hopefully we won't lose many packets.
		lostPackets: make([]lostPacket, 0, 4),
	}
}

func (t *lostPacketTracker) Add(p protocol.PacketNumber, sendTime monotime.Time, length protocol.ByteCount) {
	if len(t.lostPackets) == t.maxLength {
		t.lostPackets = t.lostPackets[1:]
	}
	t.lostPackets = append(t.lostPackets, lostPacket{
		PacketNumber: p,
		SendTime:     sendTime,
		Length:       length,
	})
}

// Delete deletes a packet from the lost packet tracker.
// This function is not optimized for performance if many packets are lost,
// but it is only used when a spurious loss is detected, which is rare.
func (t *lostPacketTracker) Delete(pn protocol.PacketNumber) {
	t.lostPackets = slices.DeleteFunc(t.lostPackets, func(p lostPacket) bool {
		return p.PacketNumber == pn
	})
}

func (t *lostPacketTracker) All() Seq3[protocol.PacketNumber, monotime.Time, protocol.ByteCount] {
	return func(yield func(protocol.PacketNumber, monotime.Time, protocol.ByteCount) bool) {
		for _, p := range t.lostPackets {
			if !yield(p.PacketNumber, p.SendTime, p.Length) {
				return
			}
		}
	}
}

func (t *lostPacketTracker) DeleteBefore(ti monotime.Time) {
	if len(t.lostPackets) == 0 {
		return
	}
	if !t.lostPackets[0].SendTime.Before(ti) {
		return
	}
	var idx int
	for ; idx < len(t.lostPackets); idx++ {
		if !t.lostPackets[idx].SendTime.Before(ti) {
			break
		}
	}
	t.lostPackets = slices.Delete(t.lostPackets, 0, idx)
}
