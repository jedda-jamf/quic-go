package qlog

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/qlogwriter/jsontext"
)

func milliseconds(dur time.Duration) float64 { return float64(dur.Nanoseconds()) / 1e6 }

type encoderHelper struct {
	enc *jsontext.Encoder
	err error
}

func (h *encoderHelper) WriteToken(t jsontext.Token) {
	if h.err != nil {
		return
	}
	h.err = h.enc.WriteToken(t)
}

type versions []Version

func (v versions) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginArray)
	for _, e := range v {
		h.WriteToken(jsontext.String(fmt.Sprintf("%x", uint32(e))))
	}
	h.WriteToken(jsontext.EndArray)
	return h.err
}

type RawInfo struct {
	Length        int // full packet length, including header and AEAD authentication tag
	PayloadLength int // length of the packet payload, excluding AEAD tag
}

func (i RawInfo) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("length"))
	h.WriteToken(jsontext.Uint(uint64(i.Length)))
	if i.PayloadLength != 0 {
		h.WriteToken(jsontext.String("payload_length"))
		h.WriteToken(jsontext.Uint(uint64(i.PayloadLength)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PathEndpointInfo struct {
	IPv4 netip.AddrPort
	IPv6 netip.AddrPort
}

func (p PathEndpointInfo) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if p.IPv4.IsValid() {
		h.WriteToken(jsontext.String("ip_v4"))
		h.WriteToken(jsontext.String(p.IPv4.Addr().String()))
		h.WriteToken(jsontext.String("port_v4"))
		h.WriteToken(jsontext.Int(int64(p.IPv4.Port())))
	}
	if p.IPv6.IsValid() {
		h.WriteToken(jsontext.String("ip_v6"))
		h.WriteToken(jsontext.String(p.IPv6.Addr().String()))
		h.WriteToken(jsontext.String("port_v6"))
		h.WriteToken(jsontext.Int(int64(p.IPv6.Port())))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type StartedConnection struct {
	Local  PathEndpointInfo
	Remote PathEndpointInfo
}

func (e StartedConnection) Name() string { return "transport:connection_started" }

func (e StartedConnection) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("local"))
	if err := e.Local.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("remote"))
	if err := e.Remote.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type VersionInformation struct {
	ClientVersions, ServerVersions []Version
	ChosenVersion                  Version
}

func (e VersionInformation) Name() string { return "transport:version_information" }

func (e VersionInformation) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if len(e.ClientVersions) > 0 {
		h.WriteToken(jsontext.String("client_versions"))
		if err := versions(e.ClientVersions).encode(enc); err != nil {
			return err
		}
	}
	if len(e.ServerVersions) > 0 {
		h.WriteToken(jsontext.String("server_versions"))
		if err := versions(e.ServerVersions).encode(enc); err != nil {
			return err
		}
	}
	h.WriteToken(jsontext.String("chosen_version"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", uint32(e.ChosenVersion))))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ConnectionClosed struct {
	Initiator Initiator

	ConnectionError  *TransportErrorCode
	ApplicationError *ApplicationErrorCode

	Reason string

	Trigger ConnectionCloseTrigger
}

func (e ConnectionClosed) Name() string { return "transport:connection_closed" }

func (e ConnectionClosed) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("initiator"))
	h.WriteToken(jsontext.String(string(e.Initiator)))
	if e.ConnectionError != nil {
		h.WriteToken(jsontext.String("connection_error"))
		if e.ConnectionError.IsCryptoError() {
			h.WriteToken(jsontext.String(fmt.Sprintf("crypto_error_%#x", uint16(*e.ConnectionError))))
		} else {
			switch *e.ConnectionError {
			case qerr.NoError:
				h.WriteToken(jsontext.String("no_error"))
			case qerr.InternalError:
				h.WriteToken(jsontext.String("internal_error"))
			case qerr.ConnectionRefused:
				h.WriteToken(jsontext.String("connection_refused"))
			case qerr.FlowControlError:
				h.WriteToken(jsontext.String("flow_control_error"))
			case qerr.StreamLimitError:
				h.WriteToken(jsontext.String("stream_limit_error"))
			case qerr.StreamStateError:
				h.WriteToken(jsontext.String("stream_state_error"))
			case qerr.FinalSizeError:
				h.WriteToken(jsontext.String("final_size_error"))
			case qerr.FrameEncodingError:
				h.WriteToken(jsontext.String("frame_encoding_error"))
			case qerr.TransportParameterError:
				h.WriteToken(jsontext.String("transport_parameter_error"))
			case qerr.ConnectionIDLimitError:
				h.WriteToken(jsontext.String("connection_id_limit_error"))
			case qerr.ProtocolViolation:
				h.WriteToken(jsontext.String("protocol_violation"))
			case qerr.InvalidToken:
				h.WriteToken(jsontext.String("invalid_token"))
			case qerr.ApplicationErrorErrorCode:
				h.WriteToken(jsontext.String("application_error"))
			case qerr.CryptoBufferExceeded:
				h.WriteToken(jsontext.String("crypto_buffer_exceeded"))
			case qerr.KeyUpdateError:
				h.WriteToken(jsontext.String("key_update_error"))
			case qerr.AEADLimitReached:
				h.WriteToken(jsontext.String("aead_limit_reached"))
			case qerr.NoViablePathError:
				h.WriteToken(jsontext.String("no_viable_path"))
			default:
				h.WriteToken(jsontext.String("unknown"))
				h.WriteToken(jsontext.String("error_code"))
				h.WriteToken(jsontext.Uint(uint64(*e.ConnectionError)))
			}
		}
	}
	if e.ApplicationError != nil {
		h.WriteToken(jsontext.String("application_error"))
		h.WriteToken(jsontext.String("unknown"))
		h.WriteToken(jsontext.String("error_code"))
		h.WriteToken(jsontext.Uint(uint64(*e.ApplicationError)))
	}
	if e.ConnectionError != nil || e.ApplicationError != nil {
		h.WriteToken(jsontext.String("reason"))
		h.WriteToken(jsontext.String(e.Reason))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(string(e.Trigger)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketSent struct {
	Header            PacketHeader
	Raw               RawInfo
	DatagramID        DatagramID
	Frames            []Frame
	ECN               ECN
	IsCoalesced       bool
	Trigger           string
	SupportedVersions []Version
}

func (e PacketSent) Name() string { return "transport:packet_sent" }

func (e PacketSent) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramID != 0 {
		h.WriteToken(jsontext.String("datagram_id"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramID)))
	}
	if len(e.Frames) > 0 {
		h.WriteToken(jsontext.String("frames"))
		if err := frames(e.Frames).encode(enc); err != nil {
			return err
		}
	}
	if e.IsCoalesced {
		h.WriteToken(jsontext.String("is_coalesced"))
		h.WriteToken(jsontext.True)
	}
	if e.ECN != ECNUnsupported {
		h.WriteToken(jsontext.String("ecn"))
		h.WriteToken(jsontext.String(string(e.ECN)))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketReceived struct {
	Header      PacketHeader
	Raw         RawInfo
	DatagramID  DatagramID
	Frames      []Frame
	ECN         ECN
	IsCoalesced bool
	Trigger     string
}

func (e PacketReceived) Name() string { return "transport:packet_received" }

func (e PacketReceived) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramID != 0 {
		h.WriteToken(jsontext.String("datagram_id"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramID)))
	}
	if len(e.Frames) > 0 {
		h.WriteToken(jsontext.String("frames"))
		if err := frames(e.Frames).encode(enc); err != nil {
			return err
		}
	}
	if e.IsCoalesced {
		h.WriteToken(jsontext.String("is_coalesced"))
		h.WriteToken(jsontext.True)
	}
	if e.ECN != ECNUnsupported {
		h.WriteToken(jsontext.String("ecn"))
		h.WriteToken(jsontext.String(string(e.ECN)))
	}
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type VersionNegotiationReceived struct {
	Header            PacketHeaderVersionNegotiation
	SupportedVersions []Version
}

func (e VersionNegotiationReceived) Name() string { return "transport:packet_received" }

func (e VersionNegotiationReceived) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("supported_versions"))
	if err := versions(e.SupportedVersions).encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type VersionNegotiationSent struct {
	Header            PacketHeaderVersionNegotiation
	SupportedVersions []Version
}

func (e VersionNegotiationSent) Name() string { return "transport:packet_sent" }

func (e VersionNegotiationSent) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("supported_versions"))
	if err := versions(e.SupportedVersions).encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketBuffered struct {
	Header     PacketHeader
	Raw        RawInfo
	DatagramID DatagramID
}

func (e PacketBuffered) Name() string { return "transport:packet_buffered" }

func (e PacketBuffered) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramID != 0 {
		h.WriteToken(jsontext.String("datagram_id"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramID)))
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String("keys_unavailable"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// PacketDropped is the transport:packet_dropped event.
type PacketDropped struct {
	Header     PacketHeader
	Raw        RawInfo
	DatagramID DatagramID
	Trigger    PacketDropReason
}

func (e PacketDropped) Name() string { return "transport:packet_dropped" }

func (e PacketDropped) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("raw"))
	if err := e.Raw.encode(enc); err != nil {
		return err
	}
	if e.DatagramID != 0 {
		h.WriteToken(jsontext.String("datagram_id"))
		h.WriteToken(jsontext.Uint(uint64(e.DatagramID)))
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(string(e.Trigger)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type MTUUpdated struct {
	Value int
	Done  bool
}

func (e MTUUpdated) Name() string { return "recovery:mtu_updated" }

func (e MTUUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("mtu"))
	h.WriteToken(jsontext.Uint(uint64(e.Value)))
	h.WriteToken(jsontext.String("done"))
	h.WriteToken(jsontext.Bool(e.Done))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// MetricsUpdated logs RTT and congestion metrics as defined in the
// recovery:metrics_updated event.
// The PTO count is logged via PTOCountUpdated.
type MetricsUpdated struct {
	MinRTT           time.Duration
	SmoothedRTT      time.Duration
	LatestRTT        time.Duration
	RTTVariance      time.Duration
	CongestionWindow int
	BytesInFlight    int
	PacketsInFlight  int
}

func (e MetricsUpdated) Name() string { return "recovery:metrics_updated" }

func (e MetricsUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.MinRTT != 0 {
		h.WriteToken(jsontext.String("min_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.MinRTT)))
	}
	if e.SmoothedRTT != 0 {
		h.WriteToken(jsontext.String("smoothed_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.SmoothedRTT)))
	}
	if e.LatestRTT != 0 {
		h.WriteToken(jsontext.String("latest_rtt"))
		h.WriteToken(jsontext.Float(milliseconds(e.LatestRTT)))
	}
	if e.RTTVariance != 0 {
		h.WriteToken(jsontext.String("rtt_variance"))
		h.WriteToken(jsontext.Float(milliseconds(e.RTTVariance)))
	}
	if e.CongestionWindow != 0 {
		h.WriteToken(jsontext.String("congestion_window"))
		h.WriteToken(jsontext.Uint(uint64(e.CongestionWindow)))
	}
	if e.BytesInFlight != 0 {
		h.WriteToken(jsontext.String("bytes_in_flight"))
		h.WriteToken(jsontext.Uint(uint64(e.BytesInFlight)))
	}
	if e.PacketsInFlight != 0 {
		h.WriteToken(jsontext.String("packets_in_flight"))
		h.WriteToken(jsontext.Uint(uint64(e.PacketsInFlight)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// PTOCountUpdated logs the pto_count value of the
// recovery:metrics_updated event.
type PTOCountUpdated struct {
	PTOCount uint32
}

func (e PTOCountUpdated) Name() string { return "recovery:metrics_updated" }

func (e PTOCountUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("pto_count"))
	h.WriteToken(jsontext.Uint(uint64(e.PTOCount)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PacketLost struct {
	Header  PacketHeader
	Trigger PacketLossReason
}

func (e PacketLost) Name() string { return "recovery:packet_lost" }

func (e PacketLost) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("header"))
	if err := e.Header.encode(enc); err != nil {
		return err
	}
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(string(e.Trigger)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type SpuriousLoss struct {
	EncryptionLevel  protocol.EncryptionLevel
	PacketNumber     protocol.PacketNumber
	PacketReordering uint64
	TimeReordering   time.Duration
}

func (e SpuriousLoss) Name() string { return "recovery:spurious_loss" }

func (e SpuriousLoss) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("packet_number_space"))
	h.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncryptionLevel)))
	h.WriteToken(jsontext.String("packet_number"))
	h.WriteToken(jsontext.Uint(uint64(e.PacketNumber)))
	h.WriteToken(jsontext.String("reordering_packets"))
	h.WriteToken(jsontext.Uint(e.PacketReordering))
	h.WriteToken(jsontext.String("reordering_time"))
	h.WriteToken(jsontext.Float(milliseconds(e.TimeReordering)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type KeyUpdated struct {
	Trigger  KeyUpdateTrigger
	KeyType  KeyType
	KeyPhase KeyPhase // only set for 1-RTT keys
	// we don't log the keys here, so we don't need `old` and `new`.
}

func (e KeyUpdated) Name() string { return "security:key_updated" }

func (e KeyUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("trigger"))
	h.WriteToken(jsontext.String(string(e.Trigger)))
	h.WriteToken(jsontext.String("key_type"))
	h.WriteToken(jsontext.String(string(e.KeyType)))
	if e.KeyType == KeyTypeClient1RTT || e.KeyType == KeyTypeServer1RTT {
		h.WriteToken(jsontext.String("key_phase"))
		h.WriteToken(jsontext.Uint(uint64(e.KeyPhase)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type KeyDiscarded struct {
	KeyType  KeyType
	KeyPhase KeyPhase // only set for 1-RTT keys
}

func (e KeyDiscarded) Name() string { return "security:key_discarded" }

func (e KeyDiscarded) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.KeyType != KeyTypeClient1RTT && e.KeyType != KeyTypeServer1RTT {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String("tls"))
	}
	h.WriteToken(jsontext.String("key_type"))
	h.WriteToken(jsontext.String(string(e.KeyType)))
	if e.KeyType == KeyTypeClient1RTT || e.KeyType == KeyTypeServer1RTT {
		h.WriteToken(jsontext.String("key_phase"))
		h.WriteToken(jsontext.Uint(uint64(e.KeyPhase)))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ParametersSet struct {
	Restore                         bool
	Initiator                       Initiator
	SentBy                          protocol.Perspective
	OriginalDestinationConnectionID protocol.ConnectionID
	InitialSourceConnectionID       protocol.ConnectionID
	RetrySourceConnectionID         *protocol.ConnectionID
	StatelessResetToken             *protocol.StatelessResetToken
	DisableActiveMigration          bool
	MaxIdleTimeout                  time.Duration
	MaxUDPPayloadSize               protocol.ByteCount
	AckDelayExponent                uint8
	MaxAckDelay                     time.Duration
	ActiveConnectionIDLimit         uint64
	InitialMaxData                  protocol.ByteCount
	InitialMaxStreamDataBidiLocal   protocol.ByteCount
	InitialMaxStreamDataBidiRemote  protocol.ByteCount
	InitialMaxStreamDataUni         protocol.ByteCount
	InitialMaxStreamsBidi           int64
	InitialMaxStreamsUni            int64
	PreferredAddress                *PreferredAddress
	MaxDatagramFrameSize            protocol.ByteCount
	EnableResetStreamAt             bool
}

func (e ParametersSet) Name() string {
	if e.Restore {
		return "transport:parameters_restored"
	}
	return "transport:parameters_set"
}

func (e ParametersSet) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if !e.Restore {
		h.WriteToken(jsontext.String("initiator"))
		h.WriteToken(jsontext.String(string(e.Initiator)))
		if e.SentBy == protocol.PerspectiveServer {
			h.WriteToken(jsontext.String("original_destination_connection_id"))
			h.WriteToken(jsontext.String(e.OriginalDestinationConnectionID.String()))
			if e.StatelessResetToken != nil {
				h.WriteToken(jsontext.String("stateless_reset_token"))
				h.WriteToken(jsontext.String(fmt.Sprintf("%x", e.StatelessResetToken[:])))
			}
			if e.RetrySourceConnectionID != nil {
				h.WriteToken(jsontext.String("retry_source_connection_id"))
				h.WriteToken(jsontext.String((*e.RetrySourceConnectionID).String()))
			}
		}
		h.WriteToken(jsontext.String("initial_source_connection_id"))
		h.WriteToken(jsontext.String(e.InitialSourceConnectionID.String()))
	}
	h.WriteToken(jsontext.String("disable_active_migration"))
	h.WriteToken(jsontext.Bool(e.DisableActiveMigration))
	if e.MaxIdleTimeout != 0 {
		h.WriteToken(jsontext.String("max_idle_timeout"))
		h.WriteToken(jsontext.Float(milliseconds(e.MaxIdleTimeout)))
	}
	if e.MaxUDPPayloadSize != 0 {
		h.WriteToken(jsontext.String("max_udp_payload_size"))
		h.WriteToken(jsontext.Int(int64(e.MaxUDPPayloadSize)))
	}
	if e.AckDelayExponent != 0 {
		h.WriteToken(jsontext.String("ack_delay_exponent"))
		h.WriteToken(jsontext.Uint(uint64(e.AckDelayExponent)))
	}
	if e.MaxAckDelay != 0 {
		h.WriteToken(jsontext.String("max_ack_delay"))
		h.WriteToken(jsontext.Float(milliseconds(e.MaxAckDelay)))
	}
	if e.ActiveConnectionIDLimit != 0 {
		h.WriteToken(jsontext.String("active_connection_id_limit"))
		h.WriteToken(jsontext.Uint(e.ActiveConnectionIDLimit))
	}
	if e.InitialMaxData != 0 {
		h.WriteToken(jsontext.String("initial_max_data"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxData)))
	}
	if e.InitialMaxStreamDataBidiLocal != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_local"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiLocal)))
	}
	if e.InitialMaxStreamDataBidiRemote != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_bidi_remote"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataBidiRemote)))
	}
	if e.InitialMaxStreamDataUni != 0 {
		h.WriteToken(jsontext.String("initial_max_stream_data_uni"))
		h.WriteToken(jsontext.Int(int64(e.InitialMaxStreamDataUni)))
	}
	if e.InitialMaxStreamsBidi != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_bidi"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsBidi))
	}
	if e.InitialMaxStreamsUni != 0 {
		h.WriteToken(jsontext.String("initial_max_streams_uni"))
		h.WriteToken(jsontext.Int(e.InitialMaxStreamsUni))
	}
	if e.PreferredAddress != nil {
		h.WriteToken(jsontext.String("preferred_address"))
		if err := e.PreferredAddress.encode(enc); err != nil {
			return err
		}
	}
	if e.MaxDatagramFrameSize != protocol.InvalidByteCount {
		h.WriteToken(jsontext.String("max_datagram_frame_size"))
		h.WriteToken(jsontext.Int(int64(e.MaxDatagramFrameSize)))
	}
	if e.EnableResetStreamAt {
		h.WriteToken(jsontext.String("reset_stream_at"))
		h.WriteToken(jsontext.True)
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type PreferredAddress struct {
	IPv4, IPv6          netip.AddrPort
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

func (a PreferredAddress) encode(enc *jsontext.Encoder) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if a.IPv4.IsValid() {
		h.WriteToken(jsontext.String("ip_v4"))
		h.WriteToken(jsontext.String(a.IPv4.Addr().String()))
		h.WriteToken(jsontext.String("port_v4"))
		h.WriteToken(jsontext.Uint(uint64(a.IPv4.Port())))
	}
	if a.IPv6.IsValid() {
		h.WriteToken(jsontext.String("ip_v6"))
		h.WriteToken(jsontext.String(a.IPv6.Addr().String()))
		h.WriteToken(jsontext.String("port_v6"))
		h.WriteToken(jsontext.Uint(uint64(a.IPv6.Port())))
	}
	h.WriteToken(jsontext.String("connection_id"))
	h.WriteToken(jsontext.String(a.ConnectionID.String()))
	h.WriteToken(jsontext.String("stateless_reset_token"))
	h.WriteToken(jsontext.String(fmt.Sprintf("%x", a.StatelessResetToken)))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type LossTimerUpdated struct {
	Type      LossTimerUpdateType
	TimerType TimerType
	EncLevel  EncryptionLevel
	Time      time.Time
}

func (e LossTimerUpdated) Name() string { return "recovery:loss_timer_updated" }

func (e LossTimerUpdated) Encode(enc *jsontext.Encoder, t time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("event_type"))
	h.WriteToken(jsontext.String(string(e.Type)))
	h.WriteToken(jsontext.String("timer_type"))
	h.WriteToken(jsontext.String(string(e.TimerType)))
	h.WriteToken(jsontext.String("packet_number_space"))
	h.WriteToken(jsontext.String(encLevelToPacketNumberSpace(e.EncLevel)))
	if e.Type == LossTimerUpdateTypeSet {
		h.WriteToken(jsontext.String("delta"))
		h.WriteToken(jsontext.Float(milliseconds(e.Time.Sub(t))))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type eventLossTimerCanceled struct{}

func (e eventLossTimerCanceled) Name() string { return "recovery:loss_timer_updated" }

func (e eventLossTimerCanceled) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("event_type"))
	h.WriteToken(jsontext.String("cancelled"))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type CongestionStateUpdated struct {
	State CongestionState
}

func (e CongestionStateUpdated) Name() string { return "recovery:congestion_state_updated" }

func (e CongestionStateUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.String(e.State.String()))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ECNStateUpdated struct {
	State   ECNState
	Trigger string
}

func (e ECNStateUpdated) Name() string { return "recovery:ecn_state_updated" }

func (e ECNStateUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("new"))
	h.WriteToken(jsontext.String(string(e.State)))
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// ECNCongestion is emitted when ECN-CE marks trigger a congestion response.
// This happens when the path is ECN-capable and the receiver reports increased
// CE counts in ACK frames, indicating that routers marked packets as congested.
type ECNCongestion struct {
	// NewCEMarks is the number of new CE marks detected in this ACK.
	NewCEMarks int64
	// TotalCEMarks is the cumulative CE count acknowledged so far.
	TotalCEMarks int64
}

func (e ECNCongestion) Name() string { return "recovery:ecn_congestion" }

func (e ECNCongestion) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("ce_marks"))
	h.WriteToken(jsontext.Int(e.NewCEMarks))
	h.WriteToken(jsontext.String("total_ce_marks"))
	h.WriteToken(jsontext.Int(e.TotalCEMarks))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

type ALPNInformation struct {
	ChosenALPN string
}

func (e ALPNInformation) Name() string { return "transport:alpn_information" }

// BBRv3StateUpdated logs state and phase transitions for BBRv3 congestion control.
// This event enables time-series visualization of the BBRv3 state machine.
type BBRv3StateUpdated struct {
	State      string // startup, drain, probe_bw, probe_rtt
	Phase      string // up, down, cruise, refill (for probe_bw only)
	RoundCount uint64
}

func (e BBRv3StateUpdated) Name() string { return "recovery:bbr_state_updated" }

func (e BBRv3StateUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("state"))
	h.WriteToken(jsontext.String(e.State))
	if e.Phase != "" {
		h.WriteToken(jsontext.String("phase"))
		h.WriteToken(jsontext.String(e.Phase))
	}
	h.WriteToken(jsontext.String("round_count"))
	h.WriteToken(jsontext.Uint(e.RoundCount))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// BBRv3ModelUpdated logs bandwidth and RTT model updates for BBRv3.
// This event enables tracking of BBRv3's bandwidth/RTT estimation.
type BBRv3ModelUpdated struct {
	Trigger       string // init, state_change, startup_round
	MaxBW         uint64 // Estimated max bandwidth (bytes/s)
	BwLo          uint64 // Lower bandwidth bound (bytes/s)
	BwHi          uint64 // Upper bandwidth bound (bytes/s)
	MinRTT        time.Duration
	InflightHi    uint64 // Upper inflight bound (bytes)
	InflightLo    uint64 // Lower inflight bound (bytes)
	BDP           uint64 // Estimated BDP (bytes)
	FullBWReached bool
}

func (e BBRv3ModelUpdated) Name() string { return "recovery:bbr_model_updated" }

func (e BBRv3ModelUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.String("max_bw"))
	h.WriteToken(jsontext.Uint(e.MaxBW))
	if e.BwLo > 0 {
		h.WriteToken(jsontext.String("bw_lo"))
		h.WriteToken(jsontext.Uint(e.BwLo))
	}
	if e.BwHi > 0 {
		h.WriteToken(jsontext.String("bw_hi"))
		h.WriteToken(jsontext.Uint(e.BwHi))
	}
	h.WriteToken(jsontext.String("min_rtt"))
	h.WriteToken(jsontext.Float(milliseconds(e.MinRTT)))
	if e.InflightHi > 0 {
		h.WriteToken(jsontext.String("inflight_hi"))
		h.WriteToken(jsontext.Uint(e.InflightHi))
	}
	if e.InflightLo > 0 {
		h.WriteToken(jsontext.String("inflight_lo"))
		h.WriteToken(jsontext.Uint(e.InflightLo))
	}
	h.WriteToken(jsontext.String("bdp"))
	h.WriteToken(jsontext.Uint(e.BDP))
	h.WriteToken(jsontext.String("full_bw_reached"))
	h.WriteToken(jsontext.Bool(e.FullBWReached))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// BBRv3ControlUpdated logs pacing rate and cwnd changes for BBRv3.
type BBRv3ControlUpdated struct {
	Trigger    string  // init, state_change, startup_round
	PacingRate uint64  // Current pacing rate (bytes/s)
	Cwnd       uint64  // Congestion window (bytes)
	PacingGain float64 // Current pacing gain factor
	CwndGain   float64 // Current cwnd gain factor
}

func (e BBRv3ControlUpdated) Name() string { return "recovery:bbr_control_updated" }

func (e BBRv3ControlUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.Trigger != "" {
		h.WriteToken(jsontext.String("trigger"))
		h.WriteToken(jsontext.String(e.Trigger))
	}
	h.WriteToken(jsontext.String("pacing_rate"))
	h.WriteToken(jsontext.Uint(e.PacingRate))
	h.WriteToken(jsontext.String("cwnd"))
	h.WriteToken(jsontext.Uint(e.Cwnd))
	h.WriteToken(jsontext.String("pacing_gain"))
	h.WriteToken(jsontext.Float(e.PacingGain))
	h.WriteToken(jsontext.String("cwnd_gain"))
	h.WriteToken(jsontext.Float(e.CwndGain))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// BBRv3RoundUpdated logs round boundary events for BBRv3.
type BBRv3RoundUpdated struct {
	State              string
	Phase              string
	RoundCount         uint64
	RoundStart         bool
	LossInRound        bool
	ECNInRound         bool
	BytesLostInRound   uint64
	DeliveryRate       uint64
	DeliveryRateValid  bool
	AppLimited         bool
	FullBW             uint64
	FullBWCount        uint64
	FullBWNow          bool
	FullBWReached      bool
	PacingRate         uint64
	BytesInFlight      uint64
	Cwnd               uint64
	SendElapsed        time.Duration
	AckElapsed         time.Duration
	RateSampleInterval time.Duration
	// Round-level diagnostic fields for filled-pipe estimator analysis
	MinRTT                   time.Duration // Current min_rtt for interval comparison
	ValidSamplesInRound      uint32        // ACK events with deliveryRate > 0 this round
	SuppressedSamplesInRound uint32        // ACK events where interval < min_rtt
	MaxDeliveryRateInRound   uint64        // Highest valid deliveryRate this round
	TotalAckEventsInRound    uint32        // Total ACK events processed this round
	// F1 instrumentation: loss-cut trajectory tracking
	SuppressedSamplesAtLossRoundStart uint32 // Suppressed samples that coincided with loss_round_start
	BwLatestBeforeCut                 uint64 // bw_latest before adaptLowerBounds (bytes/sec)
	BwLoBeforeCut                     uint64 // bw_lo before adaptLowerBounds (bytes/sec)
	InflightLoBeforeCut               uint64 // inflight_lo before adaptLowerBounds (bytes)
	BwLoAfterCut                      uint64 // bw_lo after adaptLowerBounds (bytes/sec)
	InflightLoAfterCut                uint64 // inflight_lo after adaptLowerBounds (bytes)
}

func (e BBRv3RoundUpdated) Name() string { return "recovery:bbr_round_updated" }

func (e BBRv3RoundUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	if e.State != "" {
		h.WriteToken(jsontext.String("state"))
		h.WriteToken(jsontext.String(e.State))
	}
	if e.Phase != "" {
		h.WriteToken(jsontext.String("phase"))
		h.WriteToken(jsontext.String(e.Phase))
	}
	h.WriteToken(jsontext.String("round_count"))
	h.WriteToken(jsontext.Uint(e.RoundCount))
	h.WriteToken(jsontext.String("round_start"))
	h.WriteToken(jsontext.Bool(e.RoundStart))
	h.WriteToken(jsontext.String("loss_in_round"))
	h.WriteToken(jsontext.Bool(e.LossInRound))
	h.WriteToken(jsontext.String("ecn_in_round"))
	h.WriteToken(jsontext.Bool(e.ECNInRound))
	if e.BytesLostInRound > 0 {
		h.WriteToken(jsontext.String("bytes_lost_in_round"))
		h.WriteToken(jsontext.Uint(e.BytesLostInRound))
	}
	h.WriteToken(jsontext.String("delivery_rate"))
	h.WriteToken(jsontext.Uint(e.DeliveryRate))
	h.WriteToken(jsontext.String("delivery_rate_valid"))
	h.WriteToken(jsontext.Bool(e.DeliveryRateValid))
	h.WriteToken(jsontext.String("app_limited"))
	h.WriteToken(jsontext.Bool(e.AppLimited))
	h.WriteToken(jsontext.String("full_bw"))
	h.WriteToken(jsontext.Uint(e.FullBW))
	h.WriteToken(jsontext.String("full_bw_count"))
	h.WriteToken(jsontext.Uint(e.FullBWCount))
	h.WriteToken(jsontext.String("full_bw_now"))
	h.WriteToken(jsontext.Bool(e.FullBWNow))
	h.WriteToken(jsontext.String("full_bw_reached"))
	h.WriteToken(jsontext.Bool(e.FullBWReached))
	h.WriteToken(jsontext.String("pacing_rate"))
	h.WriteToken(jsontext.Uint(e.PacingRate))
	h.WriteToken(jsontext.String("bytes_in_flight"))
	h.WriteToken(jsontext.Uint(e.BytesInFlight))
	h.WriteToken(jsontext.String("cwnd"))
	h.WriteToken(jsontext.Uint(e.Cwnd))
	h.WriteToken(jsontext.String("send_elapsed"))
	h.WriteToken(jsontext.Float(milliseconds(e.SendElapsed)))
	h.WriteToken(jsontext.String("ack_elapsed"))
	h.WriteToken(jsontext.Float(milliseconds(e.AckElapsed)))
	h.WriteToken(jsontext.String("rate_sample_interval"))
	h.WriteToken(jsontext.Float(milliseconds(e.RateSampleInterval)))
	// Round-level diagnostic fields
	h.WriteToken(jsontext.String("min_rtt"))
	h.WriteToken(jsontext.Float(milliseconds(e.MinRTT)))
	h.WriteToken(jsontext.String("valid_samples_in_round"))
	h.WriteToken(jsontext.Uint(uint64(e.ValidSamplesInRound)))
	h.WriteToken(jsontext.String("suppressed_samples_in_round"))
	h.WriteToken(jsontext.Uint(uint64(e.SuppressedSamplesInRound)))
	h.WriteToken(jsontext.String("max_delivery_rate_in_round"))
	h.WriteToken(jsontext.Uint(e.MaxDeliveryRateInRound))
	h.WriteToken(jsontext.String("total_ack_events_in_round"))
	h.WriteToken(jsontext.Uint(uint64(e.TotalAckEventsInRound)))
	if e.SuppressedSamplesAtLossRoundStart > 0 {
		h.WriteToken(jsontext.String("suppressed_samples_at_loss_round_start"))
		h.WriteToken(jsontext.Uint(uint64(e.SuppressedSamplesAtLossRoundStart)))
	}
	if e.BwLatestBeforeCut > 0 {
		h.WriteToken(jsontext.String("bw_latest_before_cut"))
		h.WriteToken(jsontext.Uint(e.BwLatestBeforeCut))
	}
	if e.BwLoBeforeCut > 0 {
		h.WriteToken(jsontext.String("bw_lo_before_cut"))
		h.WriteToken(jsontext.Uint(e.BwLoBeforeCut))
	}
	if e.InflightLoBeforeCut > 0 {
		h.WriteToken(jsontext.String("inflight_lo_before_cut"))
		h.WriteToken(jsontext.Uint(e.InflightLoBeforeCut))
	}
	if e.BwLoAfterCut > 0 {
		h.WriteToken(jsontext.String("bw_lo_after_cut"))
		h.WriteToken(jsontext.Uint(e.BwLoAfterCut))
	}
	if e.InflightLoAfterCut > 0 {
		h.WriteToken(jsontext.String("inflight_lo_after_cut"))
		h.WriteToken(jsontext.Uint(e.InflightLoAfterCut))
	}
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// BBRv3ECNUpdated logs ECN alpha changes for BBRv3.
type BBRv3ECNUpdated struct {
	ECNAlpha    float64
	ECNEligible bool
}

func (e BBRv3ECNUpdated) Name() string { return "recovery:bbr_ecn_updated" }

func (e BBRv3ECNUpdated) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("ecn_alpha"))
	h.WriteToken(jsontext.Float(e.ECNAlpha))
	h.WriteToken(jsontext.String("ecn_eligible"))
	h.WriteToken(jsontext.Bool(e.ECNEligible))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// BBRv3ProbeRTTCheck is emitted when BBRv3 enters ProbeRTT state.
// This event captures the decision factors that led to ProbeRTT entry,
// enabling diagnosis of spurious ProbeRTT transitions during Startup.
type BBRv3ProbeRTTCheck struct {
	RTTSample               time.Duration // RTT sample from this ACK event
	ProbeRTTMinStampWasZero bool          // Was probeRTTMinStamp uninitialized?
	ProbeExpired            bool          // Did probe_rtt_interval expire?
	IdleRestart             bool          // Was idleRestart flag set?
	RoundCount              uint64        // Current round count
	StateBefore             string        // BBR state before this transition
}

func (e BBRv3ProbeRTTCheck) Name() string { return "recovery:bbr_probe_rtt_check" }

func (e BBRv3ProbeRTTCheck) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("rtt_sample"))
	h.WriteToken(jsontext.Float(milliseconds(e.RTTSample)))
	h.WriteToken(jsontext.String("probe_rtt_min_stamp_was_zero"))
	h.WriteToken(jsontext.Bool(e.ProbeRTTMinStampWasZero))
	h.WriteToken(jsontext.String("probe_expired"))
	h.WriteToken(jsontext.Bool(e.ProbeExpired))
	h.WriteToken(jsontext.String("idle_restart"))
	h.WriteToken(jsontext.Bool(e.IdleRestart))
	h.WriteToken(jsontext.String("round_count"))
	h.WriteToken(jsontext.Uint(e.RoundCount))
	h.WriteToken(jsontext.String("state_before"))
	h.WriteToken(jsontext.String(e.StateBefore))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// BBRv3SpuriousLossRecovery is emitted when BBRv3 recovers from spurious loss.
// Per RFC draft-ietf-ccwg-bbr-05 §5.5.11, BBRv3 restores model bounds when
// the transport detects that a previous loss declaration was spurious.
type BBRv3SpuriousLossRecovery struct {
	SpuriousCount      int    // Number of packets determined to be spuriously lost
	RestoredBwLo       uint64 // Restored bandwidth lower bound (bytes/s)
	RestoredInflightLo uint64 // Restored inflight lower bound (bytes)
	RestoredInflightHi uint64 // Restored inflight upper bound (bytes)
	RestoredCwnd       uint64 // Congestion window after restoration (bytes)
}

func (e BBRv3SpuriousLossRecovery) Name() string { return "recovery:bbr_spurious_loss_recovery" }

func (e BBRv3SpuriousLossRecovery) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("spurious_count"))
	h.WriteToken(jsontext.Int(int64(e.SpuriousCount)))
	h.WriteToken(jsontext.String("restored_bw_lo"))
	h.WriteToken(jsontext.Uint(e.RestoredBwLo))
	h.WriteToken(jsontext.String("restored_inflight_lo"))
	h.WriteToken(jsontext.Uint(e.RestoredInflightLo))
	h.WriteToken(jsontext.String("restored_inflight_hi"))
	h.WriteToken(jsontext.Uint(e.RestoredInflightHi))
	h.WriteToken(jsontext.String("restored_cwnd"))
	h.WriteToken(jsontext.Uint(e.RestoredCwnd))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

func (e ALPNInformation) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("chosen_alpn"))
	h.WriteToken(jsontext.String(e.ChosenALPN))
	h.WriteToken(jsontext.EndObject)
	return h.err
}

// DebugEvent is a generic event that can be used to log arbitrary messages.
type DebugEvent struct {
	EventName string
	Message   string
}

func (e DebugEvent) Name() string {
	if e.EventName == "" {
		return "transport:debug"
	}
	return fmt.Sprintf("transport:%s", e.EventName)
}

func (e DebugEvent) Encode(enc *jsontext.Encoder, _ time.Time) error {
	h := encoderHelper{enc: enc}
	h.WriteToken(jsontext.BeginObject)
	h.WriteToken(jsontext.String("message"))
	h.WriteToken(jsontext.String(e.Message))
	h.WriteToken(jsontext.EndObject)
	return h.err
}
