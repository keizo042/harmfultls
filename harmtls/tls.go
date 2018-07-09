package harmtls

type opaque byte
type ProtocolVersion uint16
type Random [32]opaque
type CipherSuite [2]uint8

type Extension struct {
	Type ExtensionType
	Data []byte
}

type ExtensionType int

const (
	ServerName                          ExtensionType = 0
	MaxFragmentLength                                 = 1
	StatusRequest                                     = 5
	SupportedGroups                                   = 10
	SignatureAlgorithms                               = 13
	UseSrtp                                           = 14
	Heartbeat                                         = 15
	ApplicationLayerProtocolNegotiation               = 16
	SignedCertificateTimestamp                        = 18
	ClientCertificateType                             = 19
	ServerCertificateType                             = 20
	Padding                                           = 21
	// TODO(upamune)
	// pre_shared_key(41)
	// early_data(42)
	// supported_versions(43)
	// cookie(44)
	// psk_key_exchange_modes(45)
	// certificate_authorities(47)
	// oid_filters(48)
	// post_handshake_auth(49)
	// signature_algorithms_cert(50)
	// key_share(51)
)

func (e ExtensionType) String() string {
	switch e {
	case ServerName:
		return "server_name"
	case MaxFragmentLength:
		return "max_fragment_length"
	case StatusRequest:
		return "status_request"
	case SupportedGroups:
		return "supported_groups"
	case SignatureAlgorithms:
		return "signature_algorithms"
	case UseSrtp:
		return "use_srtp"
	case Heartbeat:
		return "heartbeat"
	case ApplicationLayerProtocolNegotiation:
		return "application_layer_protocol_negotiation"
	case SignedCertificateTimestamp:
		return "signed_certificate_timestamp"
	case ClientCertificateType:
		return "client_certificate_type"
	case ServerCertificateType:
		return "server_certificate_type"
	}

	return "unknown"
}

type ClientHello struct {
	LegacyVersion            ProtocolVersion
	Random                   Random
	LegacySession            []opaque // TODO
	CipherSuite              CipherSuite
	LegacyCompressionMethods []opaque // TODO
	Extensions               []ExtensionType
}
