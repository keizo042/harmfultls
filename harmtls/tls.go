package harmtls

type opaque byte
type ProtocolVersion uint16
type Random [32]opaque
type CipherSuite [2]uint8
type Extension int

const (
	ServerName Extension = iota
	MaxFragmentLength
	ClientCertificateURL
	TrustedCAKeys
	TrucatedHMAC
	StatusRequest
)

func (e Extension) String() string {
	switch e {
	case ServerName:
		return "ServerName"
	case MaxFragmentLength:
		return "MaxFragmentLength"
	case ClientCertificateURL:
		return "ClientCertificateURL"
	case TrustedCAKeys:
		return "TrustedCAKeys"
	case TrucatedHMAC:
		return "TrucatedHMAC"
	case StatusRequest:
		return "StatusRequest"
	}

	return "Unknown"
}

type ClientHello struct {
	LegacyVersion            ProtocolVersion
	Random                   Random
	LegacySession            []opaque // TODO
	CipherSuite              CipherSuite
	LegacyCompressionMethods []opaque // TODO
	Extensions               []Extension
}
