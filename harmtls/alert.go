package harmtls

type uint8 AlertLevel

type uint8 AlertDescription

// Alert is a alert protocol record.
type Alert struct {
	Level       AlertLevel
	Description AlertDescription
}

// AlertLevel entities
const (
	Warning AlertLevel = 1
	Fatal              = 2
)

// AlertDescription entities
const (
	CloseNotify                  AlertLevel = 0
	UnexpectedMessage                       = 10
	BadRecordMac                            = 20
	RecordOverflow                          = 22
	HandshakeFailure                        = 40
	BadCertificate                          = 42
	UnsupportedCertificate                  = 43
	CertificateRevoked                      = 44
	CertificateExpired                      = 45
	CertificateUnkown                       = 46
	IllegalParameter                        = 47
	UnkownCa                                = 48
	AccessDenied                            = 49
	DecodeError                             = 50
	DecryptError                            = 51
	ProtocolVersion                         = 70
	InsufficientSecurity                    = 71
	InappropriateFallback                   = 86
	UserCanceled                            = 90
	MissingExtension                        = 109
	UnsupportedExtension                    = 110
	BadCertificateStatusResponse            = 113
	UnknownPskIdentity                      = 115
	CertificateRequired                     = 116
	NoApplicationProtocol                   = 120
)
