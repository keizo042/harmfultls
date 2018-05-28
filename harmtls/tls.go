package harmtls

// HandshakeType indicates what type the Protocol Message is.
type HandshakeType int8

// Handshake Protocol Message Types
// see Section 4. of draft-ietf-tls13-28.
const (
	TypeClientHello         HandshakeType = 1
	TypeServerHello                       = 2
	TypeNewSessionTicket                  = 4
	TypeEndOfEaryData                     = 5
	TypeEncryptedExtensions               = 8
	TypeCertificate                       = 11
	TypeCertificateRequest                = 13
	TypeCertificateVerify                 = 15
	TypeFinished                          = 20
	TypeKeyUpdate                         = 24
	TypeMessageHash                       = 254
)

// Handshake represents a state of TLS Handshake Protocol.
// it is one of them
// - ClientHello
// - ServerHello
// - EndOfEarlyData
// - EncryptedExtensions
// - CertificateRequest
// - CertificateVerify
// - Finished
// - NewSessionTicket
// - KeyUpdate
//
type Handshake interface {
	HandshakeType() HandshakeType
}
