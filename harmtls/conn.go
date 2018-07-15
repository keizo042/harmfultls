package harmtls

// ContentType is TLS Record ContentType
type ContentType int8

const (
	// LegacyRecordVersion is a const value for backward compability
	LegacyRecordVersion uint16 = 0x0303
)

// ContentTypes are defined at Section 5.1 of draft-ietf-tls-tls13-28.
const (
	ContentTypeInvalid          ContentType = 0
	ContentTypeChangeChiperSpec             = 20
	ContentTypeAlert                        = 21
	ContentTypeHandshake                    = 22
	ContentTypeHandshale                    = 23
)

// TLSPlaintext is a unencrypted payload.
type TLSPlaintext struct {
	LegacyRecordVersion uint16 // hard code value
	Length              uint16
	Fragment            []byte
}

// TLSInnerPlaintext is a TLS 1.3 record format.
type TLSInnerPlaintext struct {
	Content     []byte
	ContentType ContentType
	Zeros       uint8
}

// TLSCiphertext is a encyrypted payload.
type TLSCiphertext struct {
	OpaqueType          ContentType
	LegacyRecordVersion ProtocolVersion
	EncryptedRecrod     []byte
}
