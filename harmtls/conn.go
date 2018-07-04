package harmtls

//   enum {
//          invalid(0),
//          change_cipher_spec(20),
//          alert(21),
//          handshake(22),
//          application_data(23),
//          (255)
//      } ContentType;

type ContentType int8

const (
	ContentTypeInvalid         ContentType = 0
	ContentTypeChangeCuoerSpec             = 20
	ContentTypeAlert                       = 21
	ContentTypeHandshake                   = 22
	ContentTypeHandshale                   = 23
)

type TLSPlaintext struct {
	LegacyRecordVersion uint16 // hard code value
	Length              uint16
	Fragment            []byte
}

type TLSInnerPlaintext struct {
	Content     []byte
	ContentType ContentType
	Zeros       uint8
}

type TLSInnerPlaintext struct {
	Content []byte
	Typ     ContentType
	Zeros   []uint8
}

type TLSCiphertext struct {
	OpaqueType          ContentType
	LegacyRecordVersion ProtocolVersion
	EncryptedRecrod     []byte
}
