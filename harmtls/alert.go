package harmtls

import (
	"bytes"
	"encoding/binary"
)

// AlertLevel is alert level
type AlertLevel uint8

// AlertDescription is alert description
type AlertDescription uint8

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
// TODO(keizo042): Add AlertLevel prefix to avoid conflict
const (
	CloseNotify                  AlertDescription = 0
	UnexpectedMessage                             = 10
	BadRecordMac                                  = 20
	RecordOverflow                                = 22
	HandshakeFailure                              = 40
	BadCertificate                                = 42
	UnsupportedCertificate                        = 43
	CertificateRevoked                            = 44
	CertificateExpired                            = 45
	CertificateUnkown                             = 46
	IllegalParameter                              = 47
	UnkownCa                                      = 48
	AccessDenied                                  = 49
	DecodeError                                   = 50
	DecryptError                                  = 51
	Protocolversion                               = 70 // conflict type of "ProtocolVersion"
	InsufficientSecurity                          = 71
	InappropriateFallback                         = 86
	UserCanceled                                  = 90
	MissingExtension                              = 109
	UnsupportedExtension                          = 110
	BadCertificateStatusResponse                  = 113
	UnknownPskIdentity                            = 115
	CertificateRequired                           = 116
	NoApplicationProtocol                         = 120
)

// MarshalBinary encodes Alert Record to bytes.
// MarshalBinary implements encoding.BinaryMarshaler.
func (a Alert) MarshalBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, a.Level); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.BigEndian, a.Description); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary decode bytes to Alert Record.
// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (a *Alert) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)
	alert, err := readBuffer(buf)
	if err != nil {
		return err
	}
	a.Level = alert.Level
	a.Description = alert.Description
	return nil
}

func readBuffer(buf *bytes.Buffer) (*Alert, error) {
	alert := new(Alert)
	if err := binary.Read(buf, binary.BigEndian, &alert.Level); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.BigEndian, &alert.Description); err != nil {
		return nil, err
	}
	return alert, nil
}
