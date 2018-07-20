package harmtls

import (
	"bytes"
	"encoding/binary"
)

// ContentType is TLS Record ContentType
type ContentType int8

const (
	// LegacyRecordVersion is a const value for backward compability
	LegacyRecordVersion uint16 = 0x0303

	// LegacyContentType is a const value for backward compability.
	LegacyContentType = 23 // application_data
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
	ContentType         ContentType
	LegacyRecordVersion uint16 // always 23
	Length              uint16
	Fragment            []byte
}

// TLSInnerPlaintext is a TLS 1.3 record format.
type TLSInnerPlaintext struct {
	Content     []byte
	ContentType ContentType
	Zeros       uint64 // length of padding
}

// TLSCiphertext is a encyrypted payload.
type TLSCiphertext struct {
	OpaqueType          ContentType
	LegacyRecordVersion ProtocolVersion
	Length              uint16
	EncryptedRecrod     []byte
}

func (ptext TLSPlaintext) writeBuffer(b *bytes.Buffer) error {
	if err := binary.Write(b, binary.BigEndian, ptext.ContentType); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, ptext.LegacyRecordVersion); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, ptext.Length); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, ptext.Fragment); err != nil {
		return err
	}
	return nil
}

func (inptext TLSInnerPlaintext) writeBuffer(b *bytes.Buffer) error {
	if err := binary.Write(b, binary.BigEndian, inptext.ContentType); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, inptext.Content); err != nil {
		return err
	}
	zeros := make([]byte, inptext.Zeros)
	if err := binary.Write(b, binary.BigEndian, zeros); err != nil {
		return err
	}
	return nil
}

func (ctext TLSCiphertext) writeBuffer(b *bytes.Buffer) error {
	if err := binary.Write(b, binary.BigEndian, ctext.OpaqueType); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, ctext.LegacyRecordVersion); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, ctext.LegacyRecordVersion); err != nil {
		return err
	}
	if err := binary.Write(b, binary.BigEndian, ctext.EncryptedRecrod); err != nil {
		return err
	}
	return nil
}
