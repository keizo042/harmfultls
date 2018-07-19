package harmtls

import (
	"bytes"
	"testing"
)

// TODO(keizo042): Add test Plaintext/Ciphertext as table driven test

func TestTLSPlaintextByte(t *testing.T) {
	record := TLSPlaintext{
		ContentType:         LegacyContentType,
		LegacyRecordVersion: LegacyRecordVersion,
		Length:              255,
		Fragment:            make([]byte, 255),
	}
	buffer := new(bytes.Buffer)
	if err := record.writeBuffer(buffer); err != nil {
		t.Fatal(err)
	}

	if buffer.Len() != 260 {
		t.Fatalf("buffer length: expected %d, actual %d", 260, buffer.Len())
	}
	expectedHeader := []byte{0x17, 0x03, 0x03, 0x00, 0xff}
	actualHeader := buffer.Bytes()[:len(expectedHeader)]
	for i := range expectedHeader {
		if expectedHeader[i] != actualHeader[i] {
			t.Fatalf("buffer element %d: expected 0x%x, actual 0x%x", i+1, expectedHeader[i], actualHeader[i])
		}
	}
}
