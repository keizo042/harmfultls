package harmtls

import (
	"bytes"
	"testing"
)

// TODO(keizo042): Add test Plaintext/Ciphertext as table driven test

func TestTLSPlaintextByte(t *testing.T) {
	recordBefore := TLSPlaintext{
		ContentType:         LegacyContentType,
		LegacyRecordVersion: LegacyRecordVersion,
		Length:              255,
		Fragment:            make([]byte, 255),
	}
	buffer := new(bytes.Buffer)
	if err := recordBefore.writeBuffer(buffer); err != nil {
		t.Fatal(err)
	}
	recordAfter := new(TLSPlaintext)
	if err := recordAfter.readBuffer(buffer); err != nil {
		t.Fatal(err)
	}
	if recordBefore.ContentType != recordAfter.ContentType {
		t.Fatalf("expected %d, actual %d", recordBefore.ContentType, recordAfter.ContentType)
	}
	if recordBefore.LegacyRecordVersion != recordAfter.LegacyRecordVersion {
		t.Fatalf("expected %d, actual %d", recordBefore.LegacyRecordVersion, recordAfter.LegacyRecordVersion)
	}
	if recordBefore.Length != recordAfter.Length {
		t.Fatalf("expected %d, actual %d", recordBefore.Length, recordAfter.Length)
	}

}
