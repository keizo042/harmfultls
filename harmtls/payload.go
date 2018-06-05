package harmtls

type plaintext struct {
	typ                 contentType
	legacyRecordVersion protocolVersion
	length              uint16
	fragment            []byte
}

type chipertext struct {
	typ                  contentType
	leegacyRecordVersion protocolVersion
	length               uint16
	encryptedRecord      []byte
}

func (p *plaintext) appData() []byte {
}
