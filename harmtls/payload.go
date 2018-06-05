package harmtls

type contentType int8

const (
	contentTypeInvaild         contentType = 0
	contentTypeChangeChperSpec             = 20
	contentTypeAlert                       = 21
	contentTypeHandshake                   = 22
	contentTypeApplicationData             = 23
)

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
	return nil
}

func (c *chipertext) bytes() []byte {
	return nil
}
