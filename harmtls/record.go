package harmtls

type protocolVersion uint16

type clientHello struct {
	legacyVersion           protocolVersion
	random                  []byte
	chiperSuite             uint16
	legacyCompressionMethod uint8
	extension               uint16
}

type record struct {
}
