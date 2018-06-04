package harmtls

import (
	"bytes"
)

type buffer struct {
	*bytes.Buffer
}

func (b *buffer) writeUint8(u uint8) error {
	return b.WriteByte(byte(u))
}

func (b *buffer) writeUint16(u uint16) error {
	buff := make([]byte, 2)
	buff[0] = byte(u & 0x00ff)
	buff[1] = byte((u & 0xff00) >> 8)
	_, err := b.Write(buff)
	return err
}
