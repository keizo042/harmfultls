package harmtls

import (
	"bytes"
	"errors"
	"io"
	"net"
)

// Conn is a TLS connection.
type Conn struct {
	remote *net.TCPAddr
	local  *net.TCPAddr
	conn   *net.TCPConn
	PSK    []byte
}

func (conn *Conn) send(b []byte) error {
	_, err := conn.conn.Write(b)
	return err
}

func (conn *Conn) sendRecord(r *record) error {
	return errors.New("ERROR")
}

func (conn *Conn) sendAppData(r io.Reader, buflen int) error {
	var (
		buf   = make([]byte, buflen)
		total int
	)
	for {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}
		ctext := chipertext{
			typ:                  contentTypeApplicationData,
			leegacyRecordVersion: legacyVersion,
			length:               uint16(n),
			encryptedRecord:      buf,
		}
		if err := conn.send(ctext.bytes()); err != nil {
			return err
		}
		total += n
		if n < buflen {
			return nil
		}
	}
}

func (conn *Conn) recv(buflen int) (io.Reader, error) {
	var (
		buff = make([]byte, buflen)
		r    = new(bytes.Buffer)
	)
	for {
		var (
			n   int
			err error
		)

		n, err = conn.conn.Read(buff)
		if err != nil {
			return nil, err
		}
		ctext, err := conn.unmarshal(buff)
		if err != nil {
			return nil, err
		}
		ptext, err := conn.decrypt(ctext)
		if err != nil {
			return nil, err
		}
		if _, err := r.Write(ptext.appData()); err != nil {
			return nil, err
		}
		if n < buflen {
			break
		}
	}
	return r, nil

}

func (conn *Conn) recvRecord() (*record, error) {
	return nil, errors.New("ERROR")
}

func (conn *Conn) recvAppData(buflen int) (io.Reader, error) {
	return nil, errors.New("ERROR")
}

func (conn *Conn) marshal(ctext *chipertext) ([]byte, error) {
	return nil, errors.New("")
}

func (conn *Conn) unmarshal(b []byte) (*chipertext, error) {
	return nil, errors.New("")
}

func (conn *Conn) encrypt(ptext *plaintext) (*chipertext, error) {
	return nil, errors.New("")
}

func (conn *Conn) decrypt(ctext *chipertext) (*plaintext, error) {
	return nil, errors.New("")
}
