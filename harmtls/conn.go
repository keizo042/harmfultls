package harmtls

import (
	"io"
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
	return nil
}

func (conn *Conn) sendAppdata(r io.Reader, buflen int) error {
	p
	var (
		buf   = make([]byte, buflen)
		total uint16
	)
	for {
		n, err := r.Read(buf)
		if err != nil {
			return err
		}
		ctext := chipertext{
			typ:                  contentTypeApplicationData,
			leegacyRecordVersion: legacyVersion,
			length:               n,
			encryptedRecord:      buf,
		}
		if err := conn.send(ctext.bytes()); err != nil {
			return err
		}
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
			n       int
			err     error
			appData []byte
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
		if n < bulen {
			break
		}
	}
	return r, nil

}

func (conn *Conn) recvRecord() (*record, error) {
}

func (conn *Conn) recvAppData() (io.Reader, error) {
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
