package harmtls

import (
	"bytes"
	"errors"
	"io"
	"net"
)

var (
	// DefaultClient is a
	DefaultClient = Client{
		BufLen: 1500,
	}
	legacyVersion protocolVersion = 0x0303
)

// Certificate is a certificate
type Certificate = []byte

// PublicKey is a public key.
type PublicKey = []byte

// Client is a
type Client struct {
	BufLen        int
	cert          Certificate
	key           PublicKey
	hasSessionKey bool
}

// Conn is a TLS connection.
type Conn struct {
	remote *net.TCPAddr
	local  *net.TCPAddr
	conn   *net.TCPConn
	PSK    []byte
}

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

func (p *plaintext) appData() []byte {
}

type chipertext struct {
	typ                  contentType
	leegacyRecordVersion protocolVersion
	length               uint16
	encryptedRecord      []byte
}

type protocolVersion uint16

type clientHello struct {
	legacyVersion           protocolVersion
	random                  []byte
	chiperSuite             uint16
	legacyCompressionMethod uint8
	extension               uint16
}

// Send sends bytes to peer.
func Send(addr *net.TCPAddr, cert Certificate, key PublicKey, r io.Reader) (io.Reader, error) {
	var (
		cli Client
	)
	cli.BufLen = DefaultClient.BufLen
	cli.cert = cert
	cli.key = key

	connTCP, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, err
	}
	connTLS, err := cli.fullHandshake(connTCP)
	if err != nil {
		return nil, err
	}
	if err := connTLS.send(r, cli.BufLen); err != nil {
		return nil, err
	}
	return connTLS.recv(cli.BufLen)

}

func (conn *Conn) sendAppdata(r io.Reader, buflen int) error {
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

func (conn *Conn) send(b []byte) error {
	_, err := conn.conn.Write(b)
	return err
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

func (c *Client) fullHandshake(conn *net.TCPConn) (*Conn, error) {
	if err := c.sendClientHello(); err != nil {
		return nil, err
	}
	if err := c.recvServerHello(); err != nil {
		return nil, err
	}
	if err := c.sendFinished(); err != nil {
		return nil, err
	}
	if err := c.recvFinished(); err != nil {
		return nil, err
	}
	return &Conn{
		conn: conn,
	}, nil
}

func (c *Client) sendClientHello() error {
	w := &buffer{
		Buffer: new(bytes.Buffer),
	}
	return nil
}

func (c *Client) sendFinished() error {
	return nil
}

func (c *Client) recvServerHello(conn *Conn) error {
	return nil
}

func (c *Client) recvFinished() error {
	return nil
}

func (conn *Conn) sendRecord(r *record) error {
	return nil
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
