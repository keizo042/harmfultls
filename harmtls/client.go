package harmtls

import (
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
type Certificate []byte

// PublicKey is a public key.
type PublicKey []byte

// Client is a
type Client struct {
	BufLen        int
	cert          Certificate
	key           PublicKey
	hasSessionKey bool
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
	if err := connTLS.sendAppData(r, cli.BufLen); err != nil {
		return nil, err
	}
	return connTLS.recvAppData(cli.BufLen)

}

func (c *Client) fullHandshake(connTCP *net.TCPConn) (*Conn, error) {
	var (
		conn = &Conn{
			conn: connTCP,
		}
	)
	if err := c.sendClientHello(conn); err != nil {
		return nil, err
	}
	if err := c.recvServerHello(conn); err != nil {
		return nil, err
	}
	if err := c.sendFinished(); err != nil {
		return nil, err
	}
	if err := c.recvFinished(); err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) sendClientHello(conn *Conn) error {
	return nil
}

func (c *Client) sendFinished() error {
	return errors.New("ERROR")
}

func (c *Client) recvServerHello(conn *Conn) error {
	return errors.New("ERROR")
}

func (c *Client) recvFinished() error {
	return errors.New("ERROR")
}
