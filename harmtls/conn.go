package harmtls

import (
	"net"
	"sync/atomic"
)

// Conn is a single TLS Connection
// Conn maintain
// - secrets
// - certificate
// - cipher suite
// - iv
// - tokens
type Conn interface {
	net.Conn
}

// conn is a entity of TLS connection.
type conn struct {
	sock        *net.TCPConn
	secret      []byte
	cert        []byte
	isEncrypted uint32
	chiperSuite [2]byte
	clientIV    []byte
	serverIV    []byte
}

// DialTLS connects TLS server
// DialTLS connect tcp and handshake.
// iv, token  are selected as internally.
func DialTLS(network string, ip net.IP, port int, secret []byte, cert []byte) (*Conn, error) {
	raddr := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
	tcp, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return nil, err
	}
	c := &conn{
		sock:   tcp,
		secret: secret,
		cert:   cert,
	}
	return c, nil
}

func (c *conn) enableEncryption() {
	atomic.StoreUint32(&c.isEncrypted, 1)
}

func (c *conn) disableEncryption() {
	atomic.StoreUint32(&c.isEncrypted, 0)
}
