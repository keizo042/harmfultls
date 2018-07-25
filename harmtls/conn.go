package harmtls

import (
	"io"
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
	io.ReadWriteCloser
}

// Key is representation of Public Key.
type Key = []byte

// Secret is secret representation.
type Secret []byte

// conn is a entity of TLS connection.
type conn struct {
	sock *net.TCPConn

	// prepared parameters
	clientKey  Key
	clientCert Key
	serverKey  []byte
	serverCert []byte

	// concecused paramters
	chiperSuite [2]byte
	psk         atomic.Value
	clientIV    []byte
	serverIV    []byte

	// should be after Client Hello
	isEncrypted uint32
	// for Hello Retry Request
	chelloHash []byte

	signatureAlgolithms [2]byte

	// computed secrets
	earlySecret                    Secret
	binderKey                      Secret
	earlyExporterMasterSecret      Secret
	handshakeSecret                Secret
	clientHandshakeTrafficSecret   Secret
	serverHandshakeTrafficSecret   Secret
	clientApplicationTrafficSecret Secret
	serverApplicationTrafficSecret Secret
	exporterMasterSecret           Secret
	resumptionMasterSecret         Secret
}

// DialTLS connects TLS server
// DialTLS connect tcp and handshake.
// iv, token  are selected as internally.
func DialTLS(network string, ip net.IP, port int, key []byte, cert []byte) (Conn, error) {
	raddr := &net.TCPAddr{
		IP:   ip,
		Port: port,
	}
	tcp, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return nil, err
	}
	c := conn{
		sock:       tcp,
		clientKey:  key,
		clientCert: cert,
	}
	return &c, nil
}

func (c conn) Write(payload []byte) (int, error) {
	return c.sock.Write(payload)
}

func (c conn) Read(buf []byte) (int, error) {
	return c.sock.Read(buf)
}

func (c conn) Close() error {
	// TODO(keizo042): Sending close_notify Alert.
	return c.sock.Close()
}

func (c *conn) setPSK(psk []byte) {
	c.psk.Store(psk)
}

func (c *conn) getPSK() []byte {
	return c.psk.Load().([]byte)
}

func (c *conn) enableEncryption() {
	atomic.StoreUint32(&c.isEncrypted, 1)
}

func (c *conn) disableEncryption() {
	atomic.StoreUint32(&c.isEncrypted, 0)
}
