package derpquic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/ntnj/derpnet"
	"github.com/quic-go/quic-go"
)

var Debug = false

// Listen connects to a DERP server URL with the provided private key.
// It returns net.Listener and implements a TCP-like stream.
// derpURL should be a valid server name compatible with the Tailscale's DERP protocol.
// key should have a length of 32 bytes
func Listen(derpURL string, key derpnet.Key) (net.Listener, error) {
	pkc, err := derpnet.ListenPacket(derpURL, key)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{
		Conn: pkc,
	}
	cert, err := localhostCertificate()
	if err != nil {
		return nil, err
	}
	l, err := tr.Listen(&tls.Config{
		ServerName:   "localhost",
		Certificates: []tls.Certificate{*cert},
	}, nil)
	if err != nil {
		return nil, err
	}
	ll := &Listener{
		l: l,
		s: make(chan streamOrError),
	}
	go ll.start()
	return ll, nil
}

type Dialer struct {
	tr *quic.Transport
}

// NewDialer connects to a DERP server URL with the provided private key.
// It returns Dialer which can be used to connect a TCP-like stream to derpquic.Listener.
// derpURL should be a valid server name compatible with the Tailscale's DERP protocol.
// key should have a length of 32 bytes
func NewDialer(derpURL string, key derpnet.Key) (*Dialer, error) {
	pkc, err := derpnet.ListenPacket(derpURL, key)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{
		Conn: pkc,
	}
	return &Dialer{tr}, nil
}

func (d *Dialer) Dial(addr derpnet.PublicKey) (net.Conn, error) {
	c, err := d.tr.Dial(context.TODO(), derpnet.Addr(addr), &tls.Config{
		InsecureSkipVerify: true,
	}, nil)
	if err != nil {
		return nil, err
	}
	// TODO: reuse connection for the same target
	s, err := c.OpenStreamSync(context.TODO())
	if err != nil {
		return nil, err
	}
	return &Connection{c: c, s: s}, nil
}

// Listener implements net.Listener.
type Listener struct {
	l *quic.Listener
	s chan streamOrError
}

// Accept implements net.Listener.
func (l *Listener) Accept() (net.Conn, error) {
	se := <-l.s
	if se.err != nil {
		return nil, se.err
	}
	return &Connection{c: se.c, s: se.s}, nil
}

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}

// Close implements net.Listener.
func (l *Listener) Close() error {
	return l.l.Close()
}

type streamOrError struct {
	c   quic.Connection
	s   quic.Stream
	err error
}

func (l *Listener) start() {
	for {
		conn, err := l.l.Accept(context.TODO())
		if Debug {
			if err == nil {
				log.Printf("accepted quic conn: %v", conn.RemoteAddr())
			} else {
				log.Printf("error accepting quic conn: %v", err)
			}
		}
		if err != nil {
			if err == quic.ErrServerClosed {
				l.s <- streamOrError{err: err}
				return
			}
			continue
		}
		go func(conn quic.Connection) {
			for {
				stream, err := conn.AcceptStream(conn.Context())
				if Debug {
					if err == nil {
						log.Printf("accepted quic stream: %v", stream.StreamID())
					} else {
						log.Printf("error accepting quic stream: %v", err)
					}
				}
				if err != nil {
					if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
						return
					}
					l.s <- streamOrError{err: err}
					continue
				}
				l.s <- streamOrError{c: conn, s: stream}
			}
		}(conn)
	}
}

var _ net.Listener = (*Listener)(nil)

// Connection implements net.Conn.
type Connection struct {
	c quic.Connection
	s quic.Stream
}

// Close implements net.Conn.
func (s *Connection) Close() error {
	return s.s.Close()
}

func (*Connection) CloseRead() error {
	return nil
}
func (s *Connection) CloseWrite() error {
	return s.s.Close()
}

// LocalAddr implements net.Conn.
func (s *Connection) LocalAddr() net.Addr {
	return s.c.LocalAddr()
}

// Read implements net.Conn.
func (s *Connection) Read(b []byte) (n int, err error) {
	return s.s.Read(b)
}

// RemoteAddr implements net.Conn.
func (s *Connection) RemoteAddr() net.Addr {
	return s.c.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (s *Connection) SetDeadline(t time.Time) error {
	s.s.SetReadDeadline(t)
	return s.s.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (s *Connection) SetReadDeadline(t time.Time) error {
	return s.s.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (s *Connection) SetWriteDeadline(t time.Time) error {
	return s.s.SetWriteDeadline(t)
}

// Write implements net.Conn.
func (s *Connection) Write(b []byte) (n int, err error) {
	return s.s.Write(b)
}

var _ net.Conn = (*Connection)(nil)

func localhostCertificate() (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		Subject:      pkix.Name{CommonName: "localhost"},
		Issuer:       pkix.Name{CommonName: "localhost"},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	return &certificate, err
}
