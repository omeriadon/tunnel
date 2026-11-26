package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

// Wire format, inside each yamux stream:
//
//	client -> server: [version=1][kind][len][addr bytes ("host:port")]
//	server -> client: [status]   (0 = ok, anything else = dial failed)
//	then raw bytes in both directions.
//
// kind is a byte so UDP can be added later as another kind without
// changing the outer transport.
const (
	protoVersion = 1
	kindTCP      = 1
	kindUDP      = 2 // addr is empty; stream carries frames: [len:2][ATYP addr port][payload]

	statusOK   = 0
	statusFail = 1

	upgradePath  = "/api/v1/stream" // looks boring on purpose
	upgradeProto = "tunnel/1"
)

func tokenHash(token string) string {
	h := sha256.Sum256([]byte("tunnel-auth:" + token))
	return hex.EncodeToString(h[:])
}

func tokenOK(got, token string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(tokenHash(token))) == 1
}

func writeRequest(w io.Writer, kind byte, addr string) error {
	if len(addr) > 255 {
		return errors.New("address too long")
	}
	buf := append([]byte{protoVersion, kind, byte(len(addr))}, addr...)
	_, err := w.Write(buf)
	return err
}

func readRequest(r io.Reader) (kind byte, addr string, err error) {
	var hdr [3]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	if hdr[0] != protoVersion {
		return 0, "", errors.New("bad protocol version")
	}
	a := make([]byte, hdr[2])
	if _, err = io.ReadFull(r, a); err != nil {
		return
	}
	return hdr[1], string(a), nil
}

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.KeepAliveInterval = 20 * time.Second // keep NAT/firewall state alive
	c.MaxStreamWindowSize = 4 << 20        // 4 MiB per stream: better throughput on high-latency links
	c.LogOutput = io.Discard
	return c
}

// pipe copies in both directions, half-closing each side as its source hits
// EOF, and fully closes both once both directions are done.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		switch c := dst.(type) {
		case interface{ CloseWrite() error }: // *net.TCPConn
			c.CloseWrite()
		case *yamux.Stream: // yamux Close sends FIN but keeps reading
			c.Close()
		default:
			a.Close()
			b.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

// writeFrame sends one UDP datagram over a stream as [len:2][body], in a
// single Write so concurrent writers can't interleave.
func writeFrame(w io.Writer, body []byte) error {
	if len(body) > 0xffff {
		return errors.New("frame too large")
	}
	buf := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(buf, uint16(len(body)))
	copy(buf[2:], body)
	_, err := w.Write(buf)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err := io.ReadFull(r, body)
	return body, err
}
