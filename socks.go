package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// Minimal SOCKS5 server (RFC 1928): no-auth, CONNECT and UDP ASSOCIATE.

const (
	cmdConnect      = 1
	cmdUDPAssociate = 3
)

func (c *client) handleSocks(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	cmd, addr, err := socksHandshake(conn)
	if err != nil {
		conn.Close()
		return
	}
	switch cmd {
	case cmdConnect:
		c.socksConnect(conn, addr)
	case cmdUDPAssociate:
		c.socksUDP(conn)
	}
}

func (c *client) socksConnect(conn net.Conn, addr string) {
	st, err := c.openStream(kindTCP, addr)
	if err != nil {
		log.Printf("%s: %v", addr, err)
		socksReply(conn, 0x05, nil) // connection refused
		conn.Close()
		return
	}
	if err := socksReply(conn, 0x00, nil); err != nil {
		st.Close()
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	pipe(conn, st)
}

// socksUDP implements UDP ASSOCIATE. The app sends SOCKS-wrapped datagrams to
// a local UDP port; we carry them over a single kindUDP tunnel stream as
// length-prefixed frames, and the server relays them from its own UDP socket.
// The association lives as long as the app's TCP control connection.
func (c *client) socksUDP(ctrl net.Conn) {
	defer ctrl.Close()
	// Bind on the same local IP the app reached us on.
	localIP := ctrl.LocalAddr().(*net.TCPAddr).IP
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP})
	if err != nil {
		socksReply(ctrl, 0x01, nil)
		return
	}
	defer uc.Close()
	st, err := c.openStream(kindUDP, "")
	if err != nil {
		log.Printf("udp associate: %v", err)
		socksReply(ctrl, 0x01, nil)
		return
	}
	defer st.Close()
	if err := socksReply(ctrl, 0x00, uc.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}
	ctrl.SetDeadline(time.Time{})

	var (
		mu      sync.Mutex
		appAddr *net.UDPAddr // where to send replies: the app's UDP socket
	)
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done); uc.Close(); st.Close() }) }

	// control connection closing ends the association
	go func() { io.Copy(io.Discard, ctrl); stop() }()

	// app -> tunnel
	go func() {
		defer stop()
		buf := make([]byte, 65535)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// only accept datagrams from the client's own host
			if !from.IP.Equal(ctrl.RemoteAddr().(*net.TCPAddr).IP) {
				continue
			}
			mu.Lock()
			appAddr = from
			mu.Unlock()
			// SOCKS UDP header: RSV(2) FRAG(1) ATYP...
			if n < 4 || buf[2] != 0 { // fragmentation not supported
				continue
			}
			// buf[3:n] is exactly [addr][payload], which is our frame body
			if err := writeFrame(st, buf[3:n]); err != nil {
				return
			}
		}
	}()

	// tunnel -> app
	go func() {
		defer stop()
		for {
			body, err := readFrame(st)
			if err != nil {
				return
			}
			mu.Lock()
			to := appAddr
			mu.Unlock()
			if to == nil {
				continue
			}
			pkt := append([]byte{0, 0, 0}, body...)
			uc.WriteToUDP(pkt, to)
		}
	}()
	<-done
}

func socksHandshake(rw io.ReadWriter) (cmd byte, addr string, err error) {
	var hdr [2]byte
	if _, err = io.ReadFull(rw, hdr[:]); err != nil {
		return
	}
	if hdr[0] != 5 {
		return 0, "", errors.New("not socks5")
	}
	methods := make([]byte, hdr[1])
	if _, err = io.ReadFull(rw, methods); err != nil {
		return
	}
	if _, err = rw.Write([]byte{5, 0}); err != nil { // no auth (we only listen on localhost)
		return
	}
	var req [3]byte
	if _, err = io.ReadFull(rw, req[:]); err != nil {
		return
	}
	cmd = req[1]
	if cmd != cmdConnect && cmd != cmdUDPAssociate {
		socksReply(rw, 0x07, nil) // command not supported
		return 0, "", errors.New("unsupported socks command")
	}
	addr, err = readSocksAddr(rw)
	if err != nil {
		socksReply(rw, 0x08, nil)
	}
	return
}

// readSocksAddr reads [ATYP][ADDR][PORT] and returns "host:port".
func readSocksAddr(r io.Reader) (string, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", err
	}
	var host string
	switch atyp[0] {
	case 1, 4: // IPv4 / IPv6
		b := make([]byte, map[byte]int{1: 4, 4: 16}[atyp[0]])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3: // domain name: resolved on the server, so no DNS leak
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("bad address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

// appendSocksAddr encodes an IP address + port as [ATYP][ADDR][PORT].
func appendSocksAddr(b []byte, a *net.UDPAddr) []byte {
	if ip4 := a.IP.To4(); ip4 != nil {
		b = append(append(b, 1), ip4...)
	} else {
		b = append(append(b, 4), a.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(a.Port))
}

func socksReply(w io.Writer, code byte, bound *net.UDPAddr) error {
	if bound == nil {
		bound = &net.UDPAddr{IP: net.IPv4zero}
	}
	_, err := w.Write(appendSocksAddr([]byte{5, code, 0}, bound))
	return err
}
