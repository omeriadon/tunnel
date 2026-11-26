package main

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// Minimal SOCKS5 server (RFC 1928): no-auth, CONNECT only for now.
// UDP ASSOCIATE is the planned next step.

func (c *client) handleSocks(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	addr, err := socksHandshake(conn)
	if err != nil {
		conn.Close()
		return
	}
	st, err := c.openStream(kindTCP, addr)
	if err != nil {
		log.Printf("%s: %v", addr, err)
		socksReply(conn, 0x05) // connection refused
		conn.Close()
		return
	}
	if err := socksReply(conn, 0x00); err != nil {
		st.Close()
		conn.Close()
		return
	}
	conn.SetDeadline(time.Time{})
	pipe(conn, st)
}

func socksHandshake(rw io.ReadWriter) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", errors.New("not socks5")
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return "", err
	}
	if _, err := rw.Write([]byte{5, 0}); err != nil { // no auth (we only listen on localhost)
		return "", err
	}

	var req [4]byte
	if _, err := io.ReadFull(rw, req[:]); err != nil {
		return "", err
	}
	if req[1] != 1 { // CONNECT
		socksReply(rw, 0x07) // command not supported
		return "", errors.New("unsupported socks command")
	}
	var host string
	switch req[3] {
	case 1: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(rw, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3: // domain name - resolved on the server, so no DNS leak
		var l [1]byte
		if _, err := io.ReadFull(rw, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(rw, b); err != nil {
			return "", err
		}
		host = string(b)
	case 4: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(rw, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		socksReply(rw, 0x08)
		return "", errors.New("bad address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(rw, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

func socksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}
