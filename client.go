package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
)

type client struct {
	server, sni, token, pin string

	mu   sync.Mutex
	sess *yamux.Session
}

func runClient(server, sni, token, pin, socksAddr string) error {
	if sni == "" {
		host, _, err := net.SplitHostPort(server)
		if err != nil {
			return fmt.Errorf("-server must be host:port: %w", err)
		}
		sni = host
	}
	c := &client{server: server, sni: sni, token: token, pin: strings.ToLower(strings.ReplaceAll(pin, ":", ""))}
	if _, err := c.session(); err != nil {
		return fmt.Errorf("initial connect: %w", err)
	}
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 proxy ready on %s", socksAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go c.handleSocks(conn)
	}
}

// session returns the live tunnel, reconnecting if it has dropped.
func (c *client) session() (*yamux.Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil && !c.sess.IsClosed() {
		return c.sess, nil
	}
	s, err := c.connect()
	if err != nil {
		return nil, err
	}
	c.sess = s
	log.Printf("tunnel up to %s", c.server)
	return s, nil
}

func (c *client) connect() (*yamux.Session, error) {
	cfg := &tls.Config{ServerName: c.sni, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	if c.pin != "" {
		// Self-signed server: skip CA checks but require the exact cert we expect.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			fp := sha256.Sum256(raw[0])
			if hex.EncodeToString(fp[:]) != c.pin {
				return errors.New("server certificate does not match -pin (possible interception)")
			}
			return nil
		}
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", c.server, cfg)
	if err != nil {
		return nil, err
	}
	req := "GET " + upgradePath + " HTTP/1.1\r\n" +
		"Host: " + c.sni + "\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: " + upgradeProto + "\r\n" +
		"X-Auth: " + tokenHash(c.token) + "\r\n\r\n"
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("server refused tunnel (HTTP %d) - wrong token?", resp.StatusCode)
	}
	conn.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		conn.Close()
		return nil, errors.New("unexpected data after upgrade")
	}
	return yamux.Client(conn, yamuxConfig())
}

func (c *client) openStream(kind byte, addr string) (net.Conn, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		sess, err := c.session()
		if err != nil {
			return nil, err
		}
		st, err := sess.OpenStream()
		if err != nil {
			lastErr = err
			sess.Close() // force reconnect on next attempt
			continue
		}
		if err := writeRequest(st, kind, addr); err != nil {
			st.Close()
			return nil, err
		}
		var status [1]byte
		st.SetReadDeadline(time.Now().Add(20 * time.Second))
		if _, err := st.Read(status[:]); err != nil {
			st.Close()
			return nil, err
		}
		st.SetReadDeadline(time.Time{})
		if status[0] != statusOK {
			st.Close()
			return nil, fmt.Errorf("server could not reach %s", addr)
		}
		return st, nil
	}
	return nil, lastErr
}
