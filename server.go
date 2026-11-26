package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/yamux"
)

func runServer(listen, token, certFile, keyFile, selfSignedPrefix string) error {
	if certFile == "" {
		certFile, keyFile = selfSignedPrefix+".crt", selfSignedPrefix+".key"
		if err := ensureSelfSigned(certFile, keyFile); err != nil {
			return err
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	fp := sha256.Sum256(cert.Certificate[0])
	log.Printf("cert fingerprint (use as client -pin): %s", hex.EncodeToString(fp[:]))

	mux := http.NewServeMux()
	mux.HandleFunc(upgradePath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != upgradeProto || !tokenOK(r.Header.Get("X-Auth"), token) {
			decoy(w, r) // unauthenticated probes just see a normal website
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "unsupported", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.SetDeadline(time.Time{}) // clear http.Server timeouts for the tunnel
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + upgradeProto + "\r\n\r\n")
		if err := buf.Flush(); err != nil {
			conn.Close()
			return
		}
		log.Printf("client connected from %s", r.RemoteAddr)
		serveSession(conn)
		log.Printf("client %s disconnected", r.RemoteAddr)
	})
	mux.HandleFunc("/", decoy)

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"}, // no h2: we need Hijack
		},
	}
	log.Printf("listening on %s", listen)
	return srv.ListenAndServeTLS("", "")
}

func decoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!doctype html><title>Welcome</title><h1>It works!</h1>")
}

// serveSession handles one client's multiplexed connection.
func serveSession(conn net.Conn) {
	sess, err := yamux.Server(conn, yamuxConfig())
	if err != nil {
		conn.Close()
		return
	}
	defer sess.Close()
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			return
		}
		go handleStream(st)
	}
}

func handleStream(st net.Conn) {
	st.SetReadDeadline(time.Now().Add(15 * time.Second))
	kind, addr, err := readRequest(st)
	st.SetReadDeadline(time.Time{})
	if err != nil {
		st.Close()
		return
	}
	switch kind {
	case kindTCP:
		target, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			log.Printf("dial %s: %v", addr, err)
			st.Write([]byte{statusFail})
			st.Close()
			return
		}
		if _, err := st.Write([]byte{statusOK}); err != nil {
			target.Close()
			st.Close()
			return
		}
		pipe(st, target)
	case kindUDP:
		if _, err := st.Write([]byte{statusOK}); err != nil {
			st.Close()
			return
		}
		relayUDP(st)
	default:
		st.Write([]byte{statusFail})
		st.Close()
	}
}

func ensureSelfSigned(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	log.Printf("generated self-signed cert %s", certFile)
	return os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
}

// relayUDP serves one UDP association: frames from the stream are sent from a
// fresh UDP socket, and anything that comes back is framed to the client.
func relayUDP(st net.Conn) {
	uc, err := net.ListenUDP("udp", nil)
	if err != nil {
		st.Close()
		return
	}
	const idle = 5 * time.Minute
	stop := func() { uc.Close(); st.Close() }
	defer stop()

	go func() {
		defer stop()
		buf := make([]byte, 65535)
		for {
			uc.SetReadDeadline(time.Now().Add(idle))
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if writeFrame(st, append(appendSocksAddr(nil, from), buf[:n]...)) != nil {
				return
			}
		}
	}()

	cache := map[string]*net.UDPAddr{}
	for {
		st.SetReadDeadline(time.Now().Add(idle))
		body, err := readFrame(st)
		if err != nil {
			return
		}
		r := bytes.NewReader(body)
		addr, err := readSocksAddr(r)
		if err != nil {
			continue
		}
		dst, ok := cache[addr]
		if !ok {
			if dst, err = net.ResolveUDPAddr("udp", addr); err != nil {
				continue
			}
			if len(cache) > 1024 {
				clear(cache)
			}
			cache[addr] = dst
		}
		uc.WriteToUDP(body[len(body)-r.Len():], dst)
	}
}
