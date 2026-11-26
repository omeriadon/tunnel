// tunnel: a small experimental proxy.
//
//	client (your laptop)                         server (your VPS)
//	browser -> SOCKS5 127.0.0.1:1080 ==TLS 443==> /dial -> internet
//
// The local network only sees a single long-lived TLS connection to your
// server. Hostnames are resolved on the server, so DNS lookups don't leak
// either (use socks5h / "proxy DNS" in your apps).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		listen := fs.String("listen", ":443", "address to listen on")
		token := fs.String("token", os.Getenv("TUNNEL_TOKEN"), "shared secret (or $TUNNEL_TOKEN)")
		cert := fs.String("cert", "", "TLS certificate file (omit to use a self-signed cert)")
		key := fs.String("key", "", "TLS key file")
		selfSigned := fs.String("selfsigned", "tunnel-selfsigned", "path prefix for the generated self-signed cert/key")
		fs.Parse(os.Args[2:])
		requireToken(*token)
		log.Fatal(runServer(*listen, *token, *cert, *key, *selfSigned))

	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		server := fs.String("server", "", "server host:port, e.g. my.vps.example:443")
		sni := fs.String("sni", "", "TLS server name (defaults to the server host)")
		token := fs.String("token", os.Getenv("TUNNEL_TOKEN"), "shared secret (or $TUNNEL_TOKEN)")
		pin := fs.String("pin", "", "SHA-256 fingerprint of the server cert (needed for self-signed certs)")
		socks := fs.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
		fs.Parse(os.Args[2:])
		requireToken(*token)
		if *server == "" {
			log.Fatal("-server is required")
		}
		log.Fatal(runClient(*server, *sni, *token, *pin, *socks))

	default:
		usage()
	}
}

func requireToken(t string) {
	if len(t) < 16 {
		log.Fatal("a -token of at least 16 characters is required (try: openssl rand -hex 24)")
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  tunnel server -token SECRET [-listen :443] [-cert c.pem -key k.pem]
  tunnel client -server host:443 -token SECRET [-pin FINGERPRINT] [-socks 127.0.0.1:1080]`)
	os.Exit(2)
}
