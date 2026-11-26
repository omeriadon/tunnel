# tunnel

Laptop runs a local SOCKS5 proxy -> one TLS connection on port 443 to your server -> server fetches from the internet.
The local network only sees HTTPS traffic to your server's IP. Hostnames get resolved on the server, so DNS lookups don't leak either.

## Server (your VPS)
    scp tunnel-linux-amd64 vps:/usr/local/bin/tunnel     # or tunnel-linux-arm64
    TOKEN=$(openssl rand -hex 24); echo $TOKEN
    sudo TUNNEL_TOKEN=$TOKEN tunnel server -listen :443
    # prints "cert fingerprint (use as client -pin): ..."
    # if you have a domain + real cert: add -cert fullchain.pem -key privkey.pem, then the client doesn't need -pin

## Client (laptop)
    TUNNEL_TOKEN=$TOKEN ./tunnel client -server VPS_IP:443 -pin FINGERPRINT
    curl --socks5-hostname 127.0.0.1:1080 https://example.com

Whole Mac: System Settings -> Network -> Wi-Fi -> Details -> Proxies -> SOCKS proxy 127.0.0.1:1080.
Firefox: Settings -> Network -> Manual proxy, SOCKS v5, tick "Proxy DNS when using SOCKS v5".

## Status
- TCP via SOCKS5 CONNECT: done
- UDP (SOCKS5 UDP ASSOCIATE -> kindUDP streams): next
