# tunnel

Your laptop runs a local SOCKS5 proxy. It sends everything over one TLS connection on port 443 to your server, and the server fetches from the internet.
The local network only sees what looks like HTTPS traffic to your server's IP. Hostnames are resolved on the server, so DNS lookups don't leak either.
If someone connects without the token, they just get a plain "It works!" page.

Supports TCP (SOCKS5 CONNECT) and UDP (SOCKS5 UDP ASSOCIATE). UDP packets are carried inside the same TLS connection.

## Server (Docker)
    git clone https://github.com/omeriadon/tunnel && cd tunnel
    cp .env.example .env
    sed -i "s/^TUNNEL_TOKEN=.*/TUNNEL_TOKEN=$(openssl rand -hex 24)/" .env
    docker compose up -d --build
    docker compose logs tunnel | grep fingerprint     # copy this for the client's -pin
    grep TUNNEL_TOKEN .env                             # copy this for the client's token

The certificate is self-signed and stored in the `tunnel-data` volume, so the fingerprint stays the same across restarts and rebuilds.
If something else is already using port 443 on the host (e.g. sshd), either set `PORT=` in `.env` or move that service first.

## Server (no Docker)
    go build -o tunnel . && sudo TUNNEL_TOKEN=... ./tunnel server -listen :443

## Client (laptop)
    go build -o tunnel .
    TUNNEL_TOKEN=... ./tunnel client -server SERVER_IP:443 -pin FINGERPRINT
    curl --socks5-hostname 127.0.0.1:1080 https://example.com

Whole Mac: System Settings → Network → Wi-Fi → Details → Proxies → SOCKS proxy `127.0.0.1:1080`.
Firefox: Settings → Network → Manual proxy, SOCKS v5, and tick "Proxy DNS when using SOCKS v5".

## Protocol
- An HTTP/1.1 `Upgrade` request to `/api/v1/stream` over TLS, authenticated with a hash of the token, then [yamux](https://github.com/hashicorp/yamux) carries many streams over that one connection.
- Each stream starts with `[ver][kind][len][host:port]`, and the server answers with one status byte.
- `kind=1` TCP: after that, raw bytes in both directions.
- `kind=2` UDP: frames of `[len:2][ATYP addr port][payload]` in both directions, one stream per SOCKS UDP association.
