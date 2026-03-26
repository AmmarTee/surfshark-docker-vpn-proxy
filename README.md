# Surfshark Docker VPN Proxy

A Docker container that runs Surfshark VPN (OpenVPN or WireGuard) and exposes SOCKS5 and HTTP proxies, managed through a clean web dashboard.

Route specific app traffic (Telegram, browsers, torrent clients) through the VPN while keeping the rest of your system on your regular connection.

## Features

- **Dual VPN protocols** -- OpenVPN (UDP/TCP) and WireGuard
- **SOCKS5 proxy** (default port 1080) -- for apps like Telegram, Firefox, etc.
- **HTTP/HTTPS proxy** (default port 8888) -- powered by tinyproxy
- **Web dashboard** at port 8080 with:
  - Server browser with search, filter by protocol, and sort by name/country/latency/recent
  - One-click connect, disconnect, and random server selection
  - On-demand server ping with color-coded latency indicators
  - Favorite and recently used server tracking
  - Connection profiles (save server + port presets for quick switching)
  - Live bandwidth monitoring (speed and session totals)
  - GeoIP location display when connected
  - DNS leak test
  - Connection timer and auto-reconnect with failover
  - Boot auto-start (optional, disabled by default) using preferred or last successful server
  - One-click Reconnect Now action (disconnect + reconnect)
  - Live event stream for reconnect and proxy lifecycle actions
  - Browser notifications on connect/disconnect/reconnect
  - Configurable SOCKS5 and HTTP proxy settings

## Architecture

```
Docker Container (Alpine 3.20)
+-- OpenVPN / WireGuard    (VPN tunnel)
+-- microsocks             (SOCKS5 proxy on :1080)
+-- tinyproxy              (HTTP proxy on :8888)
+-- Flask app              (web dashboard on :8080)
```

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- A [Surfshark](https://surfshark.com/) subscription

### 1. Clone the repository

```bash
git clone https://github.com/AmmarTee/surfshark-docker-vpn-proxy.git
cd surfshark-docker-vpn-proxy
```

### 2. Add your Surfshark credentials

Create `auth.txt` in the project root with your **service credentials** (not your account login):

```
your-surfshark-service-username
your-surfshark-service-password
```

Get these from: [Surfshark Dashboard](https://my.surfshark.com/) > VPN > Manual Setup > OpenVPN/IKEv2 Credentials

### 3. Add VPN config files

**OpenVPN**: Download `.ovpn` files from [Surfshark's manual setup page](https://my.surfshark.com/vpn/manual-setup/main/openvpn) and place them in the `Open-vpn/` folder.

**WireGuard** (optional): Download `.conf` files and place them in the `Wireguard/` folder. Create `wireguard.txt` with:

```
your-wireguard-public-key
your-wireguard-private-key
```

### 4. Start the container

```bash
docker compose up -d --build
```

### 5. Open the dashboard

Navigate to [http://localhost:8080](http://localhost:8080) -- select a server and connect.

## Usage

### Web Dashboard

Open `http://localhost:8080` to:

- Browse and search servers by country/city
- Switch between OpenVPN (UDP/TCP) and WireGuard
- Connect with one click or use the Random button
- Star favorites for quick access
- Create connection profiles
- Monitor bandwidth and connection status
- Run DNS leak tests
- View VPN logs

### Proxy Configuration

After connecting to a VPN server, route app traffic through the proxy:

| Proxy | Address | Use Case |
|-------|---------|----------|
| SOCKS5 | `127.0.0.1:1080` | Telegram, Firefox, curl |
| HTTP | `127.0.0.1:8888` | Browsers, apps that only support HTTP proxy |

**Telegram example**: Settings > Advanced > Connection type > Use custom proxy > SOCKS5 > Server: `127.0.0.1`, Port: `1080`

**curl example**:

```bash
# SOCKS5
curl -x socks5://127.0.0.1:1080 https://api.ipify.org

# HTTP
curl -x http://127.0.0.1:8888 https://api.ipify.org
```

### Docker Commands

```bash
docker compose up -d --build     # Build and start
docker compose down              # Stop
docker compose logs -f           # Tail logs
docker exec -it surfshark-vpn-proxy bash  # Shell into container
```

## API Reference

All endpoints are served from the Flask app on port 8080.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/status` | Connection state, VPN mode, IP, proxy info |
| GET | `/api/servers` | List OpenVPN servers |
| GET | `/api/wg/servers` | List WireGuard servers |
| POST | `/api/connect` | Connect OpenVPN (`{"server": "...ovpn"}`) |
| POST | `/api/wg/connect` | Connect WireGuard (`{"server": "...conf"}`) |
| POST | `/api/connect/random` | Connect to a random server |
| POST | `/api/disconnect` | Disconnect VPN and stop proxies |
| POST | `/api/reconnect-now` | Disconnect then reconnect current/last successful target |
| GET | `/api/logs` | Tail VPN log (mode-aware) |
| GET | `/api/events` | Tail backend event stream (reconnect/proxy/control events) |
| GET/POST | `/api/settings` | SOCKS5/HTTP proxy and auto-reconnect config |
| GET/POST | `/api/autostart` | Boot auto-start configuration and last-success metadata |
| GET | `/api/bandwidth` | Live speed and session data totals |
| POST | `/api/ping` | Ping servers for latency (`{"servers": [...]}`) |
| GET/POST/DELETE | `/api/favorites` | Manage favorite servers |
| GET | `/api/recent` | Recently used servers |
| GET/POST/PUT/DELETE | `/api/profiles` | Connection profiles CRUD |
| POST | `/api/profiles/activate` | Activate a saved profile |
| GET | `/api/geoip` | GeoIP lookup of current VPN IP |
| GET | `/api/dnstest` | DNS leak test |

## Configuration

### Environment Variables

Set in `docker-compose.yml`:

| Variable | Default | Description |
|----------|---------|-------------|
| `SOCKS_PORT` | `1080` | SOCKS5 proxy port |
| `SOCKS_BIND` | `0.0.0.0` | SOCKS5 bind address |
| `HTTP_PORT` | `8888` | HTTP proxy port |
| `HTTP_BIND` | `0.0.0.0` | HTTP proxy bind address |

### Ports

| Port | Service |
|------|---------|
| 8080 | Web dashboard |
| 1080 | SOCKS5 proxy |
| 8888 | HTTP/HTTPS proxy |

### Volumes

| Host Path | Container Path | Description |
|-----------|----------------|-------------|
| `./Open-vpn` | `/vpn/config` | OpenVPN config files (read-only) |
| `./Wireguard` | `/vpn/wireguard` | WireGuard config files (read-only) |
| `./auth.txt` | `/vpn/auth.txt` | OpenVPN credentials (read-only) |
| `./wireguard.txt` | `/vpn/wireguard.txt` | WireGuard keys (read-only) |
| `./data` | `/vpn/data` | Persistent data (favorites, profiles, recent, autostart, last-success) |

## Troubleshooting

### TLS handshake timeout

OpenVPN may take 1-2 minutes to negotiate TLS with some servers. The dashboard waits up to 120 seconds. If it still fails, try a different server or switch to TCP protocol.

### WireGuard connection fails

- Verify `wireguard.txt` contains your public key (line 1) and private key (line 2)
- Keys are from Surfshark's WireGuard manual setup page, not your account credentials

### Container won't start

- Ensure Docker Desktop is running
- The container requires `NET_ADMIN` capability and `/dev/net/tun` -- these are set in `docker-compose.yml`

### SOCKS5 proxy not working

- Verify the VPN is connected (check the dashboard status)
- Test directly: `curl -x socks5://127.0.0.1:1080 https://api.ipify.org`
- Check container logs: `docker compose logs -f`

### auth.txt credentials rejected

Use Surfshark **service credentials** from the Manual Setup page, not your account email/password.

## Security

- Credentials (`auth.txt`, `wireguard.txt`) are mounted read-only and never committed to git
- VPN config files (containing certificates) are gitignored
- All server filenames are regex-validated to prevent path traversal
- The dashboard is intended for local/private use only -- there is no authentication

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This project is not affiliated with, endorsed by, or sponsored by Surfshark. It is an independent tool that uses Surfshark's publicly available VPN configuration files. You must have a valid Surfshark subscription to use this software. Use responsibly and in accordance with Surfshark's Terms of Service and applicable laws.
