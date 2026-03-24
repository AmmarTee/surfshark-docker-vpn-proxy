# Surfshark Docker VPN Proxy

Docker container that runs Surfshark VPN (via OpenVPN) and exposes a SOCKS5 proxy with a web dashboard for managing connections.

## What it does

- Runs OpenVPN inside a Docker container connected to Surfshark
- Exposes a SOCKS5 proxy (default `localhost:1080`) for routing specific app traffic (e.g., Telegram)
- Web dashboard at `localhost:8080` to connect/disconnect, switch servers, and configure proxy settings

## Setup

1. Clone the repo
2. Create `auth.txt` in the project root with your Surfshark service credentials:
   ```
   your-surfshark-username
   your-surfshark-password
   ```
   Get these from: Surfshark Dashboard > VPN > Manual Setup > OpenVPN/IKEv2 Credentials

3. Place your `.ovpn` config files in the `Open-vpn/` folder

4. Start:
   ```
   docker compose up -d --build
   ```

5. Open `http://localhost:8080` to manage the VPN

## Usage

- **Dashboard** (`localhost:8080`): Select server, protocol (UDP/TCP), view logs, configure proxy settings
- **SOCKS5 Proxy** (`localhost:1080`): Point Telegram (or any app) to this proxy
- Stop: `docker compose down`
