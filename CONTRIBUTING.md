# Contributing to Surfshark Docker VPN Proxy

Thanks for your interest in contributing! This document covers the basics you need to get started.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch: `git checkout -b my-feature`
4. Make your changes
5. Test with `docker compose up -d --build`
6. Commit your changes with a clear message
7. Push to your fork and open a Pull Request

## Development Setup

### Prerequisites

- Docker and Docker Compose
- A Surfshark subscription (for testing VPN connections)

### Local Development

```bash
# Clone your fork
git clone https://github.com/<your-username>/surfshark-docker-vpn-proxy.git
cd surfshark-docker-vpn-proxy

# Create credentials (not committed to git)
echo -e "your-surfshark-username\nyour-surfshark-password" > auth.txt

# Place .ovpn files in Open-vpn/ and .conf files in Wireguard/

# Build and run
docker compose up -d --build

# View logs
docker compose logs -f

# Shell into the container
docker exec -it surfshark-vpn-proxy bash
```

There is no hot reload inside the container. After changing backend (`dashboard/app.py`) or frontend (`dashboard/templates/dashboard.html`) code, rebuild:

```bash
docker compose up -d --build
```

## Project Structure

```
Dockerfile              - Alpine 3.20 container image
docker-compose.yml      - Service definition, ports, volumes
entrypoint.sh           - Container boot script
dashboard/
  app.py                - Flask backend (all VPN logic, REST API)
  templates/
    dashboard.html      - Single-page frontend (vanilla HTML/CSS/JS)
Open-vpn/               - OpenVPN config files (.ovpn) -- gitignored
Wireguard/              - WireGuard config files (.conf) -- gitignored
data/                   - Persistent user data (favorites, profiles) -- gitignored
```

## Guidelines

### Code Style

- **Backend**: Python 3, standard library where possible. No additional pip dependencies beyond Flask.
- **Frontend**: Vanilla HTML/CSS/JS. No build tools, frameworks, or transpilers.
- Keep it simple. This is a single-container utility, not a microservices platform.

### What to Contribute

- Bug fixes
- New VPN provider support
- UI/UX improvements
- Documentation improvements
- Test coverage
- Performance improvements

### What to Avoid

- Adding heavy dependencies or frameworks
- Features that require authentication (this is a local-only tool)
- Changes that break the single-container architecture

### Security

- Never commit credentials, keys, or certificates
- VPN config files belong in gitignored directories
- Validate and sanitize all user input (server filenames are regex-checked)
- If you find a security vulnerability, please open an issue or contact maintainers directly

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add support for NordVPN configs
fix: handle WireGuard DNS leak on container restart
docs: update README with HTTP proxy setup
```

## Reporting Bugs

Open an issue with:

1. What you expected to happen
2. What actually happened
3. Steps to reproduce
4. Docker and OS version
5. Relevant logs (`docker compose logs`)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
