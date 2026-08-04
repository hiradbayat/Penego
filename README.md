# Penego

Penego is a local web toolkit for network reconnaissance: TCP port scanning, host discovery, OS fingerprinting (nmap), non-exploitative vulnerability checks, and network mapping. Results are stored in MySQL.

![Penego](assets/Penego.png)

## Features

- TCP port scan with optional banner grabbing
- ICMP host discovery (Windows/Unix ping)
- OS fingerprinting via `nmap -O`
- Vulnerability scanning from service banners (no exploits)
- Network map from completed scan data
- Async scans with progress polling
- Session auth, rate limiting, HTML/JSON export
- Audit logging

## Quick start

1. Copy env and edit credentials:

```bash
cp .env.example .env
```

2. Create MySQL database `gonet`, then:

```bash
go run .
```

3. Open http://127.0.0.1:8585 and sign in with `ADMIN_PASSWORD` (default `penego`).

See [docs/](docs/) for architecture, API, and roadmap status.

## Docker Compose

```bash
docker compose up --build
```

App: http://127.0.0.1:8585 — MySQL is started automatically.

## Docs

Start at [docs/README.md](docs/README.md).
