# 01 — Overview

## Purpose

Penego is a **local web toolkit for authorized network reconnaissance**. Lab operators and security practitioners use a browser to:

1. Discover live hosts
2. Scan TCP ports and read banners
3. Fingerprint operating systems (via nmap)
4. Flag common version/banner issues (non-exploitative)
5. Visualize hosts on a simple network map
6. Search history and export HTML/JSON reports

It is **not** a cloud SaaS, multi-tenant platform, or exploitation framework.

## Feature matrix

| Feature | UI route | API | Engine |
|---------|----------|-----|--------|
| Port scan | `/` | `POST /api/scan` | Concurrent TCP dial + optional banner |
| Host discovery | `/host-discovery` | `POST /api/host_discovery` | OS-aware `ping` |
| OS fingerprint | `/os-fingerprinting` | `POST /api/os_fingerprint` | `ping` + `nmap -O` |
| Vuln scan | `/vulnerability-scanning` | `POST /api/vuln_scan` | Banner rule pack |
| Network map | `/network-mapping` | `GET /api/network_map` | Graph from stored scans |
| History | (all scan pages) | `GET /api/scans` | Search `q`, status, pagination |
| Export | detail + history rows | `.../export`, `.../export.html` | JSON + HTML template |
| Auth | `/login` | session cookie | `ADMIN_PASSWORD` |
| Cancel / delete | UI buttons | `POST .../cancel`, `DELETE` | JobManager + GORM |

## Stack

| Layer | Technology |
|-------|------------|
| Language | Go 1.23+ |
| HTTP | Gin |
| DB | MySQL + GORM AutoMigrate |
| UI | Embedded HTML templates, Bootstrap, `assets/app.js` |
| Jobs | In-process `services.JobManager` (async) |
| Config | `.env` / environment variables |
| Packaging | Single binary (`//go:embed`) or Docker Compose |

## Repository layout

```
penego/
├── main.go                 # Composition root
├── config/                 # Load .env + env vars
├── bootstrap/              # DB connect, migrate, dependency checks
├── routes/                 # Route table
├── middlewares/            # Session auth, rate limit
├── handlers/               # HTTP → jobs / pages
├── services/               # Scan engines, jobs, vuln, map, report
├── models/                 # GORM entities + JSON helpers
├── templates/              # Pages, nav, history partial
├── assets/                 # CSS/JS/images (embedded)
├── docs/                   # This documentation
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md               # End-user oriented intro
```

## Design principles

- **Authorized use only** — tool assumes a lab or engagement scope.
- **Detection over exploitation** — vuln module never ships payloads.
- **Async by default** — long CIDR scans do not block the HTTP worker.
- **Local-first** — bind `127.0.0.1` unless you intentionally widen `LISTEN_ADDR`.
- **Fill existing packages** — prefer `bootstrap` / `routes` / `services` over new top-level trees.
