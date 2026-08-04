# Penego Documentation

Technical and user documentation for **Penego**, a local Go web toolkit for authorized network reconnaissance (port scan, host discovery, OS fingerprinting, vulnerability checks, network mapping).

## Who should read what

| Audience | Start here |
|----------|------------|
| **End users / lab operators** | [10-user-guide.md](./10-user-guide.md) and the root [README.md](../README.md) |
| **Install / ops** | [07-setup-and-run.md](./07-setup-and-run.md) |
| **API / automation** | [04-api-reference.md](./04-api-reference.md) |
| **Contributors** | [01-overview.md](./01-overview.md) → [02-architecture.md](./02-architecture.md) |

## Document index

| Doc | Description |
|-----|-------------|
| [01-overview.md](./01-overview.md) | Product scope, features, repo layout, stack |
| [02-architecture.md](./02-architecture.md) | Startup flow, packages, async job model |
| [03-data-models.md](./03-data-models.md) | MySQL / GORM entities and relationships |
| [04-api-reference.md](./04-api-reference.md) | Pages, JSON APIs, query params, examples |
| [05-scanning-engine.md](./05-scanning-engine.md) | Port/ping/nmap/vuln/map engine behavior |
| [06-frontend.md](./06-frontend.md) | Templates, history UI, export, client JS |
| [07-setup-and-run.md](./07-setup-and-run.md) | Prerequisites, `.env`, Docker, troubleshooting |
| [08-known-issues.md](./08-known-issues.md) | Platform limits and residual caveats |
| [09-roadmap.md](./09-roadmap.md) | Delivered phases and optional follow-ups |
| [10-user-guide.md](./10-user-guide.md) | Step-by-step UI guide for operators |

## Quick facts

| Item | Value |
|------|--------|
| Default URL | `http://127.0.0.1:8585` |
| Config | `.env` / environment (see `.env.example`) |
| Auth | Session cookie + `ADMIN_PASSWORD` |
| Scans | Asynchronous jobs with progress polling |
| Export | HTML report + JSON per scan |

## Mental model

```
Browser (templates + app.js)
    │  login cookie · JSON fetch
    ▼
Gin (routes + middlewares)
    │
    ▼
handlers ──► JobManager (async)
                │
                ▼
           services (scan / ping / nmap / vuln / map)
                │
                ▼
           MySQL (ScanReport → Hosts → Ports / Findings)
```
