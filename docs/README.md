# Penego Documentation

**Penego** is a Go web application for network reconnaissance: TCP port scanning, host discovery, OS fingerprinting, vulnerability checks, and network mapping. Results live in MySQL; scans run as async jobs.

| Document | Purpose |
|----------|---------|
| [01-overview.md](./01-overview.md) | Product scope and layout |
| [02-architecture.md](./02-architecture.md) | Packages and request flow |
| [03-data-models.md](./03-data-models.md) | GORM models |
| [04-api-reference.md](./04-api-reference.md) | HTTP API |
| [05-scanning-engine.md](./05-scanning-engine.md) | Engine behavior |
| [06-frontend.md](./06-frontend.md) | Templates / JS |
| [07-setup-and-run.md](./07-setup-and-run.md) | Setup |
| [08-known-issues.md](./08-known-issues.md) | Residual caveats |
| [09-roadmap.md](./09-roadmap.md) | Roadmap status |

Default listen: `127.0.0.1:8585` · Config via `.env` / environment.
