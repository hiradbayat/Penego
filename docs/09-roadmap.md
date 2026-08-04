# 09 — Roadmap Status

Growth plan phases and what shipped.

| Phase | Status | Delivered |
|-------|--------|-----------|
| **0 Stabilize** | Done | Env config, Windows/Unix ping, target validation, nav, gitignore, honest README |
| **1 Structure** | Done | `bootstrap`, `routes`, `services`, `ScanType`, `HostResultID`, thin handlers |
| **2 Productize** | Done | Shared UI, async jobs, pagination, delete, JSON/HTML export |
| **3 Modules** | Done | Auth, vuln scan, network map, HTML reports |
| **4 Harden** | Done | Rate limit, audit log, unit tests, Docker Compose, dependency checks |
| **UX polish** | Done | History search/filter, host filters, export buttons on list + detail |

## Optional follow-ups

- Browser “Print to PDF” styling extras / dedicated PDF library
- Traceroute enrichment on the network map
- Larger CVE/rule packs or optional NVD sync
- Integration tests with testcontainers MySQL
- Soft-delete purge / retention policies
- Multi-user accounts beyond a single admin password

## Contribution checklist

1. Read [01-overview.md](./01-overview.md) and the topic doc for your change.
2. Check [08-known-issues.md](./08-known-issues.md).
3. Prefer extending `handlers` / `services` / existing packages.
4. Keep modules non-exploitative unless explicitly scoped otherwise.
5. Update [04-api-reference.md](./04-api-reference.md), models, and frontend docs when contracts change.
6. Keep the root [README.md](../README.md) and [10-user-guide.md](./10-user-guide.md) accurate for operators.
