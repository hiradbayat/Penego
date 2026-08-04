# 08 — Known Issues and Caveats

Honest limits of the current release. Prefer reading this before production-like lab sharing.

## Platform

| Topic | Detail |
|-------|--------|
| nmap | Required for useful OS fingerprinting; often needs elevated privileges |
| ICMP | Firewalls that drop ping make discovery report hosts as dead |
| Windows | Stock `ping` is supported; install nmap separately for OS mode |
| Docker | Image includes `ping`/`nmap`; host networking quirks can still affect scans |

## Data / schema

- Older databases from the pre-refactor schema may need a **fresh `gonet` database**.
- Soft deletes leave tombstones; there is no automatic purge job yet.
- History search uses SQL `LIKE` (fine for labs; not a full-text search engine).

## Security posture

- Default password `penego` is for demos only — change `ADMIN_PASSWORD` and `SESSION_SECRET`.
- Single shared password (lab mode), not per-user RBAC or SSO.
- Rate limit is **in-memory per process** (not shared across replicas).
- Target validation ensures IP/CIDR syntax; it does **not** block RFC1918 or other “sensitive” ranges (by design for lab tools).
- Bind defaults to localhost; setting `LISTEN_ADDR=0.0.0.0:8585` exposes the UI on the network.

## Product depth

- Vuln rules are a **small local pack**, not a synced NVD feed.
- Network map is a simple circular canvas layout.
- HTML export is the primary report format (print to PDF from the browser if needed).
- No multi-tenant isolation or remote agent fleet.

## Safe-use reminder

Penego is intended for **authorized** testing only. The vulnerability module performs detection from banners/versions and does not ship exploits.
