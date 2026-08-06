# 10 — End-user guide (assessment toolkit)

## Typical assessment flow

1. **Login** as `admin` (or your operator account).
2. Open **Engagements** → create one with a name and optional scope (`192.168.1.0/24`).
3. Open the engagement → **Run pipeline** (or copy the engagement ID into module forms).
4. Wait for the pipeline job to finish (progress bar).
5. Review **Assets** and **Findings**; mark findings fixed/accepted as needed.
6. Click **Export Report** for a printable HTML engagement report.

## Modules

| Nav | Purpose |
|-----|---------|
| Engagements | Workspace: assets, findings, scans, export |
| Pipeline | Full assessment playbook |
| Ports / Discovery / OS | Classic recon |
| Enum | HTTP/TLS/DNS/SMB enrichment |
| Path | Traceroute |
| Vulns | Banner/CVE-style matching |
| Auth Check | One username/password against one host |
| Map | Graph from completed scans |

## Auth check rules

- Requires `AUTHCHECK_ENABLED=true` and an **engagement ID**
- Exactly one credential attempt per job
- Passwords are **not** stored in audit logs
- Supported: SSH, FTP, HTTP Basic

## Scope enforcement

When `ENFORCE_SCOPE=true` and the engagement has scope CIDRs, scan targets outside that scope are rejected.

## Roles

- **operator** — run scans, manage engagements/findings/users
- **viewer** — read-only APIs/pages (mutations forbidden)

Seeded on first boot: `admin` with `ADMIN_PASSWORD`.
