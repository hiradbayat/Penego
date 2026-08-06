# 04 — API Reference

Base: `http://127.0.0.1:8585` · Auth: session cookie · Scans return `202` + poll.

## Engagements

| Method | Path |
|--------|------|
| GET/POST | `/api/engagements` |
| GET/PATCH | `/api/engagements/:id` |
| POST | `/api/engagements/:id/close` |
| GET | `/api/engagements/:id/assets` |
| GET | `/api/engagements/:id/findings?q=&severity=&status=` |
| PATCH | `/api/engagements/:id/findings/:fid` |
| GET | `/api/engagements/:id/export.html` |

## Scan jobs (operator)

Include optional `engagement_id` on bodies.

| POST path | Notes |
|-----------|--------|
| `/api/scan` | TCP ports |
| `/api/host_discovery` | ping |
| `/api/os_fingerprint` | nmap |
| `/api/vuln_scan` | banners / `source_scan_id` |
| `/api/path_trace` | traceroute |
| `/api/udp_scan` | UDP top ports |
| `/api/service_enum` | HTTP/TLS/DNS/SMB |
| `/api/auth_check` | `auth_service`, `username`, `password`, `auth_port`, `engagement_id` |
| `/api/assessment_pipeline` | full playbook |

Also: cancel/delete/export scans, `GET /api/network_map`, `POST /api/users`, `POST /api/admin/purge`.

List scans: `GET /api/scans?type=&status=&q=&page=&limit=&engagement_id=`
