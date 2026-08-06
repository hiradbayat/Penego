# 01 — Overview

Penego is an **assessment-focused network penetration testing toolkit** (local web app). Operators run authorized recon, enumeration, vulnerability matching, and single-credential checks inside **engagements**, then export reports.

**Not included:** RCE, exploit frameworks, password spraying, C2.

## Feature matrix

| Feature | UI | API |
|---------|----|-----|
| Engagements | `/engagements` | `/api/engagements` |
| Assessment pipeline | `/assessment-pipeline` | `POST /api/assessment_pipeline` |
| Port / discovery / OS / vuln | existing routes | existing scan APIs |
| Service enum | `/enumeration` | `POST /api/service_enum` |
| Path / traceroute | `/path-trace` | `POST /api/path_trace` |
| UDP scan | (via API) | `POST /api/udp_scan` |
| Auth check | `/auth-check` | `POST /api/auth_check` |
| Findings | engagement detail | `/api/engagements/:id/findings` |
| Engagement report | Export button | `/api/engagements/:id/export.html` |
| Users | API | `POST /api/users` |

## Layout

```
models/       Engagement, Asset, Finding, User, ScanReport…
services/     jobs, enum, traceroute, cve_match, authcheck, pipeline, engagement
handlers/     scan + engagement + pages/auth
data|services vuln-rules.json (embedded)
templates/    engagements, pipeline, enum, path, auth_check, …
```
