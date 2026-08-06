# 03 — Data Models

## Engagement graph

- **Engagement** — name, status (`draft`/`active`/`closed`), `scope_cidrs`, notes
- **Asset** — per-engagement host inventory (IP, hostname, OS, TLS, HTTP title, traceroute, ports)
- **Finding** — severity, status (`open`/`fixed`/`accepted`), CVE, evidence, remediation, category
- **ScanReport** — optional `engagement_id`; hosts/ports as before
- **User** — username, bcrypt hash, role (`operator`/`viewer`)

Scan types include: `port_scan`, `host_discovery`, `os_fingerprint`, `vuln_scan`, `path_trace`, `udp_scan`, `service_enum`, `auth_check`, `assessment_pipeline`.
