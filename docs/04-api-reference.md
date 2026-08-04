# 04 — API Reference

**Base URL:** `http://127.0.0.1:8585` (or your `LISTEN_ADDR`)

**Auth:** After `POST /login`, the browser stores an HTTP-only session cookie. Send that cookie on API calls. If `AUTH_DISABLED=true`, APIs are open.

**Async rule:** `POST` scan endpoints return **`202 Accepted`** with a `scan_id`. Poll `GET /api/scans/:id` until `status` is terminal (`done`, `failed`, `cancelled`).

---

## HTML pages

| Method | Path | Notes |
|--------|------|-------|
| GET | `/login` | Login form |
| POST | `/login` | Form or JSON password |
| GET | `/logout` | Clears cookie |
| GET | `/` | Port scanner |
| GET | `/host-discovery` | Host discovery |
| GET | `/os-fingerprinting` | OS fingerprint |
| GET | `/vulnerability-scanning` | Vuln scan |
| GET | `/network-mapping` | Network map |

---

## Scan APIs

| Method | Path | Body / query |
|--------|------|----------------|
| POST | `/api/scan` | `target`, `ports`, `host_concurrency`, `port_concurrency`, `timeout_ms`, `grab_banner` |
| POST | `/api/host_discovery` | `target`, `concurrency`, `timeout_ms` |
| POST | `/api/os_fingerprint` | same as discovery |
| POST | `/api/vuln_scan` | `target` and/or `source_scan_id`, `ports` |
| POST | `/api/scans/:id/cancel` | Cancel running job |
| GET | `/api/scans` | List (see query params) |
| GET | `/api/scans/:id` | Detail + hosts |
| DELETE | `/api/scans/:id` | Delete scan graph |
| GET | `/api/scans/:id/export` | JSON download |
| GET | `/api/scans/:id/export.html` | HTML report download |
| GET | `/api/network_map` | `{nodes, edges}` |

### List query parameters

| Param | Default | Description |
|-------|---------|-------------|
| `type` | — | `port_scan`, `host_discovery`, `os_fingerprint`, `vuln_scan` |
| `status` | — | `pending`, `running`, `done`, `failed`, `cancelled` |
| `q` | — | Search id / target / ports / notes / type |
| `page` | `1` | Page number |
| `limit` | `10` | Page size (max 100) |

### List response

```json
{
  "items": [ /* ScanReportJSON… */ ],
  "page": 1,
  "limit": 10,
  "total": 42,
  "q": "192.168",
  "status": "done",
  "type": "port_scan"
}
```

### Start response (`202`)

```json
{
  "message": "Scan started",
  "scan_id": 1,
  "status": "pending",
  "scan_type": "port_scan"
}
```

### Detail shape (abbreviated)

```json
{
  "id": 1,
  "scan_type": "port_scan",
  "status": "done",
  "progress": 100,
  "target": "192.168.1.0/24",
  "ports_scanned": "22,80,443",
  "true_targets": [
    {
      "ip": "192.168.1.10",
      "alive": true,
      "open_ports": [{ "port": 22, "service": "SSH server", "banner": "SSH-2.0-OpenSSH_8.9" }],
      "vuln_findings": []
    }
  ],
  "false_targets": [{ "ip": "192.168.1.11", "alive": false }]
}
```

---

## Examples (curl)

```bash
# Login (cookie jar)
curl -c cookies.txt -X POST http://127.0.0.1:8585/login \
  -H "Content-Type: application/json" \
  -d '{"password":"penego"}'

# Start port scan
curl -b cookies.txt -X POST http://127.0.0.1:8585/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","ports":"22,80,443","grab_banner":true}'

# Poll
curl -b cookies.txt http://127.0.0.1:8585/api/scans/1

# Search history
curl -b cookies.txt "http://127.0.0.1:8585/api/scans?type=port_scan&q=127.0.0&status=done&page=1&limit=10"

# Export HTML report
curl -b cookies.txt -OJ http://127.0.0.1:8585/api/scans/1/export.html
```
