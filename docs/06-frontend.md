# 06 — Frontend

## Templates

| File | Role |
|------|------|
| `nav.html` | Shared navbar (`{{define "nav"}}`) |
| `history.html` | Search / status / page size / list / pagination (`{{define "history"}}`) |
| `index.html` | Port scanner |
| `host_discovery.html` | Host discovery |
| `os_fingerprint.html` | OS fingerprint |
| `vuln_scan.html` | Vulnerability scan |
| `network_mapping.html` | Canvas map |
| `login.html` | Auth |

Each page includes Bootstrap CSS/JS, `app.css`, and `app.js`, then calls `Penego.initHistory('<scan_type>')`.

## Client (`assets/app.js`)

| API | Behavior |
|-----|----------|
| `initHistory(type)` | Wire filters, debounce search, auto-load list |
| `refreshHistory()` | `GET /api/scans?type&q&status&page&limit` |
| `submitScan(...)` | Start job, poll progress, render detail, refresh history |
| `renderScanDetail` | Toolbar (Export Report / JSON / Cancel / Delete), host filter |
| `exportButtons` | Links to `/export.html` and `/export` |

Rendering uses DOM `textContent` (not raw `innerHTML` for banners) to reduce XSS risk from hostile service banners.

## History UX

- Auto-loads on page open
- Debounced search (~350ms)
- Status dropdown and per-page select trigger reload
- Pagination Previous / Next
- Each row: status pill, summary counts, **Export Report**, **JSON**, **View**

## Detail UX

- Sticky toolbar with exports and actions
- Filter hosts by IP / port / service / OS / CVE
- Toggle dead-host list visibility
- Match counter (“Showing X of Y alive hosts”)

## Styles (`assets/app.css`)

Status pills, history cards, sticky result toolbar, empty states, host filter bar.
