# 10 — End-user guide

This guide is for operators using the Penego web UI. For install steps, see [07-setup-and-run.md](./07-setup-and-run.md). For a short product intro, see the root [README.md](../README.md).

## Before you start

1. Confirm you have **authorization** to scan the target network.
2. Start Penego and open `http://127.0.0.1:8585` (or your `LISTEN_ADDR`).
3. Sign in with the admin password from `.env` (`ADMIN_PASSWORD`).
4. Prefer starting with a **single IP** before scanning a large CIDR.

## Modules at a glance

| Nav item | Best for | Typical input |
|----------|----------|----------------|
| Port Scanning | Finding open services | IP/CIDR + ports `22,80,443` |
| Host Discovery | “Who is up?” on a LAN | CIDR e.g. `192.168.1.0/24` |
| OS Fingerprinting | OS guess on live hosts | IP/CIDR (needs `nmap`) |
| Vulnerability Scanning | Banner/version advisories | Target+ports **or** prior scan ID |
| Network Mapping | Picture of recent scan data | Uses saved completed scans |

## Run a port scan

1. Open **Port Scanning**.
2. Enter **Target** (`10.0.0.5` or `10.0.0.0/24`).
3. Set **Ports** (`22,80,443` or ranges like `1-1024`).
4. Optionally enable **Banner grab** and tune concurrency/timeout.
5. Click **Start Scan**.
6. Wait until progress shows **100%** and status is **done**.

Alive hosts list open ports, services, and banners. Use the filter box to narrow by IP, port, or service name.

## Host discovery

Same flow without a ports field. Penego pings each address (Windows and Linux ping flags are handled automatically). Alive hosts appear under “Alive”; others under “Dead”.

## OS fingerprinting

1. Ensure `nmap` is installed and on your `PATH`.
2. On many systems, meaningful OS detection needs elevated privileges.
3. Start a fingerprint job; alive hosts show an **OS** string when nmap returns `OS details:`.

If nmap is missing, hosts may still be marked alive/dead, but OS will be `Unknown` or an error message.

## Vulnerability scanning

Two modes:

1. **Fresh scan** — provide target + ports; Penego port-scans with banners and matches a small local rule pack (OpenSSH, Apache, nginx, MySQL patterns).
2. **Re-analyze** — enter a prior **scan ID** to run rules on banners already stored (useful after a port scan).

Findings show severity, title, optional CVE id, and evidence (banner text). This module does **not** exploit anything.

## Network mapping

1. Run discovery and/or port scans first so data exists.
2. Open **Network Mapping** → **Refresh Map**.
3. Nodes = hosts; edges = same `/24` subnet and/or shared open ports.
4. The list under the canvas shows IPs, OS, and ports.

## History, search, and filters

Every scan page has a **Previous …** panel that loads automatically.

| Control | Behavior |
|---------|----------|
| **Search** | Matches scan id, target, ports text, notes (live, debounced) |
| **Status** | All / done / running / pending / failed / cancelled |
| **Per page** | 5–50 rows |
| **Prev / Next** | Pagination |
| **View** | Opens full detail in the Results card |
| **Export Report** | Downloads printable HTML |
| **JSON** | Downloads machine-readable export |

Inside a detail view you can also filter hosts and hide/show dead hosts.

## Exporting reports

| Action | Format | Use when |
|--------|--------|----------|
| **Export Report** | HTML | Sharing with a team, printing, attaching to tickets |
| **JSON** | JSON | Scripting, SIEM ingest, custom tooling |

Exports are available from:

- The sticky toolbar on a scan detail view
- Each row in the history list

## Cancel or delete

- **Cancel** — appears while status is `pending` or `running` (also available via API).
- **Delete** — removes the scan and related host/port/finding rows from the active dataset (soft-delete semantics may leave DB tombstones).

## Tips for better results

- Keep `MAX_HOSTS` / `MAX_PORTS` in mind; huge CIDRs are rejected past the cap.
- Lower concurrency on fragile networks; raise it on lab VMs.
- Banner grab adds a short read wait per open port.
- If discovery shows everything “dead”, check firewall ICMP rules and that `ping` works from the Penego host.
- Change `ADMIN_PASSWORD` and `SESSION_SECRET` before exposing the app beyond your machine.

## Getting help

- Setup problems → [07-setup-and-run.md](./07-setup-and-run.md)
- Unexpected limits → [08-known-issues.md](./08-known-issues.md)
- Automating with curl/scripts → [04-api-reference.md](./04-api-reference.md)
