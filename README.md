# Penego

**Penego** is a local web application for **authorized network reconnaissance**. Point it at IP addresses or CIDR ranges you own or have permission to test, then run port scans, host discovery, OS fingerprinting, light vulnerability checks, and network mapping. Results are saved in MySQL and can be searched, filtered, and exported as HTML or JSON reports.

![Penego](assets/Penego.png)

> **Legal notice:** Only scan networks you are authorized to assess. Unauthorized scanning may be illegal. Penego does **not** include exploitation or attack payloads.

---

## What you can do

| Module | What it does |
|--------|----------------|
| **Port scanning** | Find open TCP ports; optionally grab service banners |
| **Host discovery** | Find which hosts respond to ping on a subnet |
| **OS fingerprinting** | Guess OS via `nmap -O` (requires nmap) |
| **Vulnerability scanning** | Non-exploitative checks from banners/versions (e.g. outdated OpenSSH patterns) |
| **Network mapping** | Visual graph of hosts from your completed scans |
| **History & reports** | Search/filter past scans; export HTML report or JSON |

Scans run in the **background** with a progress bar. You can keep browsing history while a large CIDR scan runs.

---

## Requirements

| Requirement | Notes |
|-------------|--------|
| **Go 1.23+** | To build/run from source |
| **MySQL 8** | Or use Docker Compose (includes MySQL) |
| **`ping`** | Used for host discovery / alive checks (Windows & Linux supported) |
| **`nmap`** | Optional — needed only for OS fingerprinting |

---

## Quick start (from source)

### 1. Configure

```bash
cp .env.example .env
```

Edit `.env` at least:

```env
DATABASE_DSN=root:YOUR_PASSWORD@tcp(127.0.0.1:3306)/gonet?charset=utf8mb4&parseTime=True&loc=Local
ADMIN_PASSWORD=choose-a-strong-password
SESSION_SECRET=long-random-string
LISTEN_ADDR=127.0.0.1:8585
```

Create the database if it does not exist:

```sql
CREATE DATABASE gonet CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 2. Run

```bash
go run .
```

### 3. Open the UI

1. Browse to [http://127.0.0.1:8585](http://127.0.0.1:8585)
2. Sign in with `ADMIN_PASSWORD` (default in example is `penego` — change it)
3. Choose a module from the top navigation
4. Enter a target such as `192.168.1.10` or `192.168.1.0/24`
5. Start the scan and wait for progress to reach 100%
6. Use **Export Report** for a printable HTML summary, or **JSON** for raw data

---

## Quick start (Docker)

```bash
docker compose up --build
```

- App: [http://127.0.0.1:8585](http://127.0.0.1:8585)
- Default login password: `penego` (set via compose env)
- MySQL is started and wired automatically

---

## Using the web UI

### Starting a scan

1. Open the module you need (Port Scanning, Host Discovery, …).
2. Fill in **Target** (single IP or CIDR). For port/vuln scans, set **Ports** (e.g. `22,80,443` or `1-1024`).
3. Adjust concurrency/timeout if needed, then click **Start**.
4. Results appear above the history list with a live progress bar.

### History: search, filter, export

On every scan page, the **Previous …** panel:

- **Loads automatically** when you open the page
- **Search** — type a scan ID, IP/CIDR, or port list (updates as you type)
- **Status** — filter by done / running / pending / failed / cancelled
- **Per page** — 5, 10, 20, or 50
- **Pagination** — Previous / Next
- Each row has **Export Report** (HTML), **JSON**, and **View**

### Inside a result

- Sticky toolbar with **Export Report**, **JSON**, **Cancel** (if still running), **Delete**
- Filter hosts by IP, port, service, OS, or CVE text
- Toggle whether dead hosts are shown

### Network mapping

Open **Network Mapping** and click **Refresh Map** to draw hosts from recent completed scans (same `/24` subnet and shared ports become edges).

---

## Configuration reference

| Variable | Default | Meaning |
|----------|---------|---------|
| `DATABASE_DSN` | _(required)_ | MySQL connection string |
| `LISTEN_ADDR` | `127.0.0.1:8585` | HTTP bind address |
| `ADMIN_PASSWORD` | `penego` | Web login password |
| `SESSION_SECRET` | _(example)_ | Signs session cookies — change in shared labs |
| `AUTH_DISABLED` | `false` | `true` skips login (trusted local only) |
| `MAX_HOSTS` | `1024` | Cap on CIDR expansion |
| `MAX_PORTS` | `4096` | Cap on port list size |
| `DEFAULT_HOST_CONCURRENCY` | `100` | Parallel hosts |
| `DEFAULT_PORT_CONCURRENCY` | `100` | Parallel ports per host |
| `RATE_LIMIT_PER_MIN` | `60` | Max API requests per IP per minute |

Full example: [`.env.example`](.env.example).

---

## Project docs (developers)

| Guide | Contents |
|-------|----------|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/10-user-guide.md](docs/10-user-guide.md) | Detailed end-user walkthrough |
| [docs/07-setup-and-run.md](docs/07-setup-and-run.md) | Install, Docker, troubleshooting |
| [docs/04-api-reference.md](docs/04-api-reference.md) | HTTP API for automation |
| [docs/02-architecture.md](docs/02-architecture.md) | Package layout and async jobs |

---

## Safety defaults

- Listens on **localhost** by default (`127.0.0.1:8585`)
- Password login enabled unless you set `AUTH_DISABLED=true`
- Rate limiting and audit logs for scan start / delete / cancel
- Vulnerability module is **detection-only** (no exploits)

---

## License / contribution

Use only on systems you are allowed to test. For architecture, API contracts, and contribution notes, see [`docs/`](docs/).
