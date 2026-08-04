# 07 — Setup and Run

## Prerequisites

| Dependency | Required | Purpose |
|------------|----------|---------|
| Go 1.23+ | For source builds | Compile / `go run` |
| MySQL 8.x | Yes (or Compose) | Persistence |
| `ping` | Recommended | Host discovery / alive checks |
| `nmap` | Optional | OS fingerprinting |

On Windows, install nmap separately if you need OS detection. Docker images already include `ping` and `nmap`.

## Configure from source

```bash
cp .env.example .env
```

Minimum `.env`:

```env
DATABASE_DSN=root:password@tcp(127.0.0.1:3306)/gonet?charset=utf8mb4&parseTime=True&loc=Local
LISTEN_ADDR=127.0.0.1:8585
ADMIN_PASSWORD=change-me
SESSION_SECRET=change-me-to-a-long-random-value
```

Create the database:

```sql
CREATE DATABASE gonet CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

If you previously ran an older Penego schema, prefer dropping old tables or recreating `gonet` so associations match the current models.

## Run

```bash
go run .
# or
go build -o penego.exe .
./penego.exe
```

Open http://127.0.0.1:8585 and sign in.

Startup logs will warn if `ping` or `nmap` look unavailable.

## Docker Compose

```bash
docker compose up --build
```

| Service | Role |
|---------|------|
| `mysql` | MySQL 8.4, database `gonet`, root password `penego` |
| `app` | Penego on `0.0.0.0:8585` published as host `8585` |

Compose sets `DATABASE_DSN` to reach the `mysql` service. Default UI password is `penego`.

## Tests

```bash
go test ./...
```

Unit coverage focuses on parsing, CIDR expansion, vuln matching, and mapping helpers.

## Environment reference

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_DSN` | _(required)_ | MySQL DSN |
| `LISTEN_ADDR` | `127.0.0.1:8585` | HTTP bind |
| `ADMIN_PASSWORD` | `penego` | Login password |
| `SESSION_SECRET` | example value | Cookie HMAC key |
| `AUTH_DISABLED` | `false` | Skip auth if `true` |
| `MAX_HOSTS` | `1024` | CIDR expansion cap |
| `MAX_PORTS` | `4096` | Port list cap |
| `DEFAULT_HOST_CONCURRENCY` | `100` | Parallel hosts |
| `DEFAULT_PORT_CONCURRENCY` | `100` | Parallel ports |
| `RATE_LIMIT_PER_MIN` | `60` | Per-IP API budget |

## Troubleshooting

| Symptom | Likely cause | What to try |
|---------|--------------|-------------|
| Fatal on start: `DATABASE_DSN is required` | Missing `.env` | Copy `.env.example` and set DSN |
| Fatal: connect database | Wrong password/host/DB | Verify MySQL is up and DSN matches |
| Login loop / 401 on API | Cookie / password | Check `ADMIN_PASSWORD`; clear cookies |
| All hosts “dead” on discovery | ICMP blocked / no ping | Test `ping` manually; check firewall |
| OS always Unknown | No nmap / no privileges | Install nmap; run elevated if needed |
| UI looks old after changes | Embedded assets | Rebuild / restart the binary |
| `CIDR expands to N hosts (max …)` | Over `MAX_HOSTS` | Narrow CIDR or raise cap carefully |
| Rate limit exceeded | Too many requests | Wait a minute or raise `RATE_LIMIT_PER_MIN` |

## Next reads

- Operator walkthrough → [10-user-guide.md](./10-user-guide.md)
- API automation → [04-api-reference.md](./04-api-reference.md)
- Caveats → [08-known-issues.md](./08-known-issues.md)
