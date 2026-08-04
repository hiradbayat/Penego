# 05 — Scanning Engine

Implementation lives under `services/`. Handlers never dial, ping, or exec directly.

## Shared helpers (`network.go`, `probe.go`)

| Function | Role |
|----------|------|
| `ParsePorts` | Comma lists and ranges; validates 1–65535 |
| `ValidateTarget` | Single IP or CIDR only |
| `ResolveTargets` | Expand CIDR, drop network/broadcast when applicable, enforce `MAX_HOSTS` |
| `CompareIP` | Numeric IPv4 sort |
| `ProbeTCP` | `DialTimeout` + optional 512-byte banner peek |
| `ScanHost` | Parallel port probes with `port_concurrency` |
| `IsHostAlive` | Windows: `ping -n 1 -w <ms>`; Unix: `ping -c 1 -W <sec>` |
| `GetOSFingerprint` | `nmap -O`, parse `OS details:` line |
| `CheckPingAvailable` / `CheckNmapAvailable` | Startup diagnostics |

Banner → service map (substring match): OpenSSH, Apache, nginx, MySQL, PostgreSQL.

## Orchestrators (`scanner.go`, `vuln.go`)

| Function | Sets `ScanType` | Alive means |
|----------|-----------------|-------------|
| `RunPortScan` | `port_scan` | ≥1 open TCP port |
| `RunHostDiscovery` | `host_discovery` | ping success |
| `RunOSFingerprint` | `os_fingerprint` | ping success (+ OS string) |
| `RunVulnScan` | `vuln_scan` | open ports; findings via `MatchVulns` |

All accept `context.Context` for cancel and an `onProgress(done, total)` callback.

## Jobs (`jobs.go`)

`JobManager.Start` inserts a pending report, stores a cancel func, and runs the engine in a goroutine. On success it persists nested `Hosts` / ports / findings and sets `status=done`, `progress=100`. Failures and cancels update `error_message` / status accordingly.

`source_scan_id` on vuln jobs reloads an existing scan’s hosts and re-runs `AnalyzeExistingHosts` without re-probing the network.

## Mapping & reporting

- `BuildNetworkMap` — nodes from hosts; edges for same `/24` and shared ports
- `RenderHTMLReport` — printable HTML summary (target, alive/dead, ports, OS, findings)

## Operational limits

Configured via env: `MAX_HOSTS`, `MAX_PORTS`, default host/port concurrency. Oversized requests fail fast with a clear error before work starts.
