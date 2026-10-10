# Obliwan

**Agentless, multi-vendor fleet manager for WAN routers: inventory, configuration drift, guarded changes and a TR-069 ACS.**

Obliwan manages fleets of customer-site routers reached through a tunnel concentrator. It keeps an inventory and an encrypted credential vault, collects device configurations into a normalized model, detects drift, and pushes template-driven changes with planning, health gates and canary rollouts. It is multi-tenant and aimed at MSPs and network operators managing many sites.

Website: [obli.tools](https://obli.tools)

## Key features

- **Multi-vendor drivers**: MikroTik RouterOS, DrayTek, Zyxel and SonicWall, plus inventory of TR-069 devices.
- **Several transports**: RouterOS API, SSH, REST and SNMP. No agent on the devices.
- **Inventory and credential vault**: sites and devices, discovery and reconciliation, address-pool allocation, encrypted credentials with audited secret reveal.
- **Configuration drift detection**: semantic diffs, attribution, exceptions and baselines.
- **Templates and variables**: Nunjucks templates with inherited variables.
- **Planned, guarded changes**: change plans, pre-change backups, health gates and canary rollouts.
- **Firmware management**: release watching and fleet OS upgrade jobs.
- **Telemetry**: SNMP polling with interface discovery, SNMP trap and syslog ingestion, line quality, SLA reports, alerts and fleet anomaly detection.
- **TR-069 ACS**: built-in CWMP listener.
- **Fleet query language** with saved queries, multi-tenancy, hierarchical groups, audit log, TOTP two-factor authentication and notification channels.

## Quick install

```sh
curl -fsSL https://raw.githubusercontent.com/obli-tools/Obliwan/main/install.sh | sh
```

The installer runs on Linux, or on macOS with Docker Desktop. It:

- checks Docker and Docker Compose; on Linux it offers to install them with Docker's official script, only after you confirm;
- downloads `docker-compose.yml` and `.env.example` into `./obliwan`;
- creates `.env` with unique random secrets (`DB_PASSWORD`, `SESSION_SECRET`, `OBLIWAN_ENCRYPTION_KEY`, initial admin password);
- pulls the images, starts the stack and prints the panel URL and the initial admin password (shown only once).

Running it again upgrades an existing install; `.env` is never modified.

Options (pass them after `sh -s --`):

| Option | Description |
|--------|-------------|
| `-y`, `--yes` | Non-interactive: accept the defaults and install Docker if it is missing |
| `--dir PATH` | Install directory (default `./obliwan`) |
| `--port PORT` | Host port of the web interface (default `3004`, first install only) |
| `--url URL` | Public URL of the panel, e.g. `https://obliwan.example.com` (first install only) |

```sh
curl -fsSL https://raw.githubusercontent.com/obli-tools/Obliwan/main/install.sh | sh -s -- -y --dir /opt/obliwan --url https://obliwan.example.com
```

`--help` lists every option.

## Manual install (Docker Compose)

```sh
mkdir obliwan && cd obliwan
curl -fsSLO https://raw.githubusercontent.com/obli-tools/Obliwan/main/docker-compose.yml
curl -fsSLO https://raw.githubusercontent.com/obli-tools/Obliwan/main/.env.example
cp .env.example .env
mkdir -p custom/scripts custom/.ssh
# Edit .env: set DB_PASSWORD, SESSION_SECRET (a long random string),
# OBLIWAN_ENCRYPTION_KEY (exactly 64 hex characters, e.g. openssl rand -hex 32),
# DEFAULT_ADMIN_PASSWORD and CLIENT_ORIGIN (the public URL of the panel).
docker compose up -d
```

The panel answers on port `3004` (`LISTEN_PORT`). The stack runs PostgreSQL 16, the server (`meejay/obliwan-server`) and the web client (`meejay/obliwan-client`). Optional compose profiles add a WireGuard sidecar and nightly database backups; see the comments in `docker-compose.yml`.

`OBLIWAN_ENCRYPTION_KEY` encrypts every stored device credential: back it up off the host, losing it makes them unrecoverable.

## Update

```sh
docker compose pull && docker compose up -d
```

Or run the installer again from the same directory.

## Network requirements

- The Docker host needs an IP route to the management addresses of your routers (for example the tunnel subnet behind your concentrator), or the optional WireGuard link described at the top of `docker-compose.yml`. Without it, every device shows as unreachable.
- The server also publishes `7547/tcp` (TR-069), `162/udp` (SNMP traps) and `514/tcp+udp` (syslog), configurable with `CWMP_PORT`, `SNMP_TRAP_PORT` and `SYSLOG_PORT`. These must be reachable from the devices.

## Requirements

- A Linux host (or macOS with Docker Desktop) with Docker Engine and Docker Compose v2.
- HTTPS through a reverse proxy for production use: set `CLIENT_ORIGIN` in `.env` to the public `https://` address and `FORCE_HTTPS=true`, then run `docker compose up -d` again.

## Single sign-on

Obliwan supports single sign-on with [Obligate](https://github.com/obli-tools/Obligate): register Obliwan as an app in Obligate, then enter the Obligate URL and API key in the Obliwan settings. Local accounts keep working alongside SSO.

## Part of the Obli suite

| Tool | Purpose |
|------|---------|
| [Obliance](https://ance.obli.tools) | Remote monitoring and management (RMM) |
| [Oblireach](https://reach.obli.tools) | Remote screen access and remote support |
| [Obliview](https://view.obli.tools) | Uptime and infrastructure monitoring |
| [Oblimap](https://map.obli.tools) | IPAM and network discovery |
| [Obliguard](https://guard.obli.tools) | Agent-based intrusion prevention |
| [Obligate](https://gate.obli.tools) | Single sign-on and access management for the suite |
| [Oblihub](https://hub.obli.tools) | Docker control panel |
| **[Obliwan](https://github.com/obli-tools/Obliwan)** | WAN router fleet management |
| [ObliDesk](https://github.com/obli-tools/ObliDesk) | Ticketing and service desk |
| [Obliplan](https://github.com/obli-tools/Obliplan) | Workforce scheduling and working-time tracking |
| [Oblifield](https://field.obli.tools) | Field intervention management |

Suite home: [obli.tools](https://obli.tools)

## License

Obliwan is source-available under the [Elastic License 2.0](LICENSE) (ELv2). You may use, modify and self-host it, including for commercial use inside your organization; you may not provide it to others as a hosted or managed service. See [LICENSE](LICENSE) for the full terms and the obli.tools clarifications.
