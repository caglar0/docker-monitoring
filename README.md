# Docker Container Monitoring & Audit System

An end-to-end infrastructure monitoring system that audits Docker container operations at the kernel level using the Linux audit subsystem (auditd), tracks resource usage, and automatically detects unauthorized container access.

## Architecture
GPU Server 1 ─┐ ┌─ FastAPI Backend

GPU Server 2 ─┼─── HTTP (JSON) ──────────┼─ PostgreSQL

│ └─ React Frontend

└── Agent (3 threads):

• audit.log tail → docker command logs
• docker events stream → container lifecycle
• /proc + docker stats → resource usage
- **GPU Servers**: auditd monitors docker commands (execve syscall). A lightweight Python agent on each server forwards audit logs, Docker daemon events (create/start/stop/destroy), and CPU/RAM metrics to the central server.
- **Monitoring Server**: FastAPI backend (audit-event correlation, authorization logic, REST API), PostgreSQL (audit records, container inventory, time-series metrics), React frontend.

## Features

- **Audit-based command tracking** — every docker command is recorded with user, PID, timestamp, and full command text; commands that succeed at the syscall level but fail at the application level (e.g. invalid image) are correctly distinguished.
- **Container lifecycle tracking** — each container's create/start/stop/destroy history is displayed as a chronological timeline merged with related audit logs.
- **Unauthorized access detection** — actions (`exec`/`stop`/`kill`/`rm`, etc.) performed by a user against a container they don't own are automatically flagged.
- **Resource usage monitoring** — host and container-level CPU/RAM usage, viewable both live and historically, with quick date-range presets and a calendar filter.
- **Per-user resource analytics** — total resource consumption per container owner, presented as a list, bar chart, or pie chart.
- **Filterable log interface** — multi-criteria filtering by user, container, status (SUCCESS/FAILED), and command content.
- **JWT-based authentication** — stateless session management.

## Requirements

- Docker & Docker Compose (on the monitoring server)
- Docker Engine + auditd (on every server being monitored)
- Python 3.10+ (installed automatically when building the agent image, no manual setup needed)

## Setup

### 1. Monitoring Server

```bash
git clone <repo-url>
cd monitoring-system
cp .env.example .env   # fill in POSTGRES_USER, POSTGRES_PASSWORD, ADMIN_USERNAME, ADMIN_PASSWORD, JWT_SECRET
docker-compose up -d --build
```

The frontend runs on `:5173` and the backend on `:8000` by default.

### 2. Configure auditd Rules (on every monitored server)

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -F key=exec_watch
```

To make this persistent, add it to `/etc/audit/rules.d/audit.rules` and run:
```bash
sudo augenrules --load
```

### 3. Build and Run the Agent (on the server being monitored)

```bash
cd agent
docker build -t lightweight-agent .

docker run -d \
  --name docker-monitor-agent \
  --restart unless-stopped \
  -v /var/log/audit:/var/log/audit:ro \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e SERVER_NAME=<this-server-name> \
  lightweight-agent
```

Set `SERVER_NAME` to a **unique**, descriptive name on each server (e.g. `gpu-server-1`) — it's used to distinguish resources in the UI.

## Environment Variables (`.env`)

| Variable | Description |
|---|---|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | PostgreSQL connection settings |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Web UI login credentials |
| `JWT_SECRET` | Token signing key — use a long, random value |

## Project Structure
monitoring-system/

├── backend/ # FastAPI + SQLAlchemy

├── frontend/ # React + Vite + Tailwind

├── agent/ # Monitoring agent deployed to GPU/application servers

├── docker-compose.yml

└── .env.example
## Known Limitations

- Container-event correlation falls back to approximate timestamp-based matching in the rare case where the target container isn't specified in the command's arguments (e.g. an unnamed `docker run`).
- Per-user resource usage is not stored in a dedicated table; it's computed on-the-fly from existing data at request time.

## License

MIT
