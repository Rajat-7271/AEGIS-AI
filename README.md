# AEGIS AI

**An AI-assisted Security Operations Center (SOC) platform for security monitoring, alert investigation, and incident management.**

[Live application](https://aegis-ai-tawny.vercel.app) · [Source code](https://github.com/Rajat-7271/AEGIS-AI) · [API health](https://aisoc.rajat.prod.page/health)

## Overview

AEGIS AI brings security operations workflows into one web console. It is designed to help security teams review alerts, investigate suspicious activity, manage cases, and understand SOC operations.

The repository is a monorepo containing the web application, API, shared packages, supporting services, infrastructure configuration, tests, and documentation.

**Deployment note:** The public instance is a limited MVP deployment. A module present in the source code is not necessarily enabled in the hosted instance. Some advanced capabilities require additional infrastructure and configuration.

## Main areas

- **Dashboard:** Overview of SOC activity and operational metrics.
- **Alerts:** Review and manage security alerts.
- **Investigations:** Organise and track investigation workflows.
- **Cases:** Manage incidents and their progress.
- **Hunt:** Threat-hunting workflows and saved searches.
- **SOC Insights:** Operational metrics and trends.
- **Evidence and comments:** Preserve investigation context where supported.
- **User management:** Administrator and analyst accounts.

## Roles

| Role | Purpose |
|---|---|
| Admin | User and platform administration. |
| SOC Analyst | Alert review, investigations, and case workflows. |

## Architecture

The current public deployment uses:

```text
Browser
  |
  v
Next.js frontend (Vercel)
  |
  v
FastAPI backend (Docker on Blitz)
  |
  v
PostgreSQL (Supabase)
```

### Technology

- Frontend: Next.js, React, TypeScript
- Backend: Python, FastAPI, Pydantic, SQLAlchemy
- Database: PostgreSQL with Alembic migrations
- Runtime and deployment: Uvicorn, Docker, Vercel, Blitz, Supabase
- Monorepo tooling: pnpm workspaces and Turborepo

## Repository layout

```text
apps/web/       Next.js web application
services/api/   FastAPI backend
packages/       Shared packages
infra/          Infrastructure and deployment configuration
scripts/        Development and operational scripts
docs/           Project documentation
```

## Public demo

- Web: https://aegis-ai-tawny.vercel.app
- API health: https://aisoc.rajat.prod.page/health

The API is hosted on the Blitz Free tier and may sleep after inactivity. If it is asleep, open the API health link in a browser, wait for it to wake, then return to the web application and refresh.

This deployment is an MVP/demo environment, not a guaranteed always-on production SOC service.

## Local development

### Prerequisites

- Git
- Docker Desktop with Docker Compose v2
- Node.js 20+
- pnpm (the repository declares pnpm 8.15.1)
- Python 3.11 for Python service development

### Clone

```bash
git clone https://github.com/Rajat-7271/AEGIS-AI.git
cd AEGIS-AI
```

Review the root Docker Compose configuration and service documentation before starting the local stack:

```bash
docker compose up -d
```

For frontend development:

```bash
pnpm install
pnpm --filter @aisoc/web dev
```

The frontend development server uses port 3000. Backend dependencies and configuration are defined in `services/api/pyproject.toml`. Configure environment variables using the provided example files. Never point local migration commands at the production database.

## Security

- Never commit `.env` files, passwords, API tokens, private keys, or database credentials.
- Keep production secrets in hosting-provider environment settings.
- Use unique credentials and grant users only the role they need.
- Use synthetic or sanitised data for demonstrations; do not upload sensitive customer telemetry to an unapproved environment.

## Contributing

1. Create a feature branch.
2. Keep changes scoped to the relevant app or service.
3. Run the applicable tests, lint checks, and type checks.
4. Never include secrets or real customer data in commits.
5. Open a pull request describing the change and how it was tested.

Useful root-level commands:

```bash
pnpm build
pnpm test
pnpm lint
pnpm type-check
```

Some checks require supporting services to be running. Consult the relevant package or service configuration.

## License

See [LICENSE](LICENSE).
