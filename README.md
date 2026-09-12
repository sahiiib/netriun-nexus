# Netriun Nexus

Netriun Nexus is a multi-tenant control plane for orchestrating multi-cloud operations, approvals, access, and live infrastructure health from one place. It includes PostgreSQL, Redis, an embedded web interface, and a versioned REST API. Each account receives an isolated workspace. AWS EC2, Alibaba Cloud ECS and WUYING EDS, Microsoft Azure Virtual Machines, and Google Compute Engine are supported.

## Run locally

Requirements: Docker Compose and OpenSSL.

```sh
sh scripts/setup-env.sh
docker compose up --build -d
```

Open http://localhost:8080. Sign in as `admin` with `ADMIN_PASSWORD` from `.env`, or create an independent Community workspace from the sign-up screen. The setup script generates independent secrets and refuses to overwrite an existing `.env`. Never commit this file. Back up `ENCRYPTION_KEY` alongside PostgreSQL backups: encrypted cloud credentials cannot be recovered without it.

The application initializes the schema and bootstrap administrator on first startup. Subsequent boots do not reset passwords. Connect an AWS or Alibaba Cloud account in **Cloud connections**, then use **Sync cloud**; the worker checks for requests every ten seconds.

```sh
docker compose logs -f app
docker compose down
```

If port 8080 is occupied, set `PORT` and the matching `APP_ORIGIN` in `.env` (for example, `PORT=18080` and `APP_ORIGIN=http://localhost:18080`).

Persistent volumes survive `down`. The portal, PostgreSQL and Redis are published on loopback only; they are not reachable through external network interfaces. Database ports are exposed locally to support host-based Go development.

When upgrading an existing installation from Netriun CCMP, stop the old application and database cleanly before copying its PostgreSQL and Redis volumes to the Nexus volume names. Never copy a live PostgreSQL data directory. Keep the old volumes as a rollback/forensic backup until the Nexus installation has been verified.

## Features

- Public Community workspace creation with strict tenant isolation.
- One owner plus five additional team members per Community workspace.
- Searchable, paginated compute inventory across AWS, Alibaba Cloud, Azure and Google Cloud.
- An active-account context that exposes only the services belonging to the selected cloud provider.
- Live Alibaba WUYING EDS desktops and convenience users, including create, renew, user assignment, start, stop, and reboot workflows.
- Guided AWS, Alibaba Cloud, Azure and Google Cloud connection setup with a required live credential and compute-access test before saving.
- Scheduled collection across explicitly selected or all enabled regions.
- Paginated provider collection and transactional reconciliation per successful region; failed regions retain their previous inventory.
- Start, stop and reboot; live security group, volume and network interface details.
- Workspace-scoped users, access policies and viewer/operator/manager memberships.
- Redis sessions, logout/revocation, login rate limiting and renewable collector leases.
- AES-256-GCM encryption for cloud credentials, bcrypt passwords and same-origin mutation checks.
- Audit history, retention settings, structured application logs and container log rotation.
- Searchable in-app Documentation Center and contextual Help, backed by one structured content source and the stable [documentation map](docs/index.md).
- REST API at `/api/v1`, in-app API reference and [OpenAPI specification](docs/openapi.json).
- Offline [legacy migration](docs/migration.md), with a dry-run default.
- Netriun visual design with persistent dark, light and system appearance modes.
- AWS, Alibaba Cloud, Microsoft Azure and Google Cloud compute inventory and lifecycle actions.

## Permissions

Every workspace is isolated at the database-query and authorization layers. The person who creates it is its permanent owner. Workspace administrators can manage that workspace only. Users see only accounts in groups with `view_dashboard` enabled. Accounts with no group are administrator-only.

| Group role | Capabilities |
| --- | --- |
| viewer | Inventory and live details when view policy is enabled |
| operator | Viewer capabilities plus start, stop and reboot |
| manager | Operator capabilities; account and membership management when the corresponding group policies allow it |

Only workspace administrators edit group policies, users, collection settings, and view that workspace's audit records. Moving an account requires management permission on both the current and destination groups. Password or user-role updates revoke all that user's sessions. Owners cannot be removed or demoted.

## API example

```sh
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"YOUR_PASSWORD"}'

curl http://localhost:8080/api/v1/instances?state=running \
  -H 'Authorization: Bearer YOUR_TOKEN'
```

Create a free isolated workspace with `POST /api/v1/auth/signup` and `{"workspace":"Team name","username":"owner","email":"owner@example.com","password":"Strong-password1!"}`. Email addresses and usernames are globally unique. A 24-hour verification link is sent by email, and sign-in remains disabled until it is used.

Login uses the verified email address and returns a token valid for 12 hours plus an HttpOnly session cookie. Passwords must be 10–72 bytes and contain uppercase, lowercase, a number, and a symbol. Lists use `{"data": [...]}`. Errors use `{"error":"message"}`. Inventory and audit lists support `limit` (default 50, maximum 200) and `offset`.

## AWS access

Use dedicated AWS credentials. Inventory needs `ec2:DescribeRegions` and `ec2:DescribeInstances`. Live details also need `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes` and `ec2:DescribeNetworkInterfaces`. Actions need `ec2:StartInstances`, `ec2:StopInstances`, and `ec2:RebootInstances` for permitted instances. A policy example is in [docs/aws-policy.json](docs/aws-policy.json); restrict its action resources to your environment before use. Temporary session tokens are supported but must be replaced before expiry.

## Alibaba Cloud access

Use a dedicated RAM user AccessKey, not a root-account AccessKey. ECS inventory needs `ecs:DescribeRegions` and `ecs:DescribeInstances`; actions need `ecs:StartInstance`, `ecs:StopInstance`, and `ecs:RebootInstance`. WUYING EDS uses narrowly listed `ecd` actions for region discovery, desktop inventory, provisioning, renewal, lifecycle, policy, maintenance, remote-command, billing, entitlement, and convenience-user management. Follow the [Alibaba Cloud connection guide](docs/alibaba.md) and start from [docs/alibaba-policy.json](docs/alibaba-policy.json); remove product statements you do not use and restrict ECS action resources before production use. Static STS security tokens are supported and must be replaced before expiry. Leaving regions blank discovers all ECS regions visible to the credential.

## Azure and Google Cloud access

Azure uses a Microsoft Entra service principal scoped to a subscription. Google Cloud uses a dedicated service-account JSON key scoped to a project. Nexus discovers Azure Virtual Machines and Google Compute Engine instances, provides live details, and supports start, stop and reboot/reset when the identity has the required role. Follow the [Azure and Google Cloud connection guide](docs/azure-gcp.md) and prefer read-only roles when lifecycle actions are not needed.

## Product documentation

The portal includes a searchable Documentation page and a contextual **Help** button that opens the article relevant to the current page. Both read from `internal/app/web/docs.js`, so guidance stays consistent. The long-term structure is fixed as **Getting Started → Cloud Connections → Services → Access Management → Operations → Troubleshooting**; use the [documentation map](docs/index.md) when expanding it in later phases.

## Go development

Go version is declared in `go.mod`. `make run` loads `.env`, starts PostgreSQL and Redis in containers, stops the Compose application service to prevent two collectors from writing concurrently, and runs the Go process on `http://localhost:8080`. It derives host-reachable database URLs from the Compose passwords, using local ports `15432` and `16379` by default.

Email verification uses SMTP with mandatory STARTTLS. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`, and `SMTP_FROM_NAME`; use an app password rather than a primary mailbox password.

```sh
make run
go test -race ./...
go vet ./...
go build -o bin/nexus ./cmd/nexus
```

If a default local port is occupied, set `LOCAL_PORT`, `POSTGRES_PORT`, or `REDIS_PORT` in `.env`. Advanced setups can provide `RUN_DATABASE_URL` and `RUN_REDIS_URL` to make the host process use external dependencies.

Integration tests run when `TEST_DATABASE_URL` and `TEST_REDIS_URL` are provided. **Use isolated databases**: tests truncate application tables and flush the selected Redis database. PostgreSQL database name must contain `ccmp_test`. CI provisions these dependencies.

## Operation and limitations

For a public deployment, terminate HTTPS at a reverse proxy, set `APP_ORIGIN` to the exact HTTPS origin, and set `COOKIE_SECURE=true`. Keep the application port private. `/healthz` checks the process; `/readyz` checks PostgreSQL and Redis. Application logs go to stdout; Docker rotates them. Audit retention is independent of application log retention.

The application ignores forwarded client-IP headers by default. When running behind a reverse proxy, set `TRUSTED_PROXY_CIDRS` to the proxy address or network (comma-separated) so login rate limiting uses the original client IP. Trust only networks controlled by your deployment; for example, a local proxy can use `127.0.0.1/32`.

This release supports inventory and lifecycle operations for AWS EC2, Alibaba Cloud ECS, Azure Virtual Machines and Google Compute Engine; it does not provision or terminate those compute instances. Alibaba EDS is queried live and supports desktop provisioning, renewal, entitlement, lifecycle, policy changes, maintenance mode, remote commands, and billing conversion. Operations that can create charges require explicit confirmation, and AutoPay defaults to off. The worker is embedded in the Go service and collector requests and leases are workspace-scoped. AWS and Alibaba collection is regional; Azure and GCP use subscription/project-wide inventory endpoints with optional region filtering. Cloud actions are synchronous submissions, with observed state refreshed by collection. Redis requests are coalesced, not a per-request job history. Mutation intents must be stored before an action is submitted; other audit writes are best effort and failures are logged. Versioned SQL migrations run transactionally on startup.

No production cloud action was performed during development. Real account validation requires your AWS/IAM or Alibaba Cloud RAM credentials and permissions.

## Kubernetes

A production-oriented Helm chart is available at [deploy/helm/netriun-nexus](deploy/helm/netriun-nexus). It deploys the application with non-root/read-only security settings and startup, liveness, and readiness probes. PostgreSQL and Redis are intentionally external dependencies. Render and inspect the chart before any cluster deployment; no Kubernetes resources are applied automatically.

Implementation references: [AWS SDK for Go v2](https://docs.aws.amazon.com/sdk-for-go/), [Alibaba Cloud Go SDK V2](https://help.aliyun.com/en/sdk/developer-reference/use-alibaba-cloud-go-sdk-through-ide), [Azure Compute REST API](https://learn.microsoft.com/en-us/rest/api/compute/), [Google Compute Engine REST API](https://cloud.google.com/compute/docs/reference/rest/v1), [pgx](https://github.com/jackc/pgx/), [go-redis](https://redis.io/docs/latest/develop/clients/go/connect/).
