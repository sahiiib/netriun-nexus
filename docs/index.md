# Netriun Nexus documentation map

This is the canonical information architecture for product documentation. Keep these six top-level sections stable as the portal and supported services grow. New articles belong under the closest existing section; add a new top-level section only when the content cannot fit this model.

## 1. Getting Started

- Start with Netriun Nexus
- Workspace registration and email verification
- Team members and the Community workspace limit

## 2. Cloud Connections

- Connection wizard and connection test
- Amazon Web Services
- Alibaba Cloud — see [Alibaba Cloud guide](alibaba.md) and [RAM policy](alibaba-policy.json)
- Microsoft Azure — see [Azure and Google Cloud guide](azure-gcp.md)
- Google Cloud — see [Azure and Google Cloud guide](azure-gcp.md)

## 3. Services

- Multi-cloud compute inventory
- Alibaba WUYING EDS desktops
- Alibaba WUYING EDS users
- Future provider services such as object storage, databases, networking, and managed desktops

## 4. Access Management

- Workspace roles
- Access policies and group memberships
- Audit log

## 5. Operations

- Resource lifecycle actions
- Collection, refresh, and retention
- Local, Docker, and Kubernetes operation
- Legacy migration — see [migration guide](migration.md)

## 6. Troubleshooting

- Connection error codes and remediation
- Collection and sync failures
- Email verification problems
- API reference — see [OpenAPI specification](openapi.json)

## Content source

User-facing articles are stored as structured data in `internal/app/web/docs.js`. The Documentation Center, search results, and contextual Help dialogs all render from that single source. When adding or changing an article:

1. Keep its stable `id` if links may already exist.
2. Choose one of the six categories above.
3. Write a short task-oriented summary and ordered steps.
4. Add risk, permission, or billing guidance in `notes`.
5. Link longer provider instructions from the repository documentation when appropriate.
6. Verify both the Documentation page and the Help dialog for the relevant portal page.
