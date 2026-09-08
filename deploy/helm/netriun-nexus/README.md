# Netriun Nexus Helm chart

This chart deploys the Nexus application only. PostgreSQL and Redis must be
provided as external services so their lifecycle and backups remain independent
from application releases.

Create the application Secret before installation. Do not commit literal
credentials to a values file:

```sh
kubectl create secret generic netriun-nexus \
  --from-literal=DATABASE_URL='postgres://...' \
  --from-literal=REDIS_URL='redis://...' \
  --from-literal=ENCRYPTION_KEY='...' \
  --from-literal=ADMIN_USERNAME='admin' \
  --from-literal=ADMIN_PASSWORD='...'
```

Render and inspect without deploying:

```sh
helm lint deploy/helm/netriun-nexus
helm template nexus deploy/helm/netriun-nexus \
  --set config.appOrigin=https://nexus.example.com
```

For a real release, use a fixed image tag, configure ingress/TLS and provide the
exact trusted proxy CIDRs. The default chart intentionally does not install
PostgreSQL, Redis, an Ingress controller, or a certificate manager.
