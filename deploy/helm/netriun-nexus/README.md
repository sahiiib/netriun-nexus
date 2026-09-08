# Netriun Nexus Helm chart

By default, this chart deploys only the Nexus application and expects external
PostgreSQL and Redis services. For the current local cluster,
`values-local.yaml` also deploys single-replica PostgreSQL and Redis StatefulSets
with retained host-path volumes on `k8s-node01`.

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

When the bundled local PostgreSQL and Redis instances are enabled, the same
Secret must also contain `POSTGRES_PASSWORD` and `REDIS_PASSWORD`.

Render and inspect without deploying:

```sh
helm lint deploy/helm/netriun-nexus
helm template nexus deploy/helm/netriun-nexus \
  --set config.appOrigin=https://nexus.example.com
```

Deploy the local-cluster profile:

```sh
helm upgrade --install nexus deploy/helm/netriun-nexus \
  --namespace nexus-nteriun \
  --values deploy/helm/netriun-nexus/values-local.yaml \
  --wait
```

The local profile deliberately does not create an Ingress. HTTPS terminates at
Cloudflare, while Cloudflare Tunnel connects to this in-cluster HTTP origin:

```text
http://nexus-service.nexus-nteriun.svc.cluster.local:80
```

Create a Cloudflare Tunnel public hostname for `nexus.netriun.com` using that
origin. Nexus itself is configured with `APP_ORIGIN=https://nexus.netriun.com`
and secure cookies, so the public application remains HTTPS-only.

The bundled databases are appropriate for this local first deployment, but
their host-path storage is tied to `k8s-node01`. Back up
`/var/lib/netriun-nexus` on that node and move to replicated or managed storage
before treating the cluster as highly available.
