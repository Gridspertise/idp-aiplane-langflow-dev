# Langflow - mgmt-dev / gsp-platform

Wrapper Helm chart for the official `langflow-ide` chart, pinned to `0.1.2`.
It deploys Langflow as a StatefulSet serving both the API and the packaged
React visual editor on port 7860. It replaces the previous placeholder nginx dependency and
uses the existing OpenShift router; it does not install an Ingress controller
or cert-manager.

## Configure before release

- The application image in `values.yaml` is
  `quay.apps.rosa.mgmt-cluster.3mu6.p3.openshiftapps.com/gridspertise.platform/idp-aiplane-langflow:feature-addsso`.
  It is built with the application repository's
  `infrastructure/docker/Dockerfile`, which compiles and packages the React UI.
  `langflow.backend.backendOnly: false` enables the UI. The chart's separate
  Nginx frontend deployment is disabled; no second frontend image is required.
  Add `langflow-ide.imagePullSecrets` if the registry requires authentication.
- In `route.yaml`, all three Routes request `subdomain: ai-portal`, without
  setting `host`. Keep the same subdomain on all three. The expected hostname is
  `ai-portal.<ingress-controller-domain>`; verify the assigned hostname and
  admission in each Route's `status.ingress`, because the controller can ignore
  or reject a requested subdomain. Setting `host` would take precedence over
  `subdomain`. TLS uses edge termination and the OpenShift router's default
  certificate, with HTTP redirected to HTTPS. Ensure that certificate covers
  the assigned hostname. No `langflow-tls` Secret is referenced by these Routes.
- In `sso-configmap.yaml`, set the Keycloak discovery URL, realm and client ID.
  Replace `langflow.example.com` in both redirect URLs with the assigned public
  hostname, and register those exact URLs in Keycloak. The SSO configuration
  does not automatically resolve the Route subdomain.
- Apply `postgres-cluster.yaml` through the CloudNativePG operator. It creates
  PostgreSQL 18.6 with a `langflow` database and non-superuser owner.
  `LANGFLOW_DATABASE_URL` is read from the generated `langflow-postgres-app`
  Secret's `fqdn-uri` key; no database credentials need to be copied or assembled.
  Both chart-side database URL assembly and the bundled PostgreSQL/SQLite
  options remain disabled.
- Configure the default StorageClass or set `storageClassName` in `pvc.yaml`.
  Set `spec.storage.storageClass` in `postgres-cluster.yaml` if PostgreSQL
  should use a non-default StorageClass. Replace the existing `__TARGET_NAMESPACE__`
  placeholder in `pvc.yaml` with the release namespace (`gsp-platform` below).
  Keep a single backend replica while using this ReadWriteOnce data volume.

`postgres-cluster.yaml`, `pvc.yaml`, `sso-configmap.yaml`,
`backend-headless-service.yaml`, and `route.yaml` are plain Kubernetes/OpenShift
resources, outside Helm ownership. Apply them explicitly; do not
run `kubectl apply -f .`, because this directory also contains Helm metadata
and a non-functional Secret example.

The headless Service supplies the governing Service referenced by the upstream
StatefulSet but not created by chart `0.1.2`. Its selector assumes the release
name `langflow`, as used below; update it if renaming the release.

## Secrets

Copy `secret.example.yaml` to `secret.local.yaml`, replace every example value
and apply the local file. `*.local.yaml` is ignored by Git. Alternatively,
provision `langflow-secrets` using your existing secret manager.

The required keys are listed in the example; do not commit actual credentials.
Use a stable Fernet key for `LANGFLOW_SECRET_KEY`, shared by all application
processes. Back up the key with the database: changing it makes existing
encrypted data unreadable.

CloudNativePG owns the database password and connection URI in
`langflow-postgres-app`. Bootstrap creates database `langflow`, owned by the
non-superuser role `langflow`, and generates its password automatically.
The application reads the Secret's `fqdn-uri` key, which includes URL-encoded
credentials and the primary (`-rw`) Service's fully qualified DNS name:
`langflow-postgres-rw.gsp-platform.svc.<cluster-domain>` (normally
`langflow-postgres-rw.gsp-platform.svc.cluster.local`), on port 5432.
Clients do not bind to an individual database pod. The backend also mounts
the generated `langflow-postgres-ca` Secret and uses `PGSSLMODE=verify-full`
and `PGSSLROOTCERT` to validate the database certificate. The generated
`postgresql://` URI is supported by Langflow, which selects its psycopg driver.
Do not set `LANGFLOW_DATABASE_URL` in `secret.local.yaml`.

No credentials are stored in Helm values. In particular, do not set the
upstream chart's `autoLogin`, `superuserPassword`, or `secretKey` values:
authentication is configured via the explicit backend `env` entries so Helm
does not generate random credentials or duplicate those variables.

Three Routes share one hostname: `/`, `/api` and `/health` all target
`langflow-service-backend:7860`, which serves the visual editor, API and health
endpoints. This preserves the existing Route names and paths without a separate
Nginx proxy or its default 1 MiB upload limit. Neither `BACKEND_URL` nor
`FRONTEND_PORT` is needed in this integrated deployment.
Router timeouts are set to 300 seconds for long-running requests and
streams. Proxy trust is enabled; the Routes replace forwarded headers at the
router. Only expose the backend through this trusted router. Edge termination
uses HTTP between the router and the application Services.

## Install or upgrade

### CloudNativePG operator prerequisite

Verify the intended Kubernetes context before any install. The operator may
already be installed by the platform team or through OpenShift OLM:

```bash
kubectl config current-context
kubectl get crd clusters.postgresql.cnpg.io
```

Do not install a second operator if one is already present. On a cluster
without CloudNativePG, a cluster administrator can install it separately:

```bash
helm repo add cnpg https://cloudnative-pg.github.io/charts
helm repo update cnpg
helm upgrade --install cnpg cnpg/cloudnative-pg \
  --version 0.29.1 \
  --namespace cnpg-system --create-namespace \
  -f cnpg-operator-values.yaml \
  --wait --timeout 5m
kubectl wait --for=condition=Established \
  crd/clusters.postgresql.cnpg.io --timeout=120s
```

Chart `0.29.1` installs operator `1.30.1` and requires Kubernetes 1.29 or newer.
Keep operator upgrades under platform-team control; do not mix Helm and OLM
ownership. The operator is not a dependency of the application Helm chart,
because it is cluster infrastructure and must exist before the `Cluster` CR.

### Database and application

From this directory, after replacing example values and confirming the
context and namespace. Namespace `gsp-platform` must already be provisioned
by the platform team (for OpenShift, use the assigned project):

```bash
kubectl get namespace gsp-platform
kubectl apply -f secret.local.yaml
kubectl apply -f postgres-cluster.yaml
kubectl wait --for=condition=Ready cluster.postgresql.cnpg.io/langflow-postgres \
  -n gsp-platform --timeout=15m
kubectl get secret langflow-postgres-app langflow-postgres-ca -n gsp-platform
kubectl apply -f pvc.yaml -f sso-configmap.yaml -f backend-headless-service.yaml

helm repo add langflow https://langflow-ai.github.io/langflow-helm-charts
helm repo update langflow
helm dependency build .
helm lint .
helm template langflow . --namespace gsp-platform > /tmp/langflow-rendered.yaml
helm upgrade --install langflow . \
  --namespace gsp-platform \
  --wait --timeout 15m

kubectl apply -f route.yaml
kubectl get route langflow langflow-api langflow-health -n gsp-platform
kubectl get route langflow langflow-api langflow-health -n gsp-platform \
  -o 'custom-columns=NAME:.metadata.name,HOST:.status.ingress[*].host,ADMITTED:.status.ingress[*].conditions[?(@.type=="Admitted")].status'
kubectl rollout status statefulset/langflow-service -n gsp-platform
```

The OpenShift router with a suitable certificate, ready CloudNativePG database
and StorageClass must exist before installing Langflow.
`Chart.lock` locks the dependency version; downloaded chart
archives under `charts/` are intentionally not committed.

If upgrading a deployment that used the previous Ingress manifest, remove that
resource before applying the Routes to avoid competing host/path ownership:

```bash
kubectl delete ingress langflow -n gsp-platform --ignore-not-found
kubectl apply -f route.yaml
```

The supplied database uses one instance for mgmt-dev, with 20 GiB persistent
storage. This is not HA and does not include scheduled backups or WAL archiving;
configure and test backups before storing data that cannot be recreated.
For HA, plan at least three instances, suitable node placement and the extra
storage/resource requirements. Do not delete the Cluster or its PVCs to change
database configuration. Bootstrap creates a new empty database; it does not
automatically migrate data from an existing external PostgreSQL deployment.

Database credential rotation changes the operator-managed Secret, not
`langflow-secrets`. Restart the backend after credential rotation so its
environment reloads `fqdn-uri`.

This is the management/development IDE deployment. It does not enable
`LANGFLOW_DEPLOYMENT_PROFILE=prod`, which requires additional external storage,
pgVector and other infrastructure checks in our application branch. Backend
probes allow time for migrations; upstream `0.1.2` does not expose a separate
startup probe.

## Declarative SSO

The backend reads `/etc/langflow/sso/sso-bootstrap.yaml` at startup, after DB
initialization, and upserts providers by immutable slug. `${KEYCLOAK_CLIENT_SECRET}`
is resolved from the Secret-injected environment. Other `${VARIABLE}` references
may be used if corresponding backend `env` entries are added in `values.yaml`.
Kubernetes and Helm do not expand these references; the custom backend does.

Missing variables or invalid configuration cause startup to fail. Providers
not listed in the file are not deleted; disable a provider with `enabled: false`
before removing it. API changes to declared providers are overwritten on restart.

In Keycloak, enable the authorization-code flow and client authentication, and
register exactly these URLs using the real Langflow hostname:

- Valid redirect URI: `https://langflow.example.com/api/v1/sso/keycloak/callback`
- Valid post-logout redirect URI: `https://langflow.example.com/login`

Frontend and backend share one public origin, so omit
`post_login_redirect_origin`. Cookies are configured Secure and require HTTPS.

After changing ConfigMap or Secret:

```bash
kubectl apply -f sso-configmap.yaml
kubectl apply -f secret.local.yaml
kubectl rollout restart statefulset/langflow-service -n gsp-platform
kubectl rollout status statefulset/langflow-service -n gsp-platform
```

The ConfigMap is not hot-reloaded. Environment values from Secrets also require
a pod restart. Plain resources are not removed by `helm uninstall`; retain the
PVC and CloudNativePG Cluster unless their data can be discarded.

## Image build

Use `infrastructure/docker/Dockerfile` in the application repository for the
single application image. Its CI build context combines the contents of
`infrastructure/docker/` and `src/`, as documented at the top of that Dockerfile;
it is not a repository-root build context.

The Dockerfile builds the React UI, copies it into the Python package and checks
that `frontend/index.html` is present. It also installs PostgreSQL support.
Build and push this image through the existing CI pipeline, then update the
repository/tag in `values.yaml`. Do not use the backend-only or separate Nginx
Dockerfiles for this integrated deployment.

References:

- https://docs.langflow.org/deployment-kubernetes-dev
- https://github.com/langflow-ai/langflow-helm-charts/tree/main/charts/langflow-ide
- https://cloudnative-pg.io/docs/1.30/bootstrap/
- https://cloudnative-pg.io/docs/1.30/applications/
