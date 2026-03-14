# Audit Radar

**Real-time audit log explorer for OpenShift and Kubernetes**

Audit Radar collects, stores, and visualizes Kubernetes API audit events. It shows you who did what, when, and where across your cluster — with AI-powered risk scoring, webhook alerting, and exclusion filters.

Built for Red Hat OpenShift 4.x and Kubernetes / k3s.

🌐 [audit-radar.com](https://audit-radar.com) · [Docker Hub](https://hub.docker.com/u/hybrid2k3)

---

## Features

- **Live event stream** — real-time audit log feed with filtering by actor, namespace, verb, resource, and risk level
- **AI risk scoring** — every event scored HIGH/MEDIUM/LOW by IBM Granite 3.2 running locally via Ollama; no data leaves the cluster
- **Alert rules** — configurable webhook alerts to Slack and email (human DELETE, HIGH risk events, custom rules)
- **Exclusion filters** — drop noisy service account traffic before it hits the database
- **OCP OAuth2** — single sign-on with OpenShift groups (`audit-radar-admins`, `audit-radar-editors`, viewer)
- **Basic auth** — username/password fallback (works on both OCP and plain Kubernetes)
- **CSV export** — export filtered events for compliance reporting
- **SOC2 / PCI ready** — full audit trail of human and system actions across all namespaces

---

## Architecture

```
kube-apiserver
      │  audit events
      ▼
CLF (OpenShift)          Vector DaemonSet (Kubernetes/k3s)
      │  HTTP POST               │  HTTP POST
      └──────────────┬───────────┘
                     ▼
             audit-collector ──── PostgreSQL
                                      │
                              audit-analyzer (Granite 3.2 via Ollama)
                              audit-alerter  (Slack / email)
                                      │
                                  audit-ui ◄──── OCP OAuth2 / basic auth
                                      │
                                   browser
```

| Component | Image | Description |
|-----------|-------|-------------|
| audit-ui | `hybrid2k3/audit-ui` | Go HTTP server — UI, API, settings |
| audit-collector | `hybrid2k3/audit-collector` | Receives events, normalizes, stores |
| audit-analyzer | `hybrid2k3/audit-analyzer` | AI risk scoring via Granite 3.2 |
| audit-alerter | `hybrid2k3/audit-alerter` | Slack/email alerts on rules |
| ollama | `ollama/ollama` | Local LLM runtime |
| postgres | `registry.redhat.io/rhel9/postgresql-15` (OCP) / `postgres:15` (k8s) | Event storage |

---

## Helm Charts

Two separate charts are provided — one per platform:

| Chart | Path | Platform |
|-------|------|----------|
| `audit-radar-openshift` | `Helm/audit-radar-openshift/` | Red Hat OpenShift 4.x |
| `audit-radar-k8s` | `Helm/audit-radar-k8s/` | Kubernetes / k3s |

---

## Install on OpenShift

### Prerequisites

- OpenShift 4.x with cluster-admin
- Helm 3.x

### 1. Install OpenShift Logging operator

```bash
oc apply -f deploy/04b-logging-operator.yaml
# Wait ~2-3 minutes for Succeeded
oc get csv -n openshift-logging -w
```

### 2. Deploy Audit Radar

```bash
helm install audit-radar ./Helm/audit-radar-openshift
```

All secrets (PostgreSQL password, OAuth client secret, basic auth password) are generated automatically — no manual configuration required.

### 3. Apply cluster-level configuration

```bash
# Cluster Log Forwarder — forwards audit events to the collector
oc apply -f deploy/05-clf.yaml
```

```bash
# APIServer audit policy — enables field-level change capture
# ⚠ WARNING: Triggers a rolling restart of kube-apiserver pods (~5-10 min).
# Cluster stays available. Monitor with: oc get pods -n openshift-kube-apiserver -w
oc apply -f deploy/07-apiserver-audit.yaml
```

### 4. Add admin users

```bash
oc adm groups add-users audit-radar-admins <your-username>
```

### 5. Open the UI

```bash
oc get route audit-ui -n audit-vision
```

---

## Install on Kubernetes / k3s

### Prerequisites

- Kubernetes 1.24+ or k3s with cluster-admin
- Helm 3.x
- Audit logging enabled on kube-apiserver (see below)

### 1. Enable audit logging

Audit Radar requires the kube-apiserver to write audit logs to a file on the node. Refer to your distribution's documentation for how to enable audit logging. The audit log path must match `vector.auditLogPath` in values (default: `/var/log/k3s-audit.log`).

Example audit policy is included in `deploy-k8s/audit-policy.yaml`.

### 2. Set your node IP in values

Edit `Helm/audit-radar-k8s/values.yaml`:

```yaml
ui:
  ingress:
    host: "audit.<your-node-ip>.nip.io"
```

Or override on install:

```bash
helm install audit-radar ./Helm/audit-radar-k8s \
  --set ui.ingress.host=audit.192.168.10.30.nip.io
```

### 3. Deploy Audit Radar

```bash
helm install audit-radar ./Helm/audit-radar-k8s
```

### 4. Open the UI

```bash
kubectl get ingress -n audit-vision
# Open http://audit.<your-node-ip>.nip.io
```

---

## Default Credentials

> ⚠ **Change the basic auth password before exposing the UI externally.**

When installed via Helm, the basic auth password is auto-generated from the release name. To retrieve it:

```bash
# OpenShift
oc get secret audit-ui-basic-secret -n audit-vision \
  -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d

# Kubernetes
kubectl get secret audit-ui-basic-secret -n audit-vision \
  -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d
```

When installed manually (without Helm), the default credentials are:

| Field | Value |
|-------|-------|
| Username | `admin` |
| Password | `changeme` |

Change immediately after install:

```bash
# OpenShift
oc create secret generic audit-ui-basic-secret \
  --from-literal=AUTH_BASIC_USER=admin \
  --from-literal=AUTH_BASIC_PASS=yournewpassword \
  -n audit-vision --dry-run=client -o yaml | oc apply -f -
oc rollout restart deployment/audit-ui -n audit-vision

# Kubernetes
kubectl create secret generic audit-ui-basic-secret \
  --from-literal=AUTH_BASIC_USER=admin \
  --from-literal=AUTH_BASIC_PASS=yournewpassword \
  -n audit-vision --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/audit-ui -n audit-vision
```

---

## Storage

Audit Radar uses persistent storage for PostgreSQL (events) and Ollama (AI model ~1.5GB).

By default both charts use the cluster's **default StorageClass** — no configuration needed on most clusters.

| Cluster | Default StorageClass | Notes |
|---------|---------------------|-------|
| k3s | `local-path` | Stores data on node at `/var/lib/rancher/k3s/storage/` |
| OpenShift / OCS | set explicitly | Default chart uses `ocs-external-storagecluster-ceph-rbd` |
| Other clusters | cluster default | Check with `kubectl get storageclass` |

Check available storage classes on your cluster:

```bash
kubectl get storageclass
```

To use a specific StorageClass:

```bash
helm install audit-radar ./Helm/audit-radar-k8s \
  --set postgres.storageClassName=my-storage-class \
  --set ollama.storageClassName=my-storage-class
```

---

## Configuration

### OpenShift — `Helm/audit-radar-openshift/values.yaml`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `namespace` | `audit-vision` | Target namespace |
| `postgres.storage` | `10Gi` | PVC size for PostgreSQL |
| `collector.retentionDays` | `30` | Event retention in days (0 = disabled) |
| `ui.auth.adminGroup` | `audit-radar-admins` | OCP group for admin role |
| `ui.auth.editorGroup` | `audit-radar-editors` | OCP group for editor role |
| `ui.auth.basicUser` | `admin` | Basic auth username |
| `ollama.enabled` | `true` | Deploy Ollama + AI analyzer |
| `ollama.model` | `granite3.2:2b` | Model to pull (~1.5GB) |
| `ollama.storageClassName` | `ocs-external-storagecluster-ceph-rbd` | StorageClass for model PVC |
| `alerter.slack.webhookUrl` | `""` | Slack incoming webhook URL |
| `alerter.smtp.host` | `""` | SMTP host for email alerts |

### Kubernetes — `Helm/audit-radar-k8s/values.yaml`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `namespace` | `audit-vision` | Target namespace |
| `postgres.storage` | `10Gi` | PVC size for PostgreSQL |
| `collector.retentionDays` | `30` | Event retention in days (0 = disabled) |
| `ui.auth.basicUser` | `admin` | Basic auth username |
| `ui.ingress.host` | `audit.192.168.10.30.nip.io` | Ingress hostname — **change this** |
| `ollama.enabled` | `true` | Deploy Ollama + AI analyzer |
| `ollama.model` | `granite3.2:2b` | Model to pull (~1.5GB) |
| `vector.auditLogPath` | `/var/log/k3s-audit.log` | Path to audit log on host |
| `alerter.slack.webhookUrl` | `""` | Slack incoming webhook URL |
| `alerter.smtp.host` | `""` | SMTP host for email alerts |

### Disable AI analyzer (resource-constrained clusters)

```bash
helm install audit-radar ./Helm/audit-radar-k8s \
  --set ollama.enabled=false \
  --set analyzer.enabled=false
```

---

## Role Mapping

### OpenShift

| Source | Role | Access |
|--------|------|--------|
| OCP group `audit-radar-admins` | admin | Full access including settings |
| OCP group `audit-radar-editors` | editor | Alert rules, no settings |
| Any authenticated OCP user | viewer | Read-only event stream |
| Basic auth user | admin (configurable) | Full access |

```bash
# Grant admin access
oc adm groups add-users audit-radar-admins alice

# Grant editor access
oc adm groups add-users audit-radar-editors bob
```

### Kubernetes

On plain Kubernetes there is no OCP OAuth. A single basic auth user is supported — all users share the same credentials. Multi-user support with individual roles requires an OIDC provider (Keycloak, Dex).

Retrieve the generated password after install:

```bash
kubectl get secret audit-ui-basic-secret -n audit-vision   -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d
```

---

## Exclusion Filters

Noisy service account traffic can be dropped before it hits the database using exclusion rules in **Settings → Exclusion Filters**.

Wildcard actor matching is supported:

```
system:serviceaccount:cert-manager:*
system:serviceaccount:openshift-*
```

Rules reload every 30 seconds — no restart required.

---

## Alerting

Slack webhooks and email (SMTP) are configured directly in the UI under **Settings → Alert Settings**. No restart required — changes apply within 60 seconds.

---

## Secrets Management

All secrets are auto-generated on `helm install` and derived deterministically from the release name — upgrades never rotate credentials unexpectedly.

| Secret | Key | Description |
|--------|-----|-------------|
| `postgres-secret` | `DATABASE_URL` | PostgreSQL connection string |
| `audit-ui-oauth-secret` | `AUTH_CLIENT_SECRET` | OCP OAuth2 client secret |
| `audit-ui-basic-secret` | `AUTH_BASIC_PASS` | Basic auth password |

---

## Upgrade

```bash
# OpenShift
helm upgrade audit-radar ./Helm/audit-radar-openshift

# Kubernetes
helm upgrade audit-radar ./Helm/audit-radar-k8s
```

---

## Uninstall

```bash
# OpenShift
helm uninstall audit-radar
oc delete namespace audit-vision
oc delete clusterrole audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector
oc delete clusterrolebinding audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector
oc delete oauthclient audit-radar

# Kubernetes
helm uninstall audit-radar
kubectl delete namespace audit-vision
kubectl delete clusterrole audit-vision-collector
kubectl delete clusterrolebinding audit-vision-collector
```

---

## Docker Images

All images are public on Docker Hub:

| Image | Link |
|-------|------|
| audit-ui | [hybrid2k3/audit-ui](https://hub.docker.com/r/hybrid2k3/audit-ui) |
| audit-collector | [hybrid2k3/audit-collector](https://hub.docker.com/r/hybrid2k3/audit-collector) |
| audit-analyzer | [hybrid2k3/audit-analyzer](https://hub.docker.com/r/hybrid2k3/audit-analyzer) |
| audit-alerter | [hybrid2k3/audit-alerter](https://hub.docker.com/r/hybrid2k3/audit-alerter) |

---

## License

Apache 2.0
