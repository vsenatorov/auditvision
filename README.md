# Audit Radar

**Real-time audit log explorer for OpenShift**

Audit Radar collects, stores, and visualizes Kubernetes API audit events. It shows you who did what, when, and where across your cluster — with AI-powered risk scoring, anomaly detection, and webhook alerting.

Built for Red Hat OpenShift 4.x.

---

## Features

- **Live event stream** — real-time audit log feed with filtering by actor, namespace, verb, resource, and risk level
- **AI risk scoring** — every event scored by IBM Granite 3.2 running locally via Ollama; no data leaves the cluster
- **Alert rules** — configurable webhook alerts to Slack and email (human DELETE, HIGH risk events, custom rules)
- **Exclusion filters** — drop noisy service account traffic before it hits the database
- **OCP OAuth2** — single sign-on with OpenShift groups (`audit-radar-admins`, `audit-radar-editors`, viewer)
- **CSV export** — export filtered events for compliance reporting
- **SOC2 / PCI ready** — full audit trail of human and system actions across all namespaces

---

## Architecture

```
kube-apiserver
      │  audit events
      ▼
ClusterLogForwarder (OpenShift Logging)
      │  HTTP POST
      ▼
audit-collector   ──── PostgreSQL
      │                    │
      │              audit-analyzer (Granite 3.2 via Ollama)
      │              audit-alerter  (Slack / email)
      ▼
  audit-ui  ◄──── OCP OAuth2 / basic auth
      │
   browser
```

| Component | Image | Description |
|-----------|-------|-------------|
| audit-ui | `hybrid2k3/audit-ui` | Go HTTP server — UI, API, settings |
| audit-collector | `hybrid2k3/audit-collector` | Receives events from CLF, normalizes, stores |
| audit-analyzer | `hybrid2k3/audit-analyzer` | AI risk scoring via Granite 3.2 |
| audit-alerter | `hybrid2k3/audit-alerter` | Slack/email alerts on rules |
| ollama | `ollama/ollama` | Local LLM runtime |
| postgres | `registry.redhat.io/rhel9/postgresql-15` | Event storage |

---

## Install — Helm (recommended)

### Prerequisites

- OpenShift 4.x with cluster-admin
- Helm 3.x (`curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash`)

### 1. Install OpenShift Logging operator

```bash
oc apply -f deploy/04b-logging-operator.yaml
# Wait ~2-3 minutes for the operator to reach Succeeded
oc get csv -n openshift-logging -w
```

### 2. Deploy Audit Radar

```bash
helm install audit-radar ./Helm/audit-radar
```

All secrets (PostgreSQL password, OAuth client secret, basic auth password) are generated automatically from the release name — no manual secret management required.

### 3. Apply cluster-level configuration

```bash
# Cluster Log Forwarder — sends audit events to the collector
oc apply -f deploy/05-clf.yaml
```

```bash
# APIServer audit policy — enables WriteRequestBodies for full field-level change capture
# ⚠ WARNING: This triggers a rolling restart of all kube-apiserver pods.
# The cluster remains fully available during the restart but it takes 5-10 minutes.
# Monitor progress with: oc get pods -n openshift-kube-apiserver -w
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

## Install — Manual (without Helm)

If Helm is not available, all components can be applied individually with `oc apply`.

### 1. Install OpenShift Logging operator

```bash
oc apply -f deploy/04b-logging-operator.yaml
oc get csv -n openshift-logging -w   # wait for Succeeded
```

### 2. Edit secrets before applying

Before applying, replace placeholder values in `deploy/12-oauth.yaml`:

```bash
# Generate OAuth client secret
SECRET=$(openssl rand -hex 32)
# Replace REPLACE_WITH_RANDOM_SECRET in deploy/12-oauth.yaml with $SECRET
```

### 3. Deploy the stack

```bash
oc apply -f deploy/00-namespace.yaml
oc apply -f deploy/01-postgres.yaml
oc apply -f deploy/11-rbac.yaml
oc apply -f deploy/12-oauth.yaml
oc apply -f deploy/02-collector.yaml
oc apply -f deploy/03-ui.yaml
oc apply -f deploy/08-ollama.yaml    # pulls granite3.2:2b (~1.5GB) — takes a while
oc apply -f deploy/09-analyzer.yaml
oc apply -f deploy/10-alerter.yaml

# Create basic auth secret
oc create secret generic audit-ui-basic-secret \
  --from-literal=AUTH_BASIC_USER=admin \
  --from-literal=AUTH_BASIC_PASS=yourpassword \
  -n audit-vision
```

### 4. Apply cluster-level configuration

```bash
oc apply -f deploy/05-clf.yaml
```

```bash
# ⚠ WARNING: Triggers a rolling restart of kube-apiserver pods (5-10 min).
# Cluster stays available. Monitor with: oc get pods -n openshift-kube-apiserver -w
oc apply -f deploy/07-apiserver-audit.yaml
```

### 5. Add admin users

```bash
oc adm groups new audit-radar-admins
oc adm groups new audit-radar-editors
oc adm groups add-users audit-radar-admins <your-username>
```

---

## About the APIServer Audit Policy

Applying `deploy/07-apiserver-audit.yaml` enables the `WriteRequestBodies` audit profile for the `audit-write-users` group. This allows Audit Radar to capture field-level changes — for example, showing that a Deployment's replica count changed from 3 to 1, or that an image tag was updated.

**What happens when you apply it:**

- OpenShift performs a rolling restart of all `kube-apiserver` pods
- This takes approximately 5-10 minutes on a standard 3-master cluster
- The cluster remains fully available during the restart — workloads are not affected
- Monitor the rollout with: `oc get pods -n openshift-kube-apiserver -w`

**Without this policy**, Audit Radar still works — you get full actor/verb/resource/result visibility, but without request body diffs.

---

## Configuration

All configuration is in `Helm/audit-radar/values.yaml`.

| Parameter | Default | Description |
|-----------|---------|-------------|
| `namespace` | `audit-vision` | Target namespace |
| `postgres.user` | `auditvision` | PostgreSQL user |
| `postgres.storage` | `10Gi` | PVC size for PostgreSQL |
| `collector.retentionDays` | `30` | Event retention in days (0 = disabled) |
| `ui.auth.clientId` | `audit-radar` | OCP OAuth client ID |
| `ui.auth.adminGroup` | `audit-radar-admins` | OCP group for admin role |
| `ui.auth.editorGroup` | `audit-radar-editors` | OCP group for editor role |
| `ui.auth.basicUser` | `admin` | Basic auth username |
| `ollama.enabled` | `true` | Deploy Ollama + AI analyzer |
| `ollama.model` | `granite3.2:2b` | Model to pull (~1.5GB) |
| `ollama.storageClassName` | `ocs-external-storagecluster-ceph-rbd` | StorageClass for model PVC |
| `alerter.slack.webhookUrl` | `""` | Slack incoming webhook URL |
| `alerter.smtp.host` | `""` | SMTP host for email alerts |

### Disable AI analyzer (resource-constrained clusters)

```bash
helm install audit-radar ./Helm/audit-radar \
  --set ollama.enabled=false \
  --set analyzer.enabled=false
```

---

## Role Mapping

| OCP Group | Audit Radar Role | Access |
|-----------|-----------------|--------|
| `audit-radar-admins` | admin | Full access including settings |
| `audit-radar-editors` | editor | Alert rules, no settings |
| Any authenticated OCP user | viewer | Read-only event stream |
| Unauthenticated | — | Redirect to login |

```bash
# Grant admin access
oc adm groups add-users audit-radar-admins alice

# Grant editor access
oc adm groups add-users audit-radar-editors bob

# Any other OCP user gets viewer role automatically — no group needed
```

---

## Exclusion Filters

Noisy service account traffic (cert-manager, OLM, monitoring) can be dropped before it hits the database using exclusion rules in the Settings UI.

![Exclusion Filters](docs/images/exclusion-filters.png)

Filters support wildcard actor matching:

```
system:serviceaccount:cert-manager:*
system:serviceaccount:openshift-*
```

The collector reloads rules every 30 seconds — no restart required.

---
---

## Secrets & Passwords

All secrets are auto-generated on first `helm install` and stored in Kubernetes Secrets in the `audit-vision` namespace. No passwords appear in `values.yaml` or the command line.

### What gets generated

| Secret | Key | Used by | Description |
|--------|-----|---------|-------------|
| `postgres-secret` | `POSTGRESQL_PASSWORD` | postgres, collector, ui, analyzer, alerter | PostgreSQL password |
| `audit-ui-oauth-secret` | `AUTH_CLIENT_SECRET` | audit-ui, OAuthClient | OCP OAuth2 client secret |
| `audit-ui-basic-secret` | `AUTH_BASIC_PASS` | audit-ui | Basic auth fallback password |

Secrets are derived deterministically from the Helm release name — upgrades never rotate credentials unexpectedly.

### View current passwords

```bash
# PostgreSQL password
oc get secret postgres-secret -n audit-vision -o jsonpath='{.data.POSTGRESQL_PASSWORD}' | base64 -d

# Basic auth password
oc get secret audit-ui-basic-secret -n audit-vision -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d
```

### Change the basic auth password

```bash
oc create secret generic audit-ui-basic-secret \
  --from-literal=AUTH_BASIC_USER=admin \
  --from-literal=AUTH_BASIC_PASS=yournewpassword \
  -n audit-vision \
  --dry-run=client -o yaml | oc apply -f -

# Restart UI to pick up the new secret (~10 seconds)
oc rollout restart deployment/audit-ui -n audit-vision
```

### Change the PostgreSQL password

```bash
# 1. Update the secret
oc create secret generic postgres-secret \
  --from-literal=POSTGRESQL_USER=auditvision \
  --from-literal=POSTGRESQL_PASSWORD=yournewpassword \
  --from-literal=POSTGRESQL_DATABASE=auditvision \
  --from-literal=DATABASE_URL="postgres://auditvision:yournewpassword@postgres:5432/auditvision?sslmode=disable" \
  -n audit-vision \
  --dry-run=client -o yaml | oc apply -f -

# 2. Update the password inside PostgreSQL itself
oc exec -it deployment/postgres -n audit-vision -- \
  psql -U auditvision -c "ALTER USER auditvision WITH PASSWORD 'yournewpassword';"

# 3. Restart all components
oc rollout restart deployment/audit-collector deployment/audit-ui deployment/audit-analyzer deployment/audit-alerter -n audit-vision
```

---

## Alerting Configuration

### Slack

1. Go to your Slack workspace → **Apps** → **Incoming Webhooks** → **Add to Slack**
2. Choose a channel and copy the webhook URL
3. Update the ConfigMap:

```bash
oc patch configmap audit-alerter-config -n audit-vision \
  --type=merge -p '{"data":{"ALERT_SLACK_WEBHOOK":"https://hooks.slack.com/services/T.../B.../xxx"}}'

oc rollout restart deployment/audit-alerter -n audit-vision
```

### Email (SMTP)

```bash
oc patch configmap audit-alerter-config -n audit-vision --type=merge -p '{
  "data": {
    "ALERT_SMTP_HOST": "smtp.gmail.com",
    "ALERT_SMTP_PORT": "587",
    "ALERT_SMTP_USER": "alerts@yourcompany.com",
    "ALERT_EMAIL_FROM": "audit-radar@yourcompany.com",
    "ALERT_EMAIL_TO": "security@yourcompany.com"
  }
}'

# SMTP password goes into the Secret
oc create secret generic audit-alerter-secret \
  --from-literal=ALERT_SMTP_PASS=yoursmtppassword \
  -n audit-vision \
  --dry-run=client -o yaml | oc apply -f -

oc rollout restart deployment/audit-alerter -n audit-vision
```

> **Gmail:** use an [App Password](https://support.google.com/accounts/answer/185833) instead of your account password.

### Alert rules

Two built-in rules are active by default:

| Rule | ConfigMap key | Default |
|------|--------------|--------|
| Alert on HIGH risk events (Granite scored) | `ALERT_ON_HIGH` | `true` |
| Alert on human DELETE actions | `ALERT_ON_HUMAN_DELETE` | `true` |

Custom rules can be configured from **Settings → Alert Rules** in the UI — no restart required.

---

## Upgrade
## Upgrade

```bash
helm upgrade audit-radar ./Helm/audit-radar
```

---

## Uninstall

```bash
helm uninstall audit-radar
oc delete namespace audit-vision

# Cluster-scoped resources
oc delete clusterrole audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector
oc delete clusterrolebinding audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector audit-vision-collector-audit-logs
oc delete oauthclient audit-radar
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
