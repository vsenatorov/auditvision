# Audit Radar

<p align="center">
  <img src="https://audit-radar.com/logo.svg" alt="Audit Radar" width="80"/>
</p>

<p align="center">
  <strong>Real-time audit log explorer for OpenShift and Kubernetes</strong><br>
  Who did what, when — across your entire cluster. With AI risk scoring and login tracking.
</p>

<p align="center">
  <a href="https://audit-radar.com">🌐 audit-radar.com</a> ·
  <a href="https://hub.docker.com/u/hybrid2k3">Docker Hub</a> ·
  <a href="LICENSE">Apache 2.0</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/OpenShift-4.x-red?logo=redhatopenshift&logoColor=white"/>
  <img src="https://img.shields.io/badge/Kubernetes-1.24+-blue?logo=kubernetes&logoColor=white"/>
  <img src="https://img.shields.io/badge/license-Apache%202.0-green"/>
  <img src="https://img.shields.io/docker/pulls/hybrid2k3/audit-ui?label=Docker%20pulls"/>
</p>

---

> **The problem:** `kubectl get events` shows nothing useful. Enabling audit logs gives you gigabytes of JSON. You want to know who deleted that deployment at 2am — without writing log queries.
>
> **Audit Radar** collects kube-apiserver audit events, enriches them with AI risk scoring, and gives you a live filterable UI. No Elasticsearch, no Kibana, no log management platform required.

---

## Screenshot

![Audit Radar — live event stream](https://raw.githubusercontent.com/vsenatorov/auditvision/main/docs/images/post-logo.png)

*Live audit event stream with AI risk assessment — OpenShift cluster*

---

## Features

| | |
|---|---|
| 🔴 **Live event stream** | Real-time audit feed — filter by actor, namespace, verb, resource, risk level |
| 🤖 **AI risk scoring** | Every event scored HIGH/MEDIUM/LOW by IBM Granite 3.2 via Ollama — runs inside the cluster, no data leaves |
| 🔐 **Login tracking** | Dedicated Logins tab — who logged in, when, from where, via Web Console or CLI |
| 🔔 **Webhook alerts** | Slack and email rules — e.g. "DELETE in namespace production → alert #ops" |
| 📊 **Summary dashboard** | Aggregated view: top actors, risky events, verb breakdown |
| 📥 **CSV export** | Export filtered events for compliance reporting |
| 🚫 **Exclusion filters** | Drop noisy service account traffic before it hits the database |
| 🔑 **OCP OAuth2 SSO** | Login with OpenShift groups (`audit-radar-admins`, `audit-radar-editors`, viewer) |
| 🔑 **Basic auth** | Username/password fallback — works on both OCP and plain Kubernetes |

**SOC2 / PCI ready** — full audit trail of human and system actions across all namespaces.

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

Two separate charts — one per platform:

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

### 6. Get the admin password

```bash
oc get secret audit-ui-basic-secret -n audit-vision \
  -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d && echo
```

Login with `admin` and the password above.

---

## Install on Kubernetes / k3s

### Prerequisites

- Kubernetes 1.24+ or k3s with cluster-admin
- Helm 3.x
- Audit logging enabled on kube-apiserver

### 1. Enable audit logging

Audit Radar requires the kube-apiserver to write audit logs to a file on the node. Refer to your distribution's documentation. The audit log path must match `vector.auditLogPath` in values (default: `/var/log/k3s-audit.log`).

Example audit policy is included in `deploy-k8s/audit-policy.yaml`.

### 2. Deploy Audit Radar

```bash
helm install audit-radar ./Helm/audit-radar-k8s \
  --set ui.ingress.host=audit.192.168.10.30.nip.io
```

### 3. Open the UI

```bash
kubectl get ingress -n audit-vision
```

### 4. Get the admin password

```bash
kubectl get secret audit-ui-basic-secret -n audit-vision \
  -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d && echo
```

Login with `admin` and the password above.

---

## Default Credentials

> ⚠ **Change the basic auth password before exposing the UI externally.**

The Helm chart auto-generates a password on install. Retrieve it with the commands in the install section above, or:

```bash
# OpenShift
oc get secret audit-ui-basic-secret -n audit-vision \
  -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d && echo

# Kubernetes
kubectl get secret audit-ui-basic-secret -n audit-vision \
  -o jsonpath='{.data.AUTH_BASIC_PASS}' | base64 -d && echo
```

When installed **without Helm**, default credentials are `admin` / `changeme` — change immediately.

---

## Role Mapping

### OpenShift

| Source | Role | Access |
|--------|------|--------|
| OCP group `audit-radar-admins` | admin | Full access including settings |
| OCP group `audit-radar-editors` | editor | Alert rules, no settings |
| Any authenticated OCP user | viewer | Read-only event stream |
| Basic auth user | admin | Full access |

```bash
oc adm groups add-users audit-radar-admins alice
oc adm groups add-users audit-radar-editors bob
```

### Kubernetes

Single basic auth user. Multi-user support with individual roles requires an OIDC provider (Keycloak, Dex).

---

## Configuration

### Key parameters — OpenShift

| Parameter | Default | Description |
|-----------|---------|-------------|
| `collector.retentionDays` | `30` | Event retention in days |
| `ui.auth.adminGroup` | `audit-radar-admins` | OCP group for admin role |
| `ollama.enabled` | `true` | Deploy AI analyzer |
| `ollama.model` | `granite3.2:2b` | Model (~1.5GB) |
| `alerter.slack.webhookUrl` | `""` | Slack incoming webhook URL |

### Key parameters — Kubernetes

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ui.ingress.host` | `audit.192.168.10.30.nip.io` | Ingress hostname — **change this** |
| `vector.auditLogPath` | `/var/log/k3s-audit.log` | Path to audit log on host |
| `ollama.enabled` | `true` | Deploy AI analyzer |

### Disable AI analyzer (resource-constrained clusters)

```bash
helm install audit-radar ./Helm/audit-radar-k8s \
  --set ollama.enabled=false \
  --set analyzer.enabled=false
```

---

## Exclusion Filters

Drop noisy service account traffic in **Settings → Exclusion Filters**. Wildcard matching supported:

```
system:serviceaccount:cert-manager:*
system:serviceaccount:openshift-*
```

Rules reload every 30 seconds — no restart required.

---

## Upgrade / Uninstall

```bash
# Upgrade
helm upgrade audit-radar ./Helm/audit-radar-openshift   # or audit-radar-k8s

# Uninstall — OpenShift
helm uninstall audit-radar
oc delete namespace audit-vision
oc delete clusterrole audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector
oc delete clusterrolebinding audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector
oc delete oauthclient audit-radar

# Uninstall — Kubernetes
helm uninstall audit-radar
kubectl delete namespace audit-vision
kubectl delete clusterrole audit-vision-collector
kubectl delete clusterrolebinding audit-vision-collector
```

---

## Docker Images

| Image | Link |
|-------|------|
| audit-ui | [hybrid2k3/audit-ui](https://hub.docker.com/r/hybrid2k3/audit-ui) |
| audit-collector | [hybrid2k3/audit-collector](https://hub.docker.com/r/hybrid2k3/audit-collector) |
| audit-analyzer | [hybrid2k3/audit-analyzer](https://hub.docker.com/r/hybrid2k3/audit-analyzer) |
| audit-alerter | [hybrid2k3/audit-alerter](https://hub.docker.com/r/hybrid2k3/audit-alerter) |

---

## License

Apache 2.0
