# audit-radar Helm Chart

Real-time OpenShift audit log explorer with AI risk scoring and alerting.

**Platform:** OpenShift 4.x only. For Kubernetes/k3s see `deploy-k8s/`.

## Prerequisites

- OpenShift 4.x cluster with cluster-admin
- Helm 3.x
- `registry.redhat.io` pull access (for PostgreSQL image)

## Quick Install

```bash
# 1. Create OCP groups and add users
oc adm groups new audit-radar-admins
oc adm groups new audit-radar-editors
oc adm groups add-users audit-radar-admins <your-username>

# 2. Generate OAuth client secret
SECRET=$(openssl rand -hex 32)

# 3. Install
helm install audit-radar ./audit-radar \
  --set ui.auth.clientSecret=$SECRET \
  --set ui.auth.basicPass=yourpassword \
  --set postgres.password=yourdbpassword

# 4. Get the UI URL
oc get route audit-ui -n audit-vision
```

## Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace` | Target namespace | `audit-vision` |
| `postgres.password` | PostgreSQL password | `changeme` |
| `postgres.storage` | PVC size | `10Gi` |
| `collector.retentionDays` | Event retention (0 = disabled) | `30` |
| `ui.auth.clientSecret` | OCP OAuth client secret | `""` |
| `ui.auth.clientId` | OCP OAuth client ID | `audit-radar` |
| `ui.auth.adminGroup` | OCP group for admin role | `audit-radar-admins` |
| `ui.auth.editorGroup` | OCP group for editor role | `audit-radar-editors` |
| `ui.auth.basicUser` | Basic auth username | `admin` |
| `ui.auth.basicPass` | Basic auth password | `changeme` |
| `ollama.enabled` | Deploy Ollama + AI analyzer | `true` |
| `ollama.model` | Granite model to pull | `granite3.2:2b` |
| `ollama.storageClassName` | StorageClass for model PVC | `ocs-external-storagecluster-ceph-rbd` |
| `alerter.slack.webhookUrl` | Slack incoming webhook URL | `""` |
| `alerter.smtp.host` | SMTP host for email alerts | `""` |
| `clf.enabled` | Deploy Cluster Log Forwarder | `true` |
| `clf.installOperator` | Install OpenShift Logging operator | `true` |
| `auditPolicy.enabled` | Apply APIServer audit policy | `true` |
| `oauth.redirectURI` | OAuthClient redirect URI (auto-synced if empty) | `""` |

## Disable optional components

```bash
# Without AI analyzer (no GPU/Ollama)
helm install audit-radar ./audit-radar \
  --set ollama.enabled=false \
  --set analyzer.enabled=false \
  --set ui.auth.clientSecret=$SECRET

# Without alerting
helm install audit-radar ./audit-radar \
  --set alerter.enabled=false \
  --set ui.auth.clientSecret=$SECRET
```

## Upgrade

```bash
helm upgrade audit-radar ./audit-radar --reuse-values \
  --set ui.auth.clientSecret=$SECRET
```

## Uninstall

```bash
helm uninstall audit-radar
oc delete namespace audit-vision
# ClusterRoles and ClusterRoleBindings are cluster-scoped — delete manually:
oc delete clusterrole audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector
oc delete clusterrolebinding audit-ui-groups-reader audit-ui-oauth-sync audit-vision-collector
oc delete oauthclient audit-radar
```
