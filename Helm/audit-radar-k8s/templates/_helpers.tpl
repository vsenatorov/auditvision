{{/*
Common labels
*/}}
{{- define "audit-radar.labels" -}}
app.kubernetes.io/part-of: audit-vision
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{/*
Postgres password — deterministic from release name, stable across upgrades
*/}}
{{- define "audit-radar.postgresPassword" -}}
{{- sha256sum (printf "%s-postgres" .Release.Name) | trunc 32 }}
{{- end }}

{{/*
Basic auth password — deterministic from release name
*/}}
{{- define "audit-radar.basicPass" -}}
{{- sha256sum (printf "%s-basic" .Release.Name) | trunc 24 }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "audit-radar.databaseURL" -}}
{{- printf "postgres://%s:%s@postgres:5432/%s?sslmode=disable" .Values.postgres.user (include "audit-radar.postgresPassword" .) .Values.postgres.database }}
{{- end }}
