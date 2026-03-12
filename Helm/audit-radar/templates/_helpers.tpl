{{/*
Expand the name of the chart.
*/}}
{{- define "audit-radar.name" -}}
{{- .Chart.Name }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "audit-radar.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/part-of: audit-vision
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Postgres password — from values or auto-generated once via Release.Name seed
*/}}
{{- define "audit-radar.postgresPassword" -}}
{{- if .Values.postgres.password -}}
{{- .Values.postgres.password }}
{{- else -}}
{{- cat .Release.Name "pg" | sha256sum | trunc 16 }}
{{- end -}}
{{- end }}

{{/*
OAuth client secret — from values or auto-generated once via Release.Name seed
*/}}
{{- define "audit-radar.oauthSecret" -}}
{{- if .Values.ui.auth.clientSecret -}}
{{- .Values.ui.auth.clientSecret }}
{{- else -}}
{{- cat .Release.Name "oauth" | sha256sum | trunc 32 }}
{{- end -}}
{{- end }}

{{/*
Basic auth password — from values or auto-generated once via Release.Name seed
*/}}
{{- define "audit-radar.basicPass" -}}
{{- if .Values.ui.auth.basicPass -}}
{{- .Values.ui.auth.basicPass }}
{{- else -}}
{{- cat .Release.Name "basic" | sha256sum | trunc 16 }}
{{- end -}}
{{- end }}

{{/*
Postgres DATABASE_URL
*/}}
{{- define "audit-radar.databaseURL" -}}
postgres://{{ .Values.postgres.user }}:{{ include "audit-radar.postgresPassword" . }}@postgres:5432/{{ .Values.postgres.database }}?sslmode=disable
{{- end }}
