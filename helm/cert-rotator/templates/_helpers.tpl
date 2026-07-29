{{/*
Expand the name of the chart.
*/}}
{{- define "cert-rotator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Full name — used for resource names.
*/}}
{{- define "cert-rotator.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Chart label — used in selector labels.
*/}}
{{- define "cert-rotator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "cert-rotator.labels" -}}
helm.sh/chart: {{ include "cert-rotator.chart" . }}
{{ include "cert-rotator.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — used in DaemonSet matchLabels and pod template labels.
*/}}
{{- define "cert-rotator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cert-rotator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "cert-rotator.serviceAccountName" -}}
{{- if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- include "cert-rotator.fullname" . }}
{{- end }}
{{- end }}

{{/*
Namespace — all resources go here.
*/}}
{{- define "cert-rotator.namespace" -}}
{{- default "cert-rotator-system" .Values.namespace }}
{{- end }}
