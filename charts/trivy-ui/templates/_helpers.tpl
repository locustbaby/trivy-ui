{{/*
Expand the name of the chart.
*/}}
{{- define "trivy-ui.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "trivy-ui.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "trivy-ui.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "trivy-ui.labels" -}}
helm.sh/chart: {{ include "trivy-ui.chart" . }}
{{ include "trivy-ui.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "trivy-ui.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trivy-ui.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "trivy-ui.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "trivy-ui.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the namespace name
*/}}
{{- define "trivy-ui.namespace" -}}
{{- default .Release.Namespace .Values.namespace }}
{{- end }}

{{- define "trivy-ui.authSecretChecksum" -}}
{{- $secret := lookup "v1" "Secret" (include "trivy-ui.namespace" .) .Values.auth.local.existingSecret -}}
{{- if $secret }}{{ sha256sum (toJson $secret.data) }}{{ else }}{{ .Values.auth.local.existingSecret | sha256sum }}{{ end }}
{{- end }}

{{- define "trivy-ui.kubeconfigSecretChecksum" -}}
{{- $secret := lookup "v1" "Secret" (include "trivy-ui.namespace" .) .Values.kubeconfigs.secretName -}}
{{- if $secret }}{{ sha256sum (toJson $secret.data) }}{{ else }}{{ toJson .Values.kubeconfigs.data | sha256sum }}{{ end }}
{{- end }}

{{- define "trivy-ui.errorPageConfig" -}}
{{- $cfg := dict "title" (.Values.customErrorPage.title | default "Security dashboard unavailable") "message" (.Values.customErrorPage.message | default "") "items" (.Values.customErrorPage.items | default list) -}}
{{- $cfg | toJson -}}
{{- end -}}

{{- define "trivy-ui.dataPath" -}}
{{- if .Values.cache.enabled }}{{ .Values.cache.mountPath | default "/cache" }}{{ else }}/tmp/trivy-ui-data{{ end -}}
{{- end -}}
