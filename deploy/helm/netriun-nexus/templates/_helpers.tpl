{{- define "netriun-nexus.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "netriun-nexus.serviceName" -}}
{{- default (include "netriun-nexus.fullname" .) .Values.service.name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "netriun-nexus.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "netriun-nexus.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "netriun-nexus.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
app.kubernetes.io/name: {{ include "netriun-nexus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "netriun-nexus.selectorLabels" -}}
app.kubernetes.io/name: {{ include "netriun-nexus.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "netriun-nexus.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "netriun-nexus.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
