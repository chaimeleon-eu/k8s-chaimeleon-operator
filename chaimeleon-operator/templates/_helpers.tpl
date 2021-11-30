{{/*
Expand the name of the chart.
*/}}
{{- define "chaimeleon-operator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "chaimeleon-operator.fullname" -}}
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
{{- define "chaimeleon-operator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "chaimeleon-operator.labels" -}}
helm.sh/chart: {{ include "chaimeleon-operator.chart" . }}
{{ include "chaimeleon-operator.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "chaimeleon-operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "chaimeleon-operator.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "chaimeleon-operator.serviceAccountName" -}}
{{- default (include "chaimeleon-operator.fullname" .) .Values.serviceAccount.name -}}
{{- end }}


{{/*
Create the name of the role
*/}}
{{- define "chaimeleon-operator.roleName" -}}
{{- default "chaimeleon-operator-role-namespaced" .Values.rbac.role.name -}}
{{- end }}

{{/*
Create the name of the ClusterRole
*/}}
{{- define "chaimeleon-operator.clusterRoleName" -}}
{{- default "chaimeleon-operator-role-cluster" .Values.rbac.clusterRole.name -}}
{{- end }}

{{/*
Create the name of the roleBinding
*/}}
{{- define "chaimeleon-operator.roleBindingName" -}}
{{- default "chaimeleon-operator-roleBinding" .Values.rbac.roleBinding.name -}}
{{- end }}

{{/*
Create the name of the ClusterRoleBinding
*/}}
{{- define "chaimeleon-operator.clusterRoleBindingName" -}}
{{- default "chaimeleon-operator-clusterRoleBinding" .Values.rbac.clusterRoleBinding.name -}}
{{- end }}

{{/*
Create the name of k8s prefix
*/}}
{{- define "chaimeleon-operator.k8sUserPrefix" -}}
{{- default "" .Values.operatorConfiguration.k8sUserPrefix -}}
{{- end }}