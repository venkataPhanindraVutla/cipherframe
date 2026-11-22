{{- define "cipherframe.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- $n := default .Chart.Name .Values.nameOverride -}}
{{- if contains $n .Release.Name -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $n | trunc 50 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end }}

{{/* Selector labels. Args: dict "root" . "role" "api". */}}
{{- define "cipherframe.selector" -}}
app.kubernetes.io/name: {{ default .root.Chart.Name .root.Values.nameOverride }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .role }}
{{- end }}

{{- define "cipherframe.labels" -}}
{{ include "cipherframe.selector" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" }}
{{- end }}

{{/* Image reference. Args: dict "root" . "img" .Values.image.server. A digest wins over the tag. */}}
{{- define "cipherframe.image" -}}
{{- if .img.digest -}}
{{- printf "%s@%s" .img.repository .img.digest -}}
{{- else -}}
{{- printf "%s:%s" .img.repository (default .root.Chart.AppVersion .img.tag) -}}
{{- end -}}
{{- end }}

{{/* Volume name of a secret variable: CIPHERFRAME_API_KEY_PEPPERS -> s-api-key-peppers. */}}
{{- define "cipherframe.secretVolume" -}}
{{- printf "s-%s" (. | lower | replace "_" "-" | trimPrefix "cipherframe-") -}}
{{- end }}

{{/* Secrets of a role as YAML: the common ones overlaid with the role's own. Args: dict "root" . "role" "api". */}}
{{- define "cipherframe.secrets" -}}
{{- $r := get .root.Values .role -}}
{{- mergeOverwrite (deepCopy .root.Values.secrets) (deepCopy (default (dict) $r.secrets)) | toYaml -}}
{{- end }}

{{/* env entries. Args: dict "env" map "secrets" map. Secrets become NAME_FILE variables. */}}
{{- define "cipherframe.env" -}}
{{- range $k, $v := .env }}
- name: {{ $k }}
  value: {{ $v | toString | quote }}
{{- end }}
{{- range $k, $_ := .secrets }}
- name: {{ $k }}_FILE
  value: {{ printf "/var/run/cipherframe/secrets/%s/value" (include "cipherframe.secretVolume" $k) | quote }}
{{- end }}
{{- end }}

{{- define "cipherframe.secretMounts" -}}
{{- range $k, $_ := . }}
- name: {{ include "cipherframe.secretVolume" $k }}
  mountPath: {{ printf "/var/run/cipherframe/secrets/%s" (include "cipherframe.secretVolume" $k) }}
  readOnly: true
{{- end }}
{{- end }}

{{- define "cipherframe.secretVolumes" -}}
{{- range $k, $ref := . }}
- name: {{ include "cipherframe.secretVolume" $k }}
  secret:
    secretName: {{ $ref.name | quote }}
    defaultMode: 0440
    items:
      - key: {{ $ref.key | quote }}
        path: value
{{- end }}
{{- end }}

{{/* Whether a role is scaled by an autoscaler, so the Deployment leaves replicas alone. */}}
{{- define "cipherframe.autoscaled" -}}
{{- $r := get .root.Values .role -}}
{{- if or (and $r.autoscaling $r.autoscaling.enabled) (and $r.keda $r.keda.enabled) }}true{{ end -}}
{{- end }}
