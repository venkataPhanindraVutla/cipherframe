variable "project_id" {
  description = "Google Cloud project that owns the buckets, service accounts and key."
  type        = string
}

variable "region" {
  description = "Location of the buckets and of the key ring (for example europe-west1). The key ring location is permanent."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for service account ids, the key ring and the default bucket names."
  type        = string
  default     = "cipherframe"
}

variable "source_bucket_name" {
  description = "Globally unique name of the source bucket (uploaded originals). Defaults to <name_prefix>-source-<project id>."
  type        = string
  default     = null
}

variable "delivery_bucket_name" {
  description = "Globally unique name of the delivery bucket (encrypted HLS output). Defaults to <name_prefix>-delivery-<project id>."
  type        = string
  default     = null
}

variable "bucket_versioning" {
  description = "Enable object versioning on both buckets. Off by default: purge deletes explicitly, and old versions would survive it."
  type        = bool
  default     = false
}

variable "abort_incomplete_multipart_days" {
  description = "Days after which GCS aborts an unfinished multipart upload in the source bucket. 0 (default) creates no lifecycle rule."
  type        = number
  default     = 0
}

variable "cors_allowed_origins" {
  description = "Browser origins allowed to upload to the source bucket and fetch from the delivery bucket with presigned URLs. Empty creates no CORS rule (proxy delivery needs none)."
  type        = list(string)
  default     = []
}

variable "key_rotation_period" {
  description = "Automatic rotation period of the KEK, in seconds with an s suffix. Older versions stay usable for unwrapping."
  type        = string
  default     = "7776000s"
}

variable "workload_identity_members" {
  description = "IAM members allowed to act as each server role's service account (roles/iam.workloadIdentityUser), for example serviceAccount:PROJECT.svc.id.goog[cipherframe/api] for GKE. Keys are api, edge and worker; a missing key grants nobody."
  type        = map(list(string))
  default     = {}

  validation {
    condition     = length(setsubtract(keys(var.workload_identity_members), ["api", "edge", "worker"])) == 0
    error_message = "workload_identity_members may only have the keys api, edge and worker."
  }
}

variable "create_hmac_keys" {
  description = "Create one HMAC key per service account for the S3-compatible API. Off by default; the secrets then live in Terraform state. Without it, create the keys by hand (see the README)."
  type        = bool
  default     = false
}

variable "labels" {
  description = "Labels applied to the buckets."
  type        = map(string)
  default     = {}
}
