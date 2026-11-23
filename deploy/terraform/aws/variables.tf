variable "region" {
  description = "AWS region for the buckets and the KMS key (CIPHERFRAME_S3_REGION and CIPHERFRAME_KMS_AWS_REGION)."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for IAM role names, the KMS alias and the default bucket names."
  type        = string
  default     = "cipherframe"
}

variable "source_bucket_name" {
  description = "Globally unique name of the source bucket (uploaded originals). Defaults to <name_prefix>-source-<account id>."
  type        = string
  default     = null
}

variable "delivery_bucket_name" {
  description = "Globally unique name of the delivery bucket (encrypted HLS output). Defaults to <name_prefix>-delivery-<account id>."
  type        = string
  default     = null
}

variable "bucket_versioning" {
  description = "Enable S3 versioning on both buckets. Off by default: purge deletes explicitly, and old versions would survive it."
  type        = bool
  default     = false
}

variable "bucket_kms_key_arn" {
  description = "Optional customer-managed key for S3 server-side encryption (SSE-KMS). Null uses SSE-S3. The roles are granted GenerateDataKey and Decrypt on this key. It is separate from the Cipherframe KEK created here."
  type        = string
  default     = null
}

variable "abort_incomplete_multipart_days" {
  description = "Days after which S3 aborts an unfinished multipart upload in the source bucket. 0 (default) creates no lifecycle rule."
  type        = number
  default     = 0
}

variable "cors_allowed_origins" {
  description = "Browser origins allowed to upload to the source bucket and fetch from the delivery bucket with presigned URLs. Empty creates no CORS rule (proxy delivery needs none)."
  type        = list(string)
  default     = []
}

variable "assume_role_policies" {
  description = "Trust policy (JSON) per server role: keys api, edge and worker. Use IRSA, EKS Pod Identity or an EC2 instance profile; see the README for examples."
  type        = map(string)

  validation {
    condition     = toset(keys(var.assume_role_policies)) == toset(["api", "edge", "worker"])
    error_message = "assume_role_policies needs exactly the keys api, edge and worker."
  }
}

variable "kms_deletion_window_days" {
  description = "Waiting period before a scheduled deletion of the KEK takes effect (7 to 30)."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to every resource that supports them."
  type        = map(string)
  default     = {}
}

variable "enable_cdn" {
  description = "Create a CloudFront distribution in front of the delivery bucket (CDN delivery, ADR 0062). Off by default. The source bucket is never behind it."
  type        = bool
  default     = false
}

variable "cdn_public_key_pem" {
  description = "PEM public key whose private half Cipherframe signs CDN URLs with (CIPHERFRAME_CDN_SIGNING_KEY_FILE). Required when enable_cdn is true; a public key is not a secret, the private key never goes into Terraform. It must be an RSA 2048 key."
  type        = string
  default     = null
}

variable "cdn_price_class" {
  description = "CloudFront price class of the distribution."
  type        = string
  default     = "PriceClass_100"
}
