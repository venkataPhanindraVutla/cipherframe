output "s3_endpoint" {
  description = "CIPHERFRAME_S3_ENDPOINT (the GCS S3-compatible XML API)"
  value       = "https://storage.googleapis.com"
}

output "s3_source_bucket" {
  description = "CIPHERFRAME_S3_SOURCE_BUCKET"
  value       = google_storage_bucket.this["source"].name
}

output "s3_delivery_bucket" {
  description = "CIPHERFRAME_S3_DELIVERY_BUCKET"
  value       = google_storage_bucket.this["delivery"].name
}

output "kms_gcp_key_name" {
  description = "CIPHERFRAME_KMS_GCP_KEY_NAME"
  value       = google_kms_crypto_key.kek.id
}

output "service_account_emails" {
  description = "Service account email per server role."
  value       = { for k, sa in google_service_account.this : k => sa.email }
}

output "hmac_access_ids" {
  description = "CIPHERFRAME_S3_ACCESS_KEY_ID per server role, when create_hmac_keys is true. Not secret."
  value       = { for k, h in google_storage_hmac_key.this : k => h.access_id }
}

output "hmac_secrets" {
  description = "CIPHERFRAME_S3_SECRET_ACCESS_KEY per server role, when create_hmac_keys is true. Read it with terraform output -json hmac_secrets and put it straight into a secret store."
  value       = { for k, h in google_storage_hmac_key.this : k => h.secret }
  sensitive   = true
}
