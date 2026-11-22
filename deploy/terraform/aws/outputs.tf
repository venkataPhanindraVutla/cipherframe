output "s3_region" {
  description = "CIPHERFRAME_S3_REGION"
  value       = var.region
}

output "s3_source_bucket" {
  description = "CIPHERFRAME_S3_SOURCE_BUCKET"
  value       = aws_s3_bucket.this["source"].bucket
}

output "s3_delivery_bucket" {
  description = "CIPHERFRAME_S3_DELIVERY_BUCKET"
  value       = aws_s3_bucket.this["delivery"].bucket
}

output "kms_aws_key_id" {
  description = "CIPHERFRAME_KMS_AWS_KEY_ID (the alias ARN, so re-pointing the alias to a new key needs no config change)"
  value       = aws_kms_alias.kek.arn
}

output "kms_aws_region" {
  description = "CIPHERFRAME_KMS_AWS_REGION"
  value       = var.region
}

output "role_arns" {
  description = "IAM role ARN per server role, for the pod or instance that runs it."
  value       = { for k, r in aws_iam_role.this : k => r.arn }
}
