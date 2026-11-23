# Template only. Copy to terraform.tfvars (ignored by version control) and replace every
# dev-placeholder- value. Each role gets its own trust policy; these are IRSA examples. The README
# shows the EC2 instance profile variant.
region      = "eu-west-1"
name_prefix = "dev-placeholder-cipherframe"

assume_role_policies = {
  api    = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::111111111111:oidc-provider/dev-placeholder-oidc.example.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"dev-placeholder-oidc.example.com:sub\":\"system:serviceaccount:cipherframe:api\"}}}]}"
  edge   = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::111111111111:oidc-provider/dev-placeholder-oidc.example.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"dev-placeholder-oidc.example.com:sub\":\"system:serviceaccount:cipherframe:edge\"}}}]}"
  worker = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Federated\":\"arn:aws:iam::111111111111:oidc-provider/dev-placeholder-oidc.example.com\"},\"Action\":\"sts:AssumeRoleWithWebIdentity\",\"Condition\":{\"StringEquals\":{\"dev-placeholder-oidc.example.com:sub\":\"system:serviceaccount:cipherframe:worker\"}}}]}"
}

# bucket_versioning               = false
# bucket_kms_key_arn              = null # null uses SSE-S3
# abort_incomplete_multipart_days = 0
# cors_allowed_origins            = []
# enable_cdn                      = false # CloudFront in front of the delivery bucket (docs/cdn.md)
# cdn_public_key_pem              = null  # the public half of the CDN URL signing key
