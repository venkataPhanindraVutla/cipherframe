# Template only. Copy to terraform.tfvars (ignored by version control) and replace every
# dev-placeholder- value.
project_id  = "dev-placeholder-project"
region      = "europe-west1"
name_prefix = "cipherframe"

# GKE Workload Identity: one Kubernetes service account per role.
workload_identity_members = {
  api    = ["serviceAccount:dev-placeholder-project.svc.id.goog[cipherframe/api]"]
  edge   = ["serviceAccount:dev-placeholder-project.svc.id.goog[cipherframe/edge]"]
  worker = ["serviceAccount:dev-placeholder-project.svc.id.goog[cipherframe/worker]"]
}

# bucket_versioning               = false
# abort_incomplete_multipart_days = 0
# cors_allowed_origins            = []
# create_hmac_keys                = false # secrets would be kept in Terraform state
