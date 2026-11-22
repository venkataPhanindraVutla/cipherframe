locals {
  roles = ["api", "edge", "worker"]

  source_bucket   = coalesce(var.source_bucket_name, "${var.name_prefix}-source-${var.project_id}")
  delivery_bucket = coalesce(var.delivery_bucket_name, "${var.name_prefix}-delivery-${var.project_id}")
  buckets         = { source = local.source_bucket, delivery = local.delivery_bucket }
}

# ---- Buckets ---------------------------------------------------------------------------------

resource "google_storage_bucket" "this" {
  for_each = local.buckets

  name                        = each.value
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = var.labels

  versioning {
    enabled = var.bucket_versioning
  }

  dynamic "lifecycle_rule" {
    for_each = each.key == "source" && var.abort_incomplete_multipart_days > 0 ? [1] : []
    content {
      action {
        type = "AbortIncompleteMultipartUpload"
      }
      condition {
        age = var.abort_incomplete_multipart_days
      }
    }
  }

  dynamic "cors" {
    for_each = length(var.cors_allowed_origins) > 0 ? [1] : []
    content {
      origin          = var.cors_allowed_origins
      method          = each.key == "source" ? ["PUT", "POST", "HEAD"] : ["GET", "HEAD"]
      response_header = ["Content-Type", "ETag"]
      max_age_seconds = 3600
    }
  }
}

# ---- Service accounts ------------------------------------------------------------------------

resource "google_service_account" "this" {
  for_each = toset(local.roles)

  account_id   = "${var.name_prefix}-${each.key}"
  display_name = "Cipherframe ${each.key}"
}

resource "google_service_account_iam_member" "workload_identity" {
  for_each = {
    for pair in flatten([
      for role, members in var.workload_identity_members : [for m in members : { key = "${role}|${m}", role = role, member = m }]
    ]) : pair.key => pair
  }

  service_account_id = google_service_account.this[each.value.role].name
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value.member
}

# ---- Storage permissions ---------------------------------------------------------------------

# One custom role per (server role, bucket), with exactly the permissions that role uses there; the
# README derives them. They are bound on the bucket, never on the project. No prefix condition is
# set: every role's readiness check reads _cipherframe/readiness-probe, which sits outside the t/
# tree, and list calls cannot be conditioned on the object name without the listing prefix.
locals {
  # Storage permissions behind the S3 calls Cipherframe makes: HeadObject and GetObject need
  # objects.get, ListObjectsV2 needs objects.list, and the multipart calls need multipartUploads.*.
  perms = {
    api_source      = ["storage.objects.create", "storage.objects.get", "storage.objects.list", "storage.objects.delete", "storage.multipartUploads.create", "storage.multipartUploads.abort", "storage.multipartUploads.listParts"]
    api_delivery    = ["storage.objects.create", "storage.objects.get", "storage.objects.list", "storage.objects.delete"]
    edge_source     = ["storage.objects.create", "storage.objects.get", "storage.objects.list", "storage.objects.delete", "storage.multipartUploads.create", "storage.multipartUploads.abort", "storage.multipartUploads.listParts"]
    edge_delivery   = ["storage.objects.get", "storage.objects.list"]
    worker_source   = ["storage.objects.get", "storage.objects.list", "storage.objects.delete", "storage.multipartUploads.abort", "storage.multipartUploads.list"]
    worker_delivery = ["storage.objects.create", "storage.objects.get", "storage.objects.list", "storage.objects.delete"]
  }

  # Custom role ids allow letters, digits, _ and . only.
  role_id_prefix = replace(var.name_prefix, "-", "_")
}

resource "google_project_iam_custom_role" "storage" {
  for_each = local.perms

  role_id     = "${local.role_id_prefix}_${each.key}"
  title       = "Cipherframe ${replace(each.key, "_", " ")}"
  permissions = each.value
}

resource "google_storage_bucket_iam_member" "storage" {
  for_each = local.perms

  bucket = google_storage_bucket.this[split("_", each.key)[1]].name
  role   = google_project_iam_custom_role.storage[each.key].id
  member = "serviceAccount:${google_service_account.this[split("_", each.key)[0]].email}"
}

# ---- KEK -------------------------------------------------------------------------------------

resource "google_kms_key_ring" "this" {
  name     = "${var.name_prefix}-keys"
  location = var.region
}

resource "google_kms_crypto_key" "kek" {
  name            = "${var.name_prefix}-kek"
  key_ring        = google_kms_key_ring.this.id
  purpose         = "ENCRYPT_DECRYPT"
  rotation_period = var.key_rotation_period

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "SOFTWARE"
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Cipherframe reads the key (cryptoKeys.get) before it wraps or unwraps. api and worker wrap and
# unwrap; edge only unwraps.
resource "google_kms_crypto_key_iam_member" "viewer" {
  for_each = toset(local.roles)

  crypto_key_id = google_kms_crypto_key.kek.id
  role          = "roles/cloudkms.viewer"
  member        = "serviceAccount:${google_service_account.this[each.key].email}"
}

resource "google_kms_crypto_key_iam_member" "use" {
  for_each = {
    api    = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    worker = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
    edge   = "roles/cloudkms.cryptoKeyDecrypter"
  }

  crypto_key_id = google_kms_crypto_key.kek.id
  role          = each.value
  member        = "serviceAccount:${google_service_account.this[each.key].email}"
}

# ---- HMAC keys (opt in) ----------------------------------------------------------------------

resource "google_storage_hmac_key" "this" {
  for_each = var.create_hmac_keys ? toset(local.roles) : toset([])

  service_account_email = google_service_account.this[each.key].email
}
