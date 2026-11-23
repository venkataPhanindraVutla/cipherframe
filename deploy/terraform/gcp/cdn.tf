# Optional Cloud CDN in front of the delivery bucket (ADR 0062, 0065): a global external HTTPS load
# balancer whose only backend is a backend bucket for the delivery bucket. The bucket stays private
# (public access prevention is enforced): Cloud CDN reads it as its own service agent, and only
# requests with a URL signed by the key below are served. The source bucket is never behind the CDN (I4).

data "google_project" "this" {
  count = var.enable_cdn ? 1 : 0
}

resource "google_compute_backend_bucket" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name        = "${var.name_prefix}-delivery"
  bucket_name = google_storage_bucket.this["delivery"].name
  enable_cdn  = true

  cdn_policy {
    cache_mode                   = "CACHE_ALL_STATIC"
    signed_url_cache_max_age_sec = 3600
  }

  # Players on the tenants' origins fetch segments cross-origin. The bytes are ciphertext and the
  # URL, not the origin, is the credential, so the header allows any origin; leave
  # cors_allowed_origins empty (proxy and presigned need none) to send none.
  custom_response_headers = length(var.cors_allowed_origins) > 0 ? ["Access-Control-Allow-Origin: *"] : []

  lifecycle {
    precondition {
      condition     = var.cdn_domain != null && var.cdn_signing_key_value != null
      error_message = "cdn_domain and cdn_signing_key_value are required when enable_cdn is true."
    }
  }
}

resource "google_compute_backend_bucket_signed_url_key" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name           = var.cdn_signing_key_name
  key_value      = var.cdn_signing_key_value
  backend_bucket = google_compute_backend_bucket.cdn[0].name
}

# Cloud CDN's service agent reads the private delivery bucket.
resource "google_storage_bucket_iam_member" "cdn_read" {
  count = var.enable_cdn ? 1 : 0

  bucket = google_storage_bucket.this["delivery"].name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:service-${data.google_project.this[0].number}@cloud-cdn-fill.iam.gserviceaccount.com"
}

resource "google_compute_global_address" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name = "${var.name_prefix}-cdn"
}

resource "google_compute_managed_ssl_certificate" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name = "${var.name_prefix}-cdn"
  managed {
    domains = [var.cdn_domain]
  }
}

resource "google_compute_url_map" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name            = "${var.name_prefix}-cdn"
  default_service = google_compute_backend_bucket.cdn[0].self_link
}

resource "google_compute_target_https_proxy" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name             = "${var.name_prefix}-cdn"
  url_map          = google_compute_url_map.cdn[0].self_link
  ssl_certificates = [google_compute_managed_ssl_certificate.cdn[0].self_link]
}

resource "google_compute_global_forwarding_rule" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name                  = "${var.name_prefix}-cdn"
  ip_address            = google_compute_global_address.cdn[0].address
  port_range            = "443"
  target                = google_compute_target_https_proxy.cdn[0].self_link
  load_balancing_scheme = "EXTERNAL_MANAGED"
}

# The worker runs the purge after a deletion (asset.cdn_purge) with urlMaps.invalidateCache. The
# permission is bound at the project, because a URL map has no IAM policy of its own; the role holds
# that one permission and nothing else.
resource "google_project_iam_custom_role" "cdn_invalidate" {
  count = var.enable_cdn ? 1 : 0

  role_id     = "${local.role_id_prefix}_cdn_invalidate"
  title       = "Cipherframe CDN invalidate"
  permissions = ["compute.urlMaps.invalidateCache"]
}

resource "google_project_iam_member" "cdn_invalidate" {
  count = var.enable_cdn ? 1 : 0

  project = var.project_id
  role    = google_project_iam_custom_role.cdn_invalidate[0].id
  member  = "serviceAccount:${google_service_account.this["worker"].email}"
}
