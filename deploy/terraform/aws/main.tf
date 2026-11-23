data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  roles      = ["api", "edge", "worker"]

  source_bucket   = coalesce(var.source_bucket_name, "${var.name_prefix}-source-${local.account_id}")
  delivery_bucket = coalesce(var.delivery_bucket_name, "${var.name_prefix}-delivery-${local.account_id}")
  buckets         = { source = local.source_bucket, delivery = local.delivery_bucket }

  # The object the readiness check asks about (internal/health.ProbeKey); every role needs it.
  probe_key = "_cipherframe/readiness-probe"
}

# ---- Buckets ---------------------------------------------------------------------------------

resource "aws_s3_bucket" "this" {
  for_each = local.buckets

  bucket = each.value
  tags   = var.tags
}

resource "aws_s3_bucket_public_access_block" "this" {
  for_each = local.buckets

  bucket                  = aws_s3_bucket.this[each.key].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id
  rule {
    bucket_key_enabled = var.bucket_kms_key_arn != null
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.bucket_kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.bucket_kms_key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id
  versioning_configuration {
    status = var.bucket_versioning ? "Enabled" : "Suspended"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "source" {
  count = var.abort_incomplete_multipart_days > 0 ? 1 : 0

  bucket = aws_s3_bucket.this["source"].id
  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = var.abort_incomplete_multipart_days
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "this" {
  for_each = length(var.cors_allowed_origins) > 0 ? local.buckets : {}

  bucket = aws_s3_bucket.this[each.key].id
  cors_rule {
    allowed_origins = var.cors_allowed_origins
    allowed_methods = each.key == "source" ? ["PUT", "POST", "HEAD"] : ["GET", "HEAD"]
    allowed_headers = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3600
  }
}

data "aws_iam_policy_document" "bucket_tls_only" {
  for_each = local.buckets

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.this[each.key].arn, "${aws_s3_bucket.this[each.key].arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# The delivery bucket's policy with the CDN: the TLS-only rule plus read access for the distribution.
data "aws_iam_policy_document" "delivery_bucket" {
  count = var.enable_cdn ? 1 : 0

  source_policy_documents = [
    data.aws_iam_policy_document.bucket_tls_only["delivery"].json,
    data.aws_iam_policy_document.cdn_origin[0].json,
  ]
}

resource "aws_s3_bucket_policy" "this" {
  for_each = local.buckets

  bucket = aws_s3_bucket.this[each.key].id
  policy = each.key == "delivery" && var.enable_cdn ? data.aws_iam_policy_document.delivery_bucket[0].json : data.aws_iam_policy_document.bucket_tls_only[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.this]
}

# ---- Roles and KEK ---------------------------------------------------------------------------

resource "aws_iam_role" "this" {
  for_each = toset(local.roles)

  name               = "${var.name_prefix}-${each.key}"
  assume_role_policy = var.assume_role_policies[each.key]
  tags               = var.tags
}

# The key policy names the account root, which lets IAM administrators manage the key and prevents
# a lockout, and then grants use only to the roles that need it (see the README table).
data "aws_iam_policy_document" "kek" {
  statement {
    sid       = "AccountAdministration"
    effect    = "Allow"
    actions   = ["kms:Describe*", "kms:Get*", "kms:List*", "kms:Create*", "kms:Update*", "kms:Enable*", "kms:Disable*", "kms:Put*", "kms:Revoke*", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:TagResource", "kms:UntagResource"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${local.account_id}:root"]
    }
  }

  # api and worker wrap new secrets and keys; they also unwrap what they wrapped.
  statement {
    sid       = "WrapAndUnwrap"
    effect    = "Allow"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.this["api"].arn, aws_iam_role.this["worker"].arn]
    }
  }

  # edge only unwraps: it serves content keys and verifies viewer secrets, and wraps nothing.
  statement {
    sid       = "UnwrapOnly"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.this["edge"].arn]
    }
  }
}

resource "aws_kms_key" "kek" {
  description              = "Cipherframe KEK: wraps content keys, signing seeds and stored secrets"
  key_usage                = "ENCRYPT_DECRYPT"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  enable_key_rotation      = true
  deletion_window_in_days  = var.kms_deletion_window_days
  policy                   = data.aws_iam_policy_document.kek.json
  tags                     = var.tags
}

resource "aws_kms_alias" "kek" {
  name          = "alias/${var.name_prefix}-kek"
  target_key_id = aws_kms_key.kek.key_id
}

# ---- Role permissions ------------------------------------------------------------------------

locals {
  src = aws_s3_bucket.this["source"].arn
  dlv = aws_s3_bucket.this["delivery"].arn

  # Key layout (internal/storage/keys): source objects live under t/<tenant>/a/<asset>/source/,
  # delivery objects under t/<tenant>/a/<asset>/ and brand logos under t/<tenant>/branding/logo/.
  src_objects   = "${local.src}/t/*/a/*/source/*"
  dlv_asset     = "${local.dlv}/t/*/a/*"
  dlv_subtitles = "${local.dlv}/t/*/a/*/subtitles/*"
  dlv_logos     = "${local.dlv}/t/*/branding/logo/*"
  dlv_tenant    = "${local.dlv}/t/*"

  bucket_cmk = var.bucket_kms_key_arn == null ? [] : [var.bucket_kms_key_arn]

  # Per role, sid => actions and resources. HeadObject needs s3:GetObject, DeleteObjects needs
  # s3:DeleteObject, and CreateMultipartUpload, UploadPart and CompleteMultipartUpload need s3:PutObject.
  statements = {
    api = {
      SourceUploads   = { actions = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload"], resources = [local.src_objects] }
      DeliveryContent = { actions = ["s3:PutObject", "s3:DeleteObject"], resources = [local.dlv_subtitles, local.dlv_logos] }
    }
    edge = {
      SourceUploads = { actions = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"], resources = [local.src_objects] }
      DeliveryRead  = { actions = ["s3:GetObject"], resources = [local.dlv_asset] }
    }
    worker = {
      SourceRead      = { actions = ["s3:GetObject", "s3:DeleteObject", "s3:AbortMultipartUpload"], resources = [local.src_objects] }
      DeliveryProcess = { actions = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"], resources = [local.dlv_tenant] }
    }
  }
}

data "aws_iam_policy_document" "role" {
  for_each = toset(local.roles)

  dynamic "statement" {
    for_each = local.statements[each.key]
    content {
      sid       = statement.key
      actions   = statement.value.actions
      resources = statement.value.resources
    }
  }

  # Readiness probe (every role, both buckets): HEAD of a key that never exists. S3 answers 404
  # only to a caller that may list the bucket; without it the answer is 403 and the role is never ready.
  statement {
    sid       = "ReadinessProbeObject"
    actions   = ["s3:GetObject"]
    resources = ["${local.src}/${local.probe_key}", "${local.dlv}/${local.probe_key}"]
  }

  statement {
    sid       = "ListBuckets"
    actions   = ["s3:ListBucket"]
    resources = [local.src, local.dlv]
  }

  dynamic "statement" {
    for_each = length(local.bucket_cmk) > 0 ? [1] : []
    content {
      sid       = "BucketEncryptionKey"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = local.bucket_cmk
    }
  }
}

resource "aws_iam_role_policy" "role" {
  for_each = toset(local.roles)

  name   = "${var.name_prefix}-${each.key}-storage"
  role   = aws_iam_role.this[each.key].id
  policy = data.aws_iam_policy_document.role[each.key].json
}
