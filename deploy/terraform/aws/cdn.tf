# Optional CloudFront distribution in front of the delivery bucket (ADR 0062, 0065). The bucket stays
# private: CloudFront reads it through origin access control, and only requests with a signed URL for
# a key of the trusted key group are served. The source bucket is never behind the CDN (I4).

resource "aws_cloudfront_origin_access_control" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name                              = "${var.name_prefix}-delivery"
  description                       = "Reads the Cipherframe delivery bucket"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_public_key" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name        = "${var.name_prefix}-url-signing"
  encoded_key = var.cdn_public_key_pem

  lifecycle {
    precondition {
      condition     = var.cdn_public_key_pem != null
      error_message = "cdn_public_key_pem is required when enable_cdn is true."
    }
  }
}

resource "aws_cloudfront_key_group" "cdn" {
  count = var.enable_cdn ? 1 : 0

  name  = "${var.name_prefix}-url-signing"
  items = [aws_cloudfront_public_key.cdn[0].id]
}

data "aws_cloudfront_cache_policy" "caching_optimized" {
  count = var.enable_cdn ? 1 : 0

  name = "Managed-CachingOptimized"
}

# Players on the tenants' origins fetch segments cross-origin.
resource "aws_cloudfront_response_headers_policy" "cors" {
  count = var.enable_cdn && length(var.cors_allowed_origins) > 0 ? 1 : 0

  name = "${var.name_prefix}-delivery-cors"
  cors_config {
    access_control_allow_credentials = false
    origin_override                  = true
    access_control_max_age_sec       = 3600
    access_control_allow_headers {
      items = ["*"]
    }
    access_control_allow_methods {
      items = ["GET", "HEAD"]
    }
    access_control_allow_origins {
      items = var.cors_allowed_origins
    }
  }
}

resource "aws_cloudfront_distribution" "cdn" {
  count = var.enable_cdn ? 1 : 0

  enabled         = true
  comment         = "Cipherframe delivery"
  price_class     = var.cdn_price_class
  http_version    = "http2and3"
  is_ipv6_enabled = true
  tags            = var.tags

  origin {
    origin_id                = "delivery"
    domain_name              = aws_s3_bucket.this["delivery"].bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.cdn[0].id
  }

  default_cache_behavior {
    target_origin_id           = "delivery"
    viewer_protocol_policy     = "https-only"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    cache_policy_id            = data.aws_cloudfront_cache_policy.caching_optimized[0].id
    response_headers_policy_id = length(var.cors_allowed_origins) > 0 ? aws_cloudfront_response_headers_policy.cors[0].id : null
    trusted_key_groups         = [aws_cloudfront_key_group.cdn[0].id]
    compress                   = false # segments are ciphertext
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# The delivery bucket accepts reads from this distribution only, and only for asset objects.
data "aws_iam_policy_document" "cdn_origin" {
  count = var.enable_cdn ? 1 : 0

  statement {
    sid       = "CloudFrontOriginAccessControl"
    actions   = ["s3:GetObject"]
    resources = [local.dlv_asset]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.cdn[0].arn]
    }
  }
}

# The worker runs the purge after a deletion (asset.cdn_purge): it may invalidate this distribution
# and nothing else.
data "aws_iam_policy_document" "cdn_invalidate" {
  count = var.enable_cdn ? 1 : 0

  statement {
    sid       = "InvalidateDeliveryCache"
    actions   = ["cloudfront:CreateInvalidation"]
    resources = [aws_cloudfront_distribution.cdn[0].arn]
  }
}

resource "aws_iam_role_policy" "cdn_invalidate" {
  count = var.enable_cdn ? 1 : 0

  name   = "${var.name_prefix}-worker-cdn-invalidate"
  role   = aws_iam_role.this["worker"].id
  policy = data.aws_iam_policy_document.cdn_invalidate[0].json
}
