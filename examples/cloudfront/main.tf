terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
  }
}

# CLOUDFRONT-scoped web ACLs must live in us-east-1 regardless of where the
# rest of your stack runs.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

module "waf" {
  source = "../.."

  providers = {
    aws = aws.us_east_1
  }

  name  = "shared-cloudfront"
  scope = "CLOUDFRONT"

  blocked_country_codes    = ["RU", "KP", "IR"]
  rate_limit_per_5_minutes = 2000

  tags = {
    Application = "waf-shared"
    Environment = "prod"
  }
}

# One shared web ACL protects any number of distributions: each one attaches
# it via web_acl_id. CloudFront does not support aws_wafv2_web_acl_association.
#trivy:ignore:AVD-AWS-0010 access logging is out of scope for this minimal example
resource "aws_cloudfront_distribution" "example" {
  enabled    = true
  web_acl_id = module.waf.web_acl_arn

  origin {
    domain_name = "app.example.com"
    origin_id   = "app"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    target_origin_id       = "app"
    viewer_protocol_policy = "redirect-to-https"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }
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
