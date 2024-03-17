# Create ACM SSL Certificate DNS Request for MyService
#
resource "aws_acm_certificate" "acm" {
  domain_name       = "myservice.${local.domain}"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# Create ACM SSL Certificate DNS Records
#
resource "aws_route53_record" "acm" {
  for_each = {
    for dvo in aws_acm_certificate.acm.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 300
  type            = each.value.type
  zone_id         = local.zone_id
}

resource "aws_acm_certificate_validation" "acm" {
  certificate_arn         = aws_acm_certificate.acm.arn
  validation_record_fqdns = [for record in aws_route53_record.acm : record.fqdn]
}
