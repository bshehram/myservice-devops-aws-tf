# Create MyService Security Group
#
resource "aws_security_group" "myservice" {
  name        = "myservice"
  description = "myservice"
  vpc_id      = local.vpc_id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["${local.my_ip}"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "myservice"
  }
}

# Create MyService Target Group
#
resource "aws_alb_target_group" "myservice" {
  name                 = "myservice"
  port                 = 80
  protocol             = "HTTP"
  target_type          = "instance"
  vpc_id               = local.vpc_id
  deregistration_delay = 0

  health_check {
    matcher             = 200 # The HTTP codes to use when checking for a successful response from a target
    healthy_threshold   = 2   # The number of consecutive health checks successes required before considering an unhealthy target healthy
    unhealthy_threshold = 4   # The number of consecutive health check failures required before considering the target unhealthy
    interval            = 120 # The approximate amount of time, in seconds, between health checks of an individual target
    timeout             = 60  # The amount of time, in seconds, during which no response means a failed health check
  }
}

# Create MyService Target Group Attachment
#
resource "aws_alb_target_group_attachment" "myservice" {
  target_group_arn = aws_alb_target_group.myservice.arn
  target_id        = aws_instance.myservice.id
  port             = 80
}

# Create MyService ALB Listener (to alb_pub or alb_priv)
#
resource "aws_alb_listener_rule" "myservice" {
  listener_arn = aws_alb_listener.alb_pub_https.arn
  priority     = 20

  action {
    type             = "forward"
    target_group_arn = aws_alb_target_group.myservice.arn
  }

  condition {
    host_header {
      values = ["myservice.${local.domain}"]
    }
  }
}

resource "aws_alb_listener_certificate" "myservice" {
  listener_arn    = aws_alb_listener.alb_pub_https.arn
  certificate_arn = aws_acm_certificate.acm.arn
}

# Create MyService IAM Role and attach AmazonS3FullAccess policy
#
resource "aws_iam_role" "myservice" {
  name               = "myservice"
  assume_role_policy = data.aws_iam_policy_document.myservice.json
}

resource "aws_iam_instance_profile" "myservice" {
  name = "myservice"
  role = aws_iam_role.myservice.name
}

data "aws_iam_policy_document" "myservice" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "myservice_s3" {
  role       = aws_iam_role.myservice.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# Create MyService Instance (in public_subnet_ids or private_subnet_ids)
#
resource "aws_instance" "myservice" {
  ami                    = data.aws_ami.myservice.id
  instance_type          = local.myservice_instance_type
  iam_instance_profile   = aws_iam_instance_profile.myservice.name
  monitoring             = true
  subnet_id              = element(flatten([local.public_subnet_ids]), 0) # Picks the first public subnet from the list public_subnet_ids or private_subnet_ids
  vpc_security_group_ids = [aws_security_group.myservice.id]
  ebs_optimized          = true
  key_name               = aws_key_pair.myservice.key_name # use the key pair created from resource below or use local.key_name

  tags = {
    Name = "myservice"
  }

  lifecycle {
    ignore_changes = [
      ami,
    ]
  }
}

# Create MyService Key Pair
#
resource "aws_key_pair" "myservice" {
  key_name   = "myservice"
  public_key = local.myservice_key_pub
}

# Select MyService AMI built from Packer
#
data "aws_ami" "myservice" {
  filter {
    name   = "name"
    values = ["myservice-*"]
  }

  owners      = ["420694206942069"] # Replace with your AWS account ID
  most_recent = true
}

# Create Route 53 Record for ALB and EC2 Instance (for alb_pub or alb_priv and public_ip or private_ip)
#
resource "aws_route53_record" "myservice" {
  zone_id = local.zone_id
  name    = "myservice"
  type    = "A"

  alias {
    name                   = aws_alb.alb_pub.dns_name
    zone_id                = aws_alb.alb_pub.zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "myservice_ec2" {
  zone_id = local.zone_id
  name    = "myservice-ec2"
  type    = "A"
  ttl     = 300

  records = [aws_instance.myservice.public_ip]
}
