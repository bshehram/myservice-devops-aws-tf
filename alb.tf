# Create Public ALB Security Group
#
resource "aws_security_group" "alb_pub" {
  name        = "myservice-alb-pub"
  description = "myservice-alb-pub"
  vpc_id      = local.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "myservice-alb-pub"
  }
}

# Create Private ALB Security Group
#
resource "aws_security_group" "alb_priv" {
  name        = "myservice-alb-priv"
  description = "myservice-alb-priv"
  vpc_id      = local.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "myservice-alb-priv"
  }
}

# Create Private ALB 
#
resource "aws_alb" "alb_priv" {
  name = "myservice-priv"

  security_groups = [aws_security_group.alb_priv.id]

  subnets  = local.private_subnet_ids
  internal = true

  timeouts {
    create = "30m"
    update = "30m"
    delete = "30m"
  }

  tags = {
    Name = "myservice-alb-priv"
  }
}

# Create Public ALB 
#
resource "aws_alb" "alb_pub" {
  name = "myservice-pub"

  security_groups = [aws_security_group.alb_pub.id]

  subnets  = local.public_subnet_ids
  internal = false

  timeouts {
    create = "30m"
    update = "30m"
    delete = "30m"
  }

  tags = {
    Name = "myservice-alb-pub"
  }
}

# Create Private ALB HTTP Listener
#
resource "aws_alb_listener" "alb_priv_http" {
  load_balancer_arn = aws_alb.alb_priv.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Create Public ALB HTTP Listener
#
resource "aws_alb_listener" "alb_pub_http" {
  load_balancer_arn = aws_alb.alb_pub.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Create Private ALB HTTPS Listener
#
resource "aws_alb_listener" "alb_priv_https" {
  load_balancer_arn = aws_alb.alb_priv.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate_validation.acm.certificate_arn

  default_action {
    type = "redirect"

    redirect {
      host        = local.domain
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Create Public ALB HTTPS Listener
#
resource "aws_alb_listener" "alb_pub_https" {
  load_balancer_arn = aws_alb.alb_pub.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate_validation.acm.certificate_arn

  default_action {
    type = "redirect"

    redirect {
      host        = local.domain
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
