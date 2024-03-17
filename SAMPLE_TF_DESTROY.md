## Sample output from `terraform destroy` with a total of 30 resources

```
basit in ~/Documents/myservice-devops-aws-tf on main ● λ terraform destroy                
random_string.rds_password: Refreshing state... [id=42069Magic42069]
data.aws_iam_policy_document.myservice: Reading...
data.aws_ami.myservice: Reading...
aws_db_parameter_group.db: Refreshing state... [id=myservice]
aws_key_pair.myservice: Refreshing state... [id=myservice]
aws_rds_cluster_parameter_group.db: Refreshing state... [id=myservice]
aws_db_subnet_group.db: Refreshing state... [id=myservice]
aws_acm_certificate.acm: Refreshing state... [id=arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57]
aws_security_group.myservice: Refreshing state... [id=sg-0c493078a0e5e352e]
aws_security_group.db: Refreshing state... [id=sg-08bc83b69d3282783]
data.aws_iam_policy_document.myservice: Read complete after 0s [id=2851119427]
aws_security_group.alb_pub: Refreshing state... [id=sg-07c2efe5ed7e04199]
aws_alb_target_group.myservice: Refreshing state... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448]
aws_iam_role.myservice: Refreshing state... [id=myservice]
data.aws_ami.myservice: Read complete after 0s [id=ami-420420420]
aws_alb.alb_pub: Refreshing state... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca]
aws_route53_record.acm["myservice.mydomain.io"]: Refreshing state... [id=Z4206969696969__7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io._CNAME]
aws_rds_cluster.db: Refreshing state... [id=myservice]
aws_route53_record.myservice: Refreshing state... [id=Z4206969696969_myservice_A]
aws_alb_listener.alb_pub_http: Refreshing state... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/4c51557166dc2469]
aws_route53_record.myservice_db_reader: Refreshing state... [id=Z4206969696969_myservice-db-reader_CNAME]
aws_route53_record.myservice_db: Refreshing state... [id=Z4206969696969_myservice-db_CNAME]
aws_rds_cluster_instance.db[0]: Refreshing state... [id=myservice-0]
aws_rds_cluster_instance.db[1]: Refreshing state... [id=myservice-1]
aws_rds_cluster_instance.db[2]: Refreshing state... [id=myservice-2]
aws_iam_role_policy_attachment.myservice_s3: Refreshing state... [id=myservice-20240317134536547700000002]
aws_iam_instance_profile.myservice: Refreshing state... [id=myservice]
aws_acm_certificate_validation.acm: Refreshing state... [id=2024-03-17 13:45:49.634 +0000 UTC]
aws_alb_listener.alb_pub_https: Refreshing state... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e]
aws_instance.myservice: Refreshing state... [id=i-07791e678df153e86]
aws_alb_listener_certificate.myservice: Refreshing state... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e_arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57]
aws_alb_listener_rule.myservice: Refreshing state... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener-rule/app/myservice-pub/6f90586e614a1eca/b0840678603db37e/b9f58463ce1b971f]
aws_alb_target_group_attachment.myservice: Refreshing state... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448-20240317134559915600000004]
aws_route53_record.myservice_ec2: Refreshing state... [id=Z4206969696969_myservice-ec2_A]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  - destroy

Terraform will perform the following actions:

  # aws_acm_certificate.acm will be destroyed
  - resource "aws_acm_certificate" "acm" {
      - arn                       = "arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57" -> null
      - domain_name               = "myservice.mydomain.io" -> null
      - domain_validation_options = [
          - {
              - domain_name           = "myservice.mydomain.io"
              - resource_record_name  = "_7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io."
              - resource_record_type  = "CNAME"
              - resource_record_value = "_4febf6b6f0cff746c39404be2b35c356.mhbtsbpdnt.acm-validations.aws."
            },
        ] -> null
      - id                        = "arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57" -> null
      - key_algorithm             = "RSA_2048" -> null
      - not_after                 = "2025-04-15T23:59:59Z" -> null
      - not_before                = "2024-03-17T00:00:00Z" -> null
      - pending_renewal           = false -> null
      - renewal_eligibility       = "ELIGIBLE" -> null
      - renewal_summary           = [] -> null
      - status                    = "ISSUED" -> null
      - subject_alternative_names = [
          - "myservice.mydomain.io",
        ] -> null
      - tags                      = {} -> null
      - tags_all                  = {} -> null
      - type                      = "AMAZON_ISSUED" -> null
      - validation_emails         = [] -> null
      - validation_method         = "DNS" -> null

      - options {
          - certificate_transparency_logging_preference = "ENABLED" -> null
        }
    }

  # aws_acm_certificate_validation.acm will be destroyed
  - resource "aws_acm_certificate_validation" "acm" {
      - certificate_arn         = "arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57" -> null
      - id                      = "2024-03-17 13:45:49.634 +0000 UTC" -> null
      - validation_record_fqdns = [
          - "_7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io",
        ] -> null
    }

  # aws_alb.alb_pub will be destroyed
  - resource "aws_alb" "alb_pub" {
      - arn                                         = "arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca" -> null
      - arn_suffix                                  = "app/myservice-pub/6f90586e614a1eca" -> null
      - desync_mitigation_mode                      = "defensive" -> null
      - dns_name                                    = "myservice-pub-819770937.us-west-2.elb.amazonaws.com" -> null
      - drop_invalid_header_fields                  = false -> null
      - enable_cross_zone_load_balancing            = true -> null
      - enable_deletion_protection                  = false -> null
      - enable_http2                                = true -> null
      - enable_tls_version_and_cipher_suite_headers = false -> null
      - enable_waf_fail_open                        = false -> null
      - enable_xff_client_port                      = false -> null
      - id                                          = "arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca" -> null
      - idle_timeout                                = 60 -> null
      - internal                                    = false -> null
      - ip_address_type                             = "ipv4" -> null
      - load_balancer_type                          = "application" -> null
      - name                                        = "myservice-pub" -> null
      - preserve_host_header                        = false -> null
      - security_groups                             = [
          - "sg-07c2efe5ed7e04199",
        ] -> null
      - subnets                                     = [
          - "subnet-0490ec6d7ca42a49d",
          - "subnet-0826ac0b500f4b37c",
          - "subnet-099968b8d0d26f998",
          - "subnet-0ae21b6bac4a2f923",
        ] -> null
      - tags                                        = {
          - "Name" = "myservice-alb-pub"
        } -> null
      - tags_all                                    = {
          - "Name" = "myservice-alb-pub"
        } -> null
      - vpc_id                                      = "vpc-00e246a40bce74dd8" -> null
      - xff_header_processing_mode                  = "append" -> null
      - zone_id                                     = "Z1H1FL5HABSF5" -> null

      - access_logs {
          - enabled = false -> null
        }

      - connection_logs {
          - enabled = false -> null
        }

      - subnet_mapping {
          - subnet_id = "subnet-0490ec6d7ca42a49d" -> null
        }
      - subnet_mapping {
          - subnet_id = "subnet-0826ac0b500f4b37c" -> null
        }
      - subnet_mapping {
          - subnet_id = "subnet-099968b8d0d26f998" -> null
        }
      - subnet_mapping {
          - subnet_id = "subnet-0ae21b6bac4a2f923" -> null
        }

      - timeouts {
          - create = "30m" -> null
          - delete = "30m" -> null
          - update = "30m" -> null
        }
    }

  # aws_alb_listener.alb_pub_http will be destroyed
  - resource "aws_alb_listener" "alb_pub_http" {
      - arn               = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/4c51557166dc2469" -> null
      - id                = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/4c51557166dc2469" -> null
      - load_balancer_arn = "arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca" -> null
      - port              = 80 -> null
      - protocol          = "HTTP" -> null
      - tags              = {} -> null
      - tags_all          = {} -> null

      - default_action {
          - order = 1 -> null
          - type  = "redirect" -> null

          - redirect {
              - host        = "#{host}" -> null
              - path        = "/#{path}" -> null
              - port        = "443" -> null
              - protocol    = "HTTPS" -> null
              - query       = "#{query}" -> null
              - status_code = "HTTP_301" -> null
            }
        }
    }

  # aws_alb_listener.alb_pub_https will be destroyed
  - resource "aws_alb_listener" "alb_pub_https" {
      - arn               = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e" -> null
      - certificate_arn   = "arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57" -> null
      - id                = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e" -> null
      - load_balancer_arn = "arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca" -> null
      - port              = 443 -> null
      - protocol          = "HTTPS" -> null
      - ssl_policy        = "ELBSecurityPolicy-2016-08" -> null
      - tags              = {} -> null
      - tags_all          = {} -> null

      - default_action {
          - order = 1 -> null
          - type  = "redirect" -> null

          - redirect {
              - host        = "mydomain.io" -> null
              - path        = "/#{path}" -> null
              - port        = "443" -> null
              - protocol    = "HTTPS" -> null
              - query       = "#{query}" -> null
              - status_code = "HTTP_301" -> null
            }
        }

      - mutual_authentication {
          - ignore_client_certificate_expiry = false -> null
          - mode                             = "off" -> null
        }
    }

  # aws_alb_listener_certificate.myservice will be destroyed
  - resource "aws_alb_listener_certificate" "myservice" {
      - certificate_arn = "arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57" -> null
      - id              = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e_arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57" -> null
      - listener_arn    = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e" -> null
    }

  # aws_alb_listener_rule.myservice will be destroyed
  - resource "aws_alb_listener_rule" "myservice" {
      - arn          = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener-rule/app/myservice-pub/6f90586e614a1eca/b0840678603db37e/b9f58463ce1b971f" -> null
      - id           = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener-rule/app/myservice-pub/6f90586e614a1eca/b0840678603db37e/b9f58463ce1b971f" -> null
      - listener_arn = "arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e" -> null
      - priority     = 20 -> null
      - tags         = {} -> null
      - tags_all     = {} -> null

      - action {
          - order            = 1 -> null
          - target_group_arn = "arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448" -> null
          - type             = "forward" -> null
        }

      - condition {
          - host_header {
              - values = [
                  - "myservice.mydomain.io",
                ] -> null
            }
        }
    }

  # aws_alb_target_group.myservice will be destroyed
  - resource "aws_alb_target_group" "myservice" {
      - arn                                = "arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448" -> null
      - arn_suffix                         = "targetgroup/myservice/3ebdb431db91c448" -> null
      - deregistration_delay               = "0" -> null
      - id                                 = "arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448" -> null
      - ip_address_type                    = "ipv4" -> null
      - lambda_multi_value_headers_enabled = false -> null
      - load_balancer_arns                 = [
          - "arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca",
        ] -> null
      - load_balancing_algorithm_type      = "round_robin" -> null
      - load_balancing_anomaly_mitigation  = "off" -> null
      - load_balancing_cross_zone_enabled  = "use_load_balancer_configuration" -> null
      - name                               = "myservice" -> null
      - port                               = 80 -> null
      - protocol                           = "HTTP" -> null
      - protocol_version                   = "HTTP1" -> null
      - proxy_protocol_v2                  = false -> null
      - slow_start                         = 0 -> null
      - tags                               = {} -> null
      - tags_all                           = {} -> null
      - target_type                        = "instance" -> null
      - vpc_id                             = "vpc-00e246a40bce74dd8" -> null

      - health_check {
          - enabled             = true -> null
          - healthy_threshold   = 2 -> null
          - interval            = 120 -> null
          - matcher             = "200" -> null
          - path                = "/" -> null
          - port                = "traffic-port" -> null
          - protocol            = "HTTP" -> null
          - timeout             = 60 -> null
          - unhealthy_threshold = 4 -> null
        }

      - stickiness {
          - cookie_duration = 86400 -> null
          - enabled         = false -> null
          - type            = "lb_cookie" -> null
        }

      - target_failover {}

      - target_health_state {}
    }

  # aws_alb_target_group_attachment.myservice will be destroyed
  - resource "aws_alb_target_group_attachment" "myservice" {
      - id               = "arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448-20240317134559915600000004" -> null
      - port             = 80 -> null
      - target_group_arn = "arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448" -> null
      - target_id        = "i-07791e678df153e86" -> null
    }

  # aws_db_parameter_group.db will be destroyed
  - resource "aws_db_parameter_group" "db" {
      - arn         = "arn:aws:rds:us-west-2:4206942069:pg:myservice" -> null
      - description = "Managed by Terraform" -> null
      - family      = "aurora-postgresql11" -> null
      - id          = "myservice" -> null
      - name        = "myservice" -> null
      - tags        = {} -> null
      - tags_all    = {} -> null
    }

  # aws_db_subnet_group.db will be destroyed
  - resource "aws_db_subnet_group" "db" {
      - arn                     = "arn:aws:rds:us-west-2:4206942069:subgrp:myservice" -> null
      - description             = "myservice" -> null
      - id                      = "myservice" -> null
      - name                    = "myservice" -> null
      - subnet_ids              = [
          - "subnet-00a1422e78ea03c88",
          - "subnet-08211bf789d64e791",
          - "subnet-08702d1b7553207fb",
          - "subnet-0f2c0fa276216d000",
        ] -> null
      - supported_network_types = [
          - "IPV4",
        ] -> null
      - tags                    = {
          - "Name" = "myservice"
        } -> null
      - tags_all                = {
          - "Name" = "myservice"
        } -> null
      - vpc_id                  = "vpc-00e246a40bce74dd8" -> null
    }

  # aws_iam_instance_profile.myservice will be destroyed
  - resource "aws_iam_instance_profile" "myservice" {
      - arn         = "arn:aws:iam::4206942069:instance-profile/myservice" -> null
      - create_date = "2024-03-17T13:45:36Z" -> null
      - id          = "myservice" -> null
      - name        = "myservice" -> null
      - path        = "/" -> null
      - role        = "myservice" -> null
      - tags        = {} -> null
      - tags_all    = {} -> null
      - unique_id   = "AIPA4WVB2JNQNQH3UX2GZ" -> null
    }

  # aws_iam_role.myservice will be destroyed
  - resource "aws_iam_role" "myservice" {
      - arn                   = "arn:aws:iam::4206942069:role/myservice" -> null
      - assume_role_policy    = jsonencode(
            {
              - Statement = [
                  - {
                      - Action    = "sts:AssumeRole"
                      - Effect    = "Allow"
                      - Principal = {
                          - Service = "ec2.amazonaws.com"
                        }
                    },
                ]
              - Version   = "2012-10-17"
            }
        ) -> null
      - create_date           = "2024-03-17T13:45:35Z" -> null
      - force_detach_policies = false -> null
      - id                    = "myservice" -> null
      - managed_policy_arns   = [
          - "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        ] -> null
      - max_session_duration  = 3600 -> null
      - name                  = "myservice" -> null
      - path                  = "/" -> null
      - tags                  = {} -> null
      - tags_all              = {} -> null
      - unique_id             = "AROA4WVB2JNQCZ3U4VAU4" -> null
    }

  # aws_iam_role_policy_attachment.myservice_s3 will be destroyed
  - resource "aws_iam_role_policy_attachment" "myservice_s3" {
      - id         = "myservice-20240317134536547700000002" -> null
      - policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess" -> null
      - role       = "myservice" -> null
    }

  # aws_instance.myservice will be destroyed
  - resource "aws_instance" "myservice" {
      - ami                                  = "ami-069e7c74c7628b19d" -> null
      - arn                                  = "arn:aws:ec2:us-west-2:4206942069:instance/i-07791e678df153e86" -> null
      - associate_public_ip_address          = true -> null
      - availability_zone                    = "us-west-2a" -> null
      - cpu_core_count                       = 2 -> null
      - cpu_threads_per_core                 = 1 -> null
      - disable_api_stop                     = false -> null
      - disable_api_termination              = false -> null
      - ebs_optimized                        = true -> null
      - get_password_data                    = false -> null
      - hibernation                          = false -> null
      - iam_instance_profile                 = "myservice" -> null
      - id                                   = "i-07791e678df153e86" -> null
      - instance_initiated_shutdown_behavior = "stop" -> null
      - instance_state                       = "running" -> null
      - instance_type                        = "t4g.medium" -> null
      - ipv6_address_count                   = 0 -> null
      - ipv6_addresses                       = [] -> null
      - key_name                             = "myservice" -> null
      - monitoring                           = true -> null
      - placement_partition_number           = 0 -> null
      - primary_network_interface_id         = "eni-06c4893a9c660f0da" -> null
      - private_dns                          = "ip-10-42-4-146.us-west-2.compute.internal" -> null
      - private_ip                           = "10.42.4.146" -> null
      - public_dns                           = "ec2-52-43-231-215.us-west-2.compute.amazonaws.com" -> null
      - public_ip                            = "52.43.231.215" -> null
      - secondary_private_ips                = [] -> null
      - security_groups                      = [] -> null
      - source_dest_check                    = true -> null
      - subnet_id                            = "subnet-0826ac0b500f4b37c" -> null
      - tags                                 = {
          - "Name" = "myservice"
        } -> null
      - tags_all                             = {
          - "Name" = "myservice"
        } -> null
      - tenancy                              = "default" -> null
      - user_data_replace_on_change          = false -> null
      - vpc_security_group_ids               = [
          - "sg-0c493078a0e5e352e",
        ] -> null

      - capacity_reservation_specification {
          - capacity_reservation_preference = "open" -> null
        }

      - cpu_options {
          - core_count       = 2 -> null
          - threads_per_core = 1 -> null
        }

      - credit_specification {
          - cpu_credits = "unlimited" -> null
        }

      - enclave_options {
          - enabled = false -> null
        }

      - maintenance_options {
          - auto_recovery = "default" -> null
        }

      - metadata_options {
          - http_endpoint               = "enabled" -> null
          - http_protocol_ipv6          = "disabled" -> null
          - http_put_response_hop_limit = 1 -> null
          - http_tokens                 = "optional" -> null
          - instance_metadata_tags      = "disabled" -> null
        }

      - private_dns_name_options {
          - enable_resource_name_dns_a_record    = false -> null
          - enable_resource_name_dns_aaaa_record = false -> null
          - hostname_type                        = "ip-name" -> null
        }

      - root_block_device {
          - delete_on_termination = true -> null
          - device_name           = "/dev/xvda" -> null
          - encrypted             = false -> null
          - iops                  = 100 -> null
          - tags                  = {} -> null
          - tags_all              = {} -> null
          - throughput            = 0 -> null
          - volume_id             = "vol-0a8455544275bc822" -> null
          - volume_size           = 10 -> null
          - volume_type           = "gp2" -> null
        }
    }

  # aws_key_pair.myservice will be destroyed
  - resource "aws_key_pair" "myservice" {
      - arn         = "arn:aws:ec2:us-west-2:4206942069:key-pair/myservice" -> null
      - fingerprint = "24:71:84:70:bd:c3:f9:4a:04:ec:d8:95:c7:bc:31:a2" -> null
      - id          = "myservice" -> null
      - key_name    = "myservice" -> null
      - key_pair_id = "key-065dca1ae650e1197" -> null
      - key_type    = "rsa" -> null
      - public_key  = "ssh-rsa AAAAB+lc8wP2Qb9rikCPs= basit@shehram.com" -> null
      - tags        = {} -> null
      - tags_all    = {} -> null
    }

  # aws_rds_cluster.db will be destroyed
  - resource "aws_rds_cluster" "db" {
      - allocated_storage                   = 1 -> null
      - arn                                 = "arn:aws:rds:us-west-2:4206942069:cluster:myservice" -> null
      - availability_zones                  = [
          - "us-west-2a",
          - "us-west-2b",
          - "us-west-2c",
        ] -> null
      - backtrack_window                    = 0 -> null
      - backup_retention_period             = 7 -> null
      - cluster_identifier                  = "myservice" -> null
      - cluster_members                     = [
          - "myservice-0",
          - "myservice-1",
          - "myservice-2",
        ] -> null
      - cluster_resource_id                 = "cluster-LGOH7T4ZR6LK7H345FIIGQ2JEI" -> null
      - copy_tags_to_snapshot               = false -> null
      - database_name                       = "myservice" -> null
      - db_cluster_parameter_group_name     = "myservice" -> null
      - db_subnet_group_name                = "myservice" -> null
      - delete_automated_backups            = true -> null
      - deletion_protection                 = false -> null
      - enable_global_write_forwarding      = false -> null
      - enable_http_endpoint                = false -> null
      - enabled_cloudwatch_logs_exports     = [] -> null
      - endpoint                            = "myservice.cluster-cgub7ocz2dps.us-west-2.rds.amazonaws.com" -> null
      - engine                              = "aurora-postgresql" -> null
      - engine_mode                         = "provisioned" -> null
      - engine_version                      = "11.9" -> null
      - engine_version_actual               = "11.9" -> null
      - hosted_zone_id                      = "Z1PVIF0B656C1W" -> null
      - iam_database_authentication_enabled = false -> null
      - iam_roles                           = [] -> null
      - id                                  = "myservice" -> null
      - iops                                = 0 -> null
      - master_password                     = (sensitive value) -> null
      - master_user_secret                  = [] -> null
      - master_username                     = "myservice" -> null
      - network_type                        = "IPV4" -> null
      - port                                = 5432 -> null
      - preferred_backup_window             = "10:24-10:54" -> null
      - preferred_maintenance_window        = "tue:12:29-tue:12:59" -> null
      - reader_endpoint                     = "myservice.cluster-ro-cgub7ocz2dps.us-west-2.rds.amazonaws.com" -> null
      - skip_final_snapshot                 = true -> null
      - storage_encrypted                   = false -> null
      - tags                                = {
          - "Name" = "myservice"
        } -> null
      - tags_all                            = {
          - "Name" = "myservice"
        } -> null
      - vpc_security_group_ids              = [
          - "sg-08bc83b69d3282783",
        ] -> null
    }

  # aws_rds_cluster_instance.db[0] will be destroyed
  - resource "aws_rds_cluster_instance" "db" {
      - apply_immediately                     = true -> null
      - arn                                   = "arn:aws:rds:us-west-2:4206942069:db:myservice-0" -> null
      - auto_minor_version_upgrade            = true -> null
      - availability_zone                     = "us-west-2b" -> null
      - ca_cert_identifier                    = "rds-ca-rsa2048-g1" -> null
      - cluster_identifier                    = "myservice" -> null
      - copy_tags_to_snapshot                 = false -> null
      - db_parameter_group_name               = "myservice" -> null
      - db_subnet_group_name                  = "myservice" -> null
      - dbi_resource_id                       = "db-CGGVMC3SAH6URGSG3K7FTJK36U" -> null
      - endpoint                              = "myservice-0.cgub7ocz2dps.us-west-2.rds.amazonaws.com" -> null
      - engine                                = "aurora-postgresql" -> null
      - engine_version                        = "11.9" -> null
      - engine_version_actual                 = "11.9" -> null
      - id                                    = "myservice-0" -> null
      - identifier                            = "myservice-0" -> null
      - instance_class                        = "db.t4g.medium" -> null
      - monitoring_interval                   = 0 -> null
      - network_type                          = "IPV4" -> null
      - performance_insights_enabled          = false -> null
      - performance_insights_retention_period = 0 -> null
      - port                                  = 5432 -> null
      - preferred_backup_window               = "10:24-10:54" -> null
      - preferred_maintenance_window          = "mon:06:58-mon:07:28" -> null
      - promotion_tier                        = 0 -> null
      - publicly_accessible                   = false -> null
      - storage_encrypted                     = false -> null
      - tags                                  = {} -> null
      - tags_all                              = {} -> null
      - writer                                = true -> null
    }

  # aws_rds_cluster_instance.db[1] will be destroyed
  - resource "aws_rds_cluster_instance" "db" {
      - apply_immediately                     = true -> null
      - arn                                   = "arn:aws:rds:us-west-2:4206942069:db:myservice-1" -> null
      - auto_minor_version_upgrade            = true -> null
      - availability_zone                     = "us-west-2c" -> null
      - ca_cert_identifier                    = "rds-ca-rsa2048-g1" -> null
      - cluster_identifier                    = "myservice" -> null
      - copy_tags_to_snapshot                 = false -> null
      - db_parameter_group_name               = "myservice" -> null
      - db_subnet_group_name                  = "myservice" -> null
      - dbi_resource_id                       = "db-KO64XXBAIKX7LFIJJJBK3RNGAQ" -> null
      - endpoint                              = "myservice-1.cgub7ocz2dps.us-west-2.rds.amazonaws.com" -> null
      - engine                                = "aurora-postgresql" -> null
      - engine_version                        = "11.9" -> null
      - engine_version_actual                 = "11.9" -> null
      - id                                    = "myservice-1" -> null
      - identifier                            = "myservice-1" -> null
      - instance_class                        = "db.t4g.medium" -> null
      - monitoring_interval                   = 0 -> null
      - network_type                          = "IPV4" -> null
      - performance_insights_enabled          = false -> null
      - performance_insights_retention_period = 0 -> null
      - port                                  = 5432 -> null
      - preferred_backup_window               = "10:24-10:54" -> null
      - preferred_maintenance_window          = "mon:06:12-mon:06:42" -> null
      - promotion_tier                        = 0 -> null
      - publicly_accessible                   = false -> null
      - storage_encrypted                     = false -> null
      - tags                                  = {} -> null
      - tags_all                              = {} -> null
      - writer                                = false -> null
    }

  # aws_rds_cluster_instance.db[2] will be destroyed
  - resource "aws_rds_cluster_instance" "db" {
      - apply_immediately                     = true -> null
      - arn                                   = "arn:aws:rds:us-west-2:4206942069:db:myservice-2" -> null
      - auto_minor_version_upgrade            = true -> null
      - availability_zone                     = "us-west-2a" -> null
      - ca_cert_identifier                    = "rds-ca-rsa2048-g1" -> null
      - cluster_identifier                    = "myservice" -> null
      - copy_tags_to_snapshot                 = false -> null
      - db_parameter_group_name               = "myservice" -> null
      - db_subnet_group_name                  = "myservice" -> null
      - dbi_resource_id                       = "db-GLJ73GCGDTFRSWPWJ67KKF2ER4" -> null
      - endpoint                              = "myservice-2.cgub7ocz2dps.us-west-2.rds.amazonaws.com" -> null
      - engine                                = "aurora-postgresql" -> null
      - engine_version                        = "11.9" -> null
      - engine_version_actual                 = "11.9" -> null
      - id                                    = "myservice-2" -> null
      - identifier                            = "myservice-2" -> null
      - instance_class                        = "db.t4g.medium" -> null
      - monitoring_interval                   = 0 -> null
      - network_type                          = "IPV4" -> null
      - performance_insights_enabled          = false -> null
      - performance_insights_retention_period = 0 -> null
      - port                                  = 5432 -> null
      - preferred_backup_window               = "10:24-10:54" -> null
      - preferred_maintenance_window          = "thu:06:40-thu:07:10" -> null
      - promotion_tier                        = 0 -> null
      - publicly_accessible                   = false -> null
      - storage_encrypted                     = false -> null
      - tags                                  = {} -> null
      - tags_all                              = {} -> null
      - writer                                = false -> null
    }

  # aws_rds_cluster_parameter_group.db will be destroyed
  - resource "aws_rds_cluster_parameter_group" "db" {
      - arn         = "arn:aws:rds:us-west-2:4206942069:cluster-pg:myservice" -> null
      - description = "Managed by Terraform" -> null
      - family      = "aurora-postgresql11" -> null
      - id          = "myservice" -> null
      - name        = "myservice" -> null
      - tags        = {} -> null
      - tags_all    = {} -> null
    }

  # aws_route53_record.acm["myservice.mydomain.io"] will be destroyed
  - resource "aws_route53_record" "acm" {
      - allow_overwrite                  = true -> null
      - fqdn                             = "_7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io" -> null
      - id                               = "Z4206969696969__7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io._CNAME" -> null
      - multivalue_answer_routing_policy = false -> null
      - name                             = "_7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io" -> null
      - records                          = [
          - "_4febf6b6f0cff746c39404be2b35c356.mhbtsbpdnt.acm-validations.aws.",
        ] -> null
      - ttl                              = 300 -> null
      - type                             = "CNAME" -> null
      - zone_id                          = "Z4206969696969" -> null
    }

  # aws_route53_record.myservice will be destroyed
  - resource "aws_route53_record" "myservice" {
      - fqdn                             = "myservice.mydomain.io" -> null
      - id                               = "Z4206969696969_myservice_A" -> null
      - multivalue_answer_routing_policy = false -> null
      - name                             = "myservice" -> null
      - records                          = [] -> null
      - ttl                              = 0 -> null
      - type                             = "A" -> null
      - zone_id                          = "Z4206969696969" -> null

      - alias {
          - evaluate_target_health = false -> null
          - name                   = "myservice-pub-819770937.us-west-2.elb.amazonaws.com" -> null
          - zone_id                = "Z1H1FL5HABSF5" -> null
        }
    }

  # aws_route53_record.myservice_db will be destroyed
  - resource "aws_route53_record" "myservice_db" {
      - fqdn                             = "myservice-db.mydomain.io" -> null
      - id                               = "Z4206969696969_myservice-db_CNAME" -> null
      - multivalue_answer_routing_policy = false -> null
      - name                             = "myservice-db" -> null
      - records                          = [
          - "myservice.cluster-cgub7ocz2dps.us-west-2.rds.amazonaws.com",
        ] -> null
      - ttl                              = 300 -> null
      - type                             = "CNAME" -> null
      - zone_id                          = "Z4206969696969" -> null
    }

  # aws_route53_record.myservice_db_reader will be destroyed
  - resource "aws_route53_record" "myservice_db_reader" {
      - fqdn                             = "myservice-db-reader.mydomain.io" -> null
      - id                               = "Z4206969696969_myservice-db-reader_CNAME" -> null
      - multivalue_answer_routing_policy = false -> null
      - name                             = "myservice-db-reader" -> null
      - records                          = [
          - "myservice.cluster-ro-cgub7ocz2dps.us-west-2.rds.amazonaws.com",
        ] -> null
      - ttl                              = 300 -> null
      - type                             = "CNAME" -> null
      - zone_id                          = "Z4206969696969" -> null
    }

  # aws_route53_record.myservice_ec2 will be destroyed
  - resource "aws_route53_record" "myservice_ec2" {
      - fqdn                             = "myservice-ec2.mydomain.io" -> null
      - id                               = "Z4206969696969_myservice-ec2_A" -> null
      - multivalue_answer_routing_policy = false -> null
      - name                             = "myservice-ec2" -> null
      - records                          = [
          - "52.43.231.215",
        ] -> null
      - ttl                              = 300 -> null
      - type                             = "A" -> null
      - zone_id                          = "Z4206969696969" -> null
    }

  # aws_security_group.alb_pub will be destroyed
  - resource "aws_security_group" "alb_pub" {
      - arn                    = "arn:aws:ec2:us-west-2:4206942069:security-group/sg-07c2efe5ed7e04199" -> null
      - description            = "myservice-alb-pub" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-07c2efe5ed7e04199" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 443
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 443
            },
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 80
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "tcp"
              - security_groups  = []
              - self             = false
              - to_port          = 80
            },
        ] -> null
      - name                   = "myservice-alb-pub" -> null
      - owner_id               = "4206942069" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "myservice-alb-pub"
        } -> null
      - tags_all               = {
          - "Name" = "myservice-alb-pub"
        } -> null
      - vpc_id                 = "vpc-00e246a40bce74dd8" -> null
    }

  # aws_security_group.db will be destroyed
  - resource "aws_security_group" "db" {
      - arn                    = "arn:aws:ec2:us-west-2:4206942069:security-group/sg-08bc83b69d3282783" -> null
      - description            = "myservice-db" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-08bc83b69d3282783" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "10.0.0.0/8",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - name                   = "myservice-db" -> null
      - owner_id               = "4206942069" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "myservice-db"
        } -> null
      - tags_all               = {
          - "Name" = "myservice-db"
        } -> null
      - vpc_id                 = "vpc-00e246a40bce74dd8" -> null
    }

  # aws_security_group.myservice will be destroyed
  - resource "aws_security_group" "myservice" {
      - arn                    = "arn:aws:ec2:us-west-2:4206942069:security-group/sg-0c493078a0e5e352e" -> null
      - description            = "myservice" -> null
      - egress                 = [
          - {
              - cidr_blocks      = [
                  - "0.0.0.0/0",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - id                     = "sg-0c493078a0e5e352e" -> null
      - ingress                = [
          - {
              - cidr_blocks      = [
                  - "10.0.0.0/8",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
          - {
              - cidr_blocks      = [
                  - "174.25.79.99/32",
                ]
              - description      = ""
              - from_port        = 0
              - ipv6_cidr_blocks = []
              - prefix_list_ids  = []
              - protocol         = "-1"
              - security_groups  = []
              - self             = false
              - to_port          = 0
            },
        ] -> null
      - name                   = "myservice" -> null
      - owner_id               = "4206942069" -> null
      - revoke_rules_on_delete = false -> null
      - tags                   = {
          - "Name" = "myservice"
        } -> null
      - tags_all               = {
          - "Name" = "myservice"
        } -> null
      - vpc_id                 = "vpc-00e246a40bce74dd8" -> null
    }

  # random_string.rds_password will be destroyed
  - resource "random_string" "rds_password" {
      - id          = "42069Magic42069" -> null
      - length      = 16 -> null
      - lower       = true -> null
      - min_lower   = 0 -> null
      - min_numeric = 0 -> null
      - min_special = 0 -> null
      - min_upper   = 0 -> null
      - number      = true -> null
      - numeric     = true -> null
      - result      = "42069Magic42069" -> null
      - special     = false -> null
      - upper       = true -> null
    }

Plan: 0 to add, 0 to change, 30 to destroy.

Changes to Outputs:
  - myservice             = "myservice.mydomain.io" -> null
  - myservice_db          = "myservice-db.mydomain.io" -> null
  - myservice_db_name     = "myservice" -> null
  - myservice_db_password = "42069Magic42069" -> null
  - myservice_db_reader   = "myservice-db-reader.mydomain.io" -> null
  - myservice_db_username = "myservice" -> null
  - myservice_ec2         = "myservice-ec2.mydomain.io" -> null

Do you really want to destroy all resources?
  Terraform will destroy all your managed infrastructure, as shown above.
  There is no undo. Only 'yes' will be accepted to confirm.

  Enter a value: yes

aws_alb_listener_certificate.myservice: Destroying... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e_arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57]
aws_alb_target_group_attachment.myservice: Destroying... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448-20240317134559915600000004]
aws_route53_record.myservice: Destroying... [id=Z4206969696969_myservice_A]
aws_rds_cluster_instance.db[1]: Destroying... [id=myservice-1]
aws_route53_record.myservice_ec2: Destroying... [id=Z4206969696969_myservice-ec2_A]
aws_rds_cluster_instance.db[2]: Destroying... [id=myservice-2]
aws_alb_listener.alb_pub_http: Destroying... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/4c51557166dc2469]
aws_alb_listener_rule.myservice: Destroying... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener-rule/app/myservice-pub/6f90586e614a1eca/b0840678603db37e/b9f58463ce1b971f]
aws_rds_cluster_instance.db[0]: Destroying... [id=myservice-0]
aws_route53_record.myservice_db: Destroying... [id=Z4206969696969_myservice-db_CNAME]
aws_alb_target_group_attachment.myservice: Destruction complete after 0s
aws_route53_record.myservice_db_reader: Destroying... [id=Z4206969696969_myservice-db-reader_CNAME]
aws_alb_listener_certificate.myservice: Destruction complete after 0s
aws_iam_role_policy_attachment.myservice_s3: Destroying... [id=myservice-20240317134536547700000002]
aws_alb_listener_rule.myservice: Destruction complete after 0s
aws_alb_listener.alb_pub_https: Destroying... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e]
aws_alb_listener.alb_pub_http: Destruction complete after 0s
aws_alb_target_group.myservice: Destroying... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448]
aws_alb_listener.alb_pub_https: Destruction complete after 0s
aws_acm_certificate_validation.acm: Destroying... [id=2024-03-17 13:45:49.634 +0000 UTC]
aws_acm_certificate_validation.acm: Destruction complete after 0s
aws_route53_record.acm["myservice.mydomain.io"]: Destroying... [id=Z4206969696969__7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io._CNAME]
aws_alb_target_group.myservice: Destruction complete after 0s
aws_iam_role_policy_attachment.myservice_s3: Destruction complete after 0s
aws_route53_record.myservice: Still destroying... [id=Z4206969696969_myservice_A, 10s elapsed]
aws_route53_record.myservice_db: Still destroying... [id=Z4206969696969_myservice-db_CNAME, 10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 10s elapsed]
aws_route53_record.myservice_ec2: Still destroying... [id=Z4206969696969_myservice-ec2_A, 10s elapsed]
aws_route53_record.myservice_db_reader: Still destroying... [id=Z4206969696969_myservice-db-reader_CNAME, 10s elapsed]
aws_route53_record.acm["myservice.mydomain.io"]: Still destroying... [id=Z4206969696969__7f796e8e33a4fb74f...48e0939503.myservice.mydomain.io._CNAME, 10s elapsed]
aws_route53_record.myservice_db: Still destroying... [id=Z4206969696969_myservice-db_CNAME, 20s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 20s elapsed]
aws_route53_record.myservice: Still destroying... [id=Z4206969696969_myservice_A, 20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 20s elapsed]
aws_route53_record.myservice_ec2: Still destroying... [id=Z4206969696969_myservice-ec2_A, 20s elapsed]
aws_route53_record.myservice_db_reader: Still destroying... [id=Z4206969696969_myservice-db-reader_CNAME, 20s elapsed]
aws_route53_record.acm["myservice.mydomain.io"]: Still destroying... [id=Z4206969696969__7f796e8e33a4fb74f...48e0939503.myservice.mydomain.io._CNAME, 20s elapsed]
aws_route53_record.myservice_ec2: Still destroying... [id=Z4206969696969_myservice-ec2_A, 30s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 30s elapsed]
aws_route53_record.myservice: Still destroying... [id=Z4206969696969_myservice_A, 30s elapsed]
aws_route53_record.myservice_db: Still destroying... [id=Z4206969696969_myservice-db_CNAME, 30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 30s elapsed]
aws_route53_record.myservice_db_reader: Still destroying... [id=Z4206969696969_myservice-db-reader_CNAME, 30s elapsed]
aws_route53_record.acm["myservice.mydomain.io"]: Still destroying... [id=Z4206969696969__7f796e8e33a4fb74f...48e0939503.myservice.mydomain.io._CNAME, 30s elapsed]
aws_route53_record.myservice_db_reader: Destruction complete after 32s
aws_route53_record.acm["myservice.mydomain.io"]: Destruction complete after 33s
aws_acm_certificate.acm: Destroying... [id=arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57]
aws_acm_certificate.acm: Destruction complete after 0s
aws_route53_record.myservice_ec2: Destruction complete after 36s
aws_instance.myservice: Destroying... [id=i-07791e678df153e86]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 40s elapsed]
aws_route53_record.myservice: Still destroying... [id=Z4206969696969_myservice_A, 40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 40s elapsed]
aws_route53_record.myservice_db: Still destroying... [id=Z4206969696969_myservice-db_CNAME, 40s elapsed]
aws_route53_record.myservice_db: Destruction complete after 40s
aws_route53_record.myservice: Destruction complete after 42s
aws_alb.alb_pub: Destroying... [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca]
aws_alb.alb_pub: Destruction complete after 2s
aws_security_group.alb_pub: Destroying... [id=sg-07c2efe5ed7e04199]
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 50s elapsed]
aws_security_group.alb_pub: Still destroying... [id=sg-07c2efe5ed7e04199, 10s elapsed]
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 1m0s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 1m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 1m0s elapsed]
aws_security_group.alb_pub: Still destroying... [id=sg-07c2efe5ed7e04199, 20s elapsed]
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 1m10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 1m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 1m10s elapsed]
aws_security_group.alb_pub: Still destroying... [id=sg-07c2efe5ed7e04199, 30s elapsed]
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 1m20s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 1m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 1m20s elapsed]
aws_security_group.alb_pub: Destruction complete after 37s
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 1m30s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 1m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 1m30s elapsed]
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 1m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 1m40s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 1m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 1m40s elapsed]
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 1m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 1m50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 1m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 1m50s elapsed]
aws_instance.myservice: Still destroying... [id=i-07791e678df153e86, 1m20s elapsed]
aws_instance.myservice: Destruction complete after 1m21s
aws_iam_instance_profile.myservice: Destroying... [id=myservice]
aws_key_pair.myservice: Destroying... [id=myservice]
aws_security_group.myservice: Destroying... [id=sg-0c493078a0e5e352e]
aws_key_pair.myservice: Destruction complete after 0s
aws_iam_instance_profile.myservice: Destruction complete after 0s
aws_iam_role.myservice: Destroying... [id=myservice]
aws_security_group.myservice: Destruction complete after 1s
aws_iam_role.myservice: Destruction complete after 1s
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 2m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 2m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 2m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 2m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 2m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 2m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 2m20s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 2m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 2m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 2m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 2m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 2m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 2m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 2m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 2m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 2m50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 2m50s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 2m50s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 3m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 3m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 3m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 3m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 3m10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 3m10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 3m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 3m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 3m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 3m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 3m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 3m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 3m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 3m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 3m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 3m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 3m50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 3m50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 4m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 4m0s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 4m0s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 4m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 4m10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 4m10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 4m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 4m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 4m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 4m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 4m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 4m30s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 4m40s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 4m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 4m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 4m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 4m50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 4m50s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 5m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 5m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 5m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 5m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 5m10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 5m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 5m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 5m20s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 5m20s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 5m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 5m30s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 5m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 5m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 5m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 5m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 5m50s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 5m50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 5m50s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 6m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 6m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 6m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 6m10s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 6m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 6m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 6m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 6m20s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 6m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 6m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 6m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 6m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 6m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 6m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 6m40s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 6m50s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 6m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 6m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 7m0s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 7m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 7m0s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 7m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 7m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 7m10s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 7m20s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 7m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 7m20s elapsed]
aws_rds_cluster_instance.db[2]: Still destroying... [id=myservice-2, 7m30s elapsed]
aws_rds_cluster_instance.db[0]: Still destroying... [id=myservice-0, 7m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 7m30s elapsed]
aws_rds_cluster_instance.db[0]: Destruction complete after 7m35s
aws_rds_cluster_instance.db[2]: Destruction complete after 7m35s
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 7m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 7m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 8m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 8m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 8m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 8m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 8m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 8m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 9m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 9m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 9m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 9m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 9m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 9m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 10m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 10m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 10m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 10m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 10m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 10m50s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 11m0s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 11m10s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 11m20s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 11m30s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 11m40s elapsed]
aws_rds_cluster_instance.db[1]: Still destroying... [id=myservice-1, 11m50s elapsed]
aws_rds_cluster_instance.db[1]: Destruction complete after 11m59s
aws_db_parameter_group.db: Destroying... [id=myservice]
aws_rds_cluster.db: Destroying... [id=myservice]
aws_db_parameter_group.db: Destruction complete after 0s
aws_rds_cluster.db: Still destroying... [id=myservice, 10s elapsed]
aws_rds_cluster.db: Still destroying... [id=myservice, 20s elapsed]
aws_rds_cluster.db: Still destroying... [id=myservice, 30s elapsed]
aws_rds_cluster.db: Still destroying... [id=myservice, 40s elapsed]
aws_rds_cluster.db: Still destroying... [id=myservice, 50s elapsed]
aws_rds_cluster.db: Still destroying... [id=myservice, 1m0s elapsed]
aws_rds_cluster.db: Still destroying... [id=myservice, 1m10s elapsed]
aws_rds_cluster.db: Destruction complete after 1m10s
aws_rds_cluster_parameter_group.db: Destroying... [id=myservice]
aws_db_subnet_group.db: Destroying... [id=myservice]
aws_security_group.db: Destroying... [id=sg-08bc83b69d3282783]
random_string.rds_password: Destroying... [id=42069Magic42069]
random_string.rds_password: Destruction complete after 0s
aws_rds_cluster_parameter_group.db: Destruction complete after 0s
aws_db_subnet_group.db: Destruction complete after 1s
aws_security_group.db: Destruction complete after 1s

Destroy complete! Resources: 30 destroyed.
```