## Sample output from `terraform apply` with a total of 30 resources

```
basit in ~/Documents/myservice-devops-aws-tf on main λ terraform apply
data.aws_ami.myservice: Reading...
data.aws_iam_policy_document.myservice: Reading...
data.aws_iam_policy_document.myservice: Read complete after 0s [id=2851119427]
data.aws_ami.myservice: Read complete after 0s [id=ami-0694204204208b19d]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_acm_certificate.acm will be created
  + resource "aws_acm_certificate" "acm" {
      + arn                       = (known after apply)
      + domain_name               = "myservice.mydomain.io"
      + domain_validation_options = [
          + {
              + domain_name           = "myservice.mydomain.io"
              + resource_record_name  = (known after apply)
              + resource_record_type  = (known after apply)
              + resource_record_value = (known after apply)
            },
        ]
      + id                        = (known after apply)
      + key_algorithm             = (known after apply)
      + not_after                 = (known after apply)
      + not_before                = (known after apply)
      + pending_renewal           = (known after apply)
      + renewal_eligibility       = (known after apply)
      + renewal_summary           = (known after apply)
      + status                    = (known after apply)
      + subject_alternative_names = [
          + "myservice.mydomain.io",
        ]
      + tags_all                  = (known after apply)
      + type                      = (known after apply)
      + validation_emails         = (known after apply)
      + validation_method         = "DNS"
    }

  # aws_acm_certificate_validation.acm will be created
  + resource "aws_acm_certificate_validation" "acm" {
      + certificate_arn         = (known after apply)
      + id                      = (known after apply)
      + validation_record_fqdns = (known after apply)
    }

  # aws_alb.alb_pub will be created
  + resource "aws_alb" "alb_pub" {
      + arn                                                          = (known after apply)
      + arn_suffix                                                   = (known after apply)
      + desync_mitigation_mode                                       = "defensive"
      + dns_name                                                     = (known after apply)
      + drop_invalid_header_fields                                   = false
      + enable_deletion_protection                                   = false
      + enable_http2                                                 = true
      + enable_tls_version_and_cipher_suite_headers                  = false
      + enable_waf_fail_open                                         = false
      + enable_xff_client_port                                       = false
      + enforce_security_group_inbound_rules_on_private_link_traffic = (known after apply)
      + id                                                           = (known after apply)
      + idle_timeout                                                 = 60
      + internal                                                     = false
      + ip_address_type                                              = (known after apply)
      + load_balancer_type                                           = "application"
      + name                                                         = "myservice-pub"
      + name_prefix                                                  = (known after apply)
      + preserve_host_header                                         = false
      + security_groups                                              = (known after apply)
      + subnets                                                      = [
          + "subnet-0490ec6d7ca42a49d",
          + "subnet-0826ac0b500f4b37c",
          + "subnet-099968b8d0d26f998",
          + "subnet-0ae21b6bac4a2f923",
        ]
      + tags                                                         = {
          + "Name" = "myservice-alb-pub"
        }
      + tags_all                                                     = {
          + "Name" = "myservice-alb-pub"
        }
      + vpc_id                                                       = (known after apply)
      + xff_header_processing_mode                                   = "append"
      + zone_id                                                      = (known after apply)

      + timeouts {
          + create = "30m"
          + delete = "30m"
          + update = "30m"
        }
    }

  # aws_alb_listener.alb_pub_http will be created
  + resource "aws_alb_listener" "alb_pub_http" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 80
      + protocol          = "HTTP"
      + ssl_policy        = (known after apply)
      + tags_all          = (known after apply)

      + default_action {
          + order = (known after apply)
          + type  = "redirect"

          + redirect {
              + host        = "#{host}"
              + path        = "/#{path}"
              + port        = "443"
              + protocol    = "HTTPS"
              + query       = "#{query}"
              + status_code = "HTTP_301"
            }
        }
    }

  # aws_alb_listener.alb_pub_https will be created
  + resource "aws_alb_listener" "alb_pub_https" {
      + arn               = (known after apply)
      + certificate_arn   = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 443
      + protocol          = "HTTPS"
      + ssl_policy        = "ELBSecurityPolicy-2016-08"
      + tags_all          = (known after apply)

      + default_action {
          + order = (known after apply)
          + type  = "redirect"

          + redirect {
              + host        = "mydomain.io"
              + path        = "/#{path}"
              + port        = "443"
              + protocol    = "HTTPS"
              + query       = "#{query}"
              + status_code = "HTTP_301"
            }
        }
    }

  # aws_alb_listener_certificate.myservice will be created
  + resource "aws_alb_listener_certificate" "myservice" {
      + certificate_arn = (known after apply)
      + id              = (known after apply)
      + listener_arn    = (known after apply)
    }

  # aws_alb_listener_rule.myservice will be created
  + resource "aws_alb_listener_rule" "myservice" {
      + arn          = (known after apply)
      + id           = (known after apply)
      + listener_arn = (known after apply)
      + priority     = 20
      + tags_all     = (known after apply)

      + action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }

      + condition {
          + host_header {
              + values = [
                  + "myservice.mydomain.io",
                ]
            }
        }
    }

  # aws_alb_target_group.myservice will be created
  + resource "aws_alb_target_group" "myservice" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + connection_termination             = (known after apply)
      + deregistration_delay               = "0"
      + id                                 = (known after apply)
      + ip_address_type                    = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancer_arns                 = (known after apply)
      + load_balancing_algorithm_type      = (known after apply)
      + load_balancing_anomaly_mitigation  = (known after apply)
      + load_balancing_cross_zone_enabled  = (known after apply)
      + name                               = "myservice"
      + name_prefix                        = (known after apply)
      + port                               = 80
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "HTTP"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = "vpc-00e246a40bce74dd8"

      + health_check {
          + enabled             = true
          + healthy_threshold   = 2
          + interval            = 120
          + matcher             = "200"
          + path                = (known after apply)
          + port                = "traffic-port"
          + protocol            = "HTTP"
          + timeout             = 60
          + unhealthy_threshold = 4
        }
    }

  # aws_alb_target_group_attachment.myservice will be created
  + resource "aws_alb_target_group_attachment" "myservice" {
      + id               = (known after apply)
      + port             = 80
      + target_group_arn = (known after apply)
      + target_id        = (known after apply)
    }

  # aws_db_parameter_group.db will be created
  + resource "aws_db_parameter_group" "db" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + family      = "aurora-postgresql11"
      + id          = (known after apply)
      + name        = "myservice"
      + name_prefix = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_db_subnet_group.db will be created
  + resource "aws_db_subnet_group" "db" {
      + arn                     = (known after apply)
      + description             = "myservice"
      + id                      = (known after apply)
      + name                    = "myservice"
      + name_prefix             = (known after apply)
      + subnet_ids              = [
          + "subnet-00a1422e78ea03c88",
          + "subnet-08211bf789d64e791",
          + "subnet-08702d1b7553207fb",
          + "subnet-0f2c0fa276216d000",
        ]
      + supported_network_types = (known after apply)
      + tags                    = {
          + "Name" = "myservice"
        }
      + tags_all                = {
          + "Name" = "myservice"
        }
      + vpc_id                  = (known after apply)
    }

  # aws_iam_instance_profile.myservice will be created
  + resource "aws_iam_instance_profile" "myservice" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "myservice"
      + name_prefix = (known after apply)
      + path        = "/"
      + role        = "myservice"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.myservice will be created
  + resource "aws_iam_role" "myservice" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "myservice"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)
    }

  # aws_iam_role_policy_attachment.myservice_s3 will be created
  + resource "aws_iam_role_policy_attachment" "myservice_s3" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
      + role       = "myservice"
    }

  # aws_instance.myservice will be created
  + resource "aws_instance" "myservice" {
      + ami                                  = "ami-069e7c74c7628b19d"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = (known after apply)
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_stop                     = (known after apply)
      + disable_api_termination              = (known after apply)
      + ebs_optimized                        = true
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + host_resource_group_arn              = (known after apply)
      + iam_instance_profile                 = "myservice"
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_lifecycle                   = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t4g.medium"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "myservice"
      + monitoring                           = true
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + spot_instance_request_id             = (known after apply)
      + subnet_id                            = "subnet-0826ac0b500f4b37c"
      + tags                                 = {
          + "Name" = "myservice"
        }
      + tags_all                             = {
          + "Name" = "myservice"
        }
      + tenancy                              = (known after apply)
      + user_data                            = (known after apply)
      + user_data_base64                     = (known after apply)
      + user_data_replace_on_change          = false
      + vpc_security_group_ids               = (known after apply)
    }

  # aws_key_pair.myservice will be created
  + resource "aws_key_pair" "myservice" {
      + arn             = (known after apply)
      + fingerprint     = (known after apply)
      + id              = (known after apply)
      + key_name        = "myservice"
      + key_name_prefix = (known after apply)
      + key_pair_id     = (known after apply)
      + key_type        = (known after apply)
      + public_key      = "ssh-rsa AAAAB3NzaC1yc2EAAAADA= basit@shehram.com"
      + tags_all        = (known after apply)
    }

  # aws_rds_cluster.db will be created
  + resource "aws_rds_cluster" "db" {
      + allocated_storage               = (known after apply)
      + apply_immediately               = (known after apply)
      + arn                             = (known after apply)
      + availability_zones              = (known after apply)
      + backup_retention_period         = 7
      + cluster_identifier              = "myservice"
      + cluster_identifier_prefix       = (known after apply)
      + cluster_members                 = (known after apply)
      + cluster_resource_id             = (known after apply)
      + copy_tags_to_snapshot           = false
      + database_name                   = "myservice"
      + db_cluster_parameter_group_name = (known after apply)
      + db_subnet_group_name            = (known after apply)
      + db_system_id                    = (known after apply)
      + delete_automated_backups        = true
      + enable_global_write_forwarding  = false
      + enable_http_endpoint            = false
      + endpoint                        = (known after apply)
      + engine                          = "aurora-postgresql"
      + engine_mode                     = "provisioned"
      + engine_version                  = "11.9"
      + engine_version_actual           = (known after apply)
      + hosted_zone_id                  = (known after apply)
      + iam_roles                       = (known after apply)
      + id                              = (known after apply)
      + kms_key_id                      = (known after apply)
      + master_password                 = (sensitive value)
      + master_user_secret              = (known after apply)
      + master_user_secret_kms_key_id   = (known after apply)
      + master_username                 = "myservice"
      + network_type                    = (known after apply)
      + port                            = (known after apply)
      + preferred_backup_window         = (known after apply)
      + preferred_maintenance_window    = (known after apply)
      + reader_endpoint                 = (known after apply)
      + skip_final_snapshot             = true
      + storage_encrypted               = (known after apply)
      + storage_type                    = (known after apply)
      + tags                            = {
          + "Name" = "myservice"
        }
      + tags_all                        = {
          + "Name" = "myservice"
        }
      + vpc_security_group_ids          = (known after apply)
    }

  # aws_rds_cluster_instance.db[0] will be created
  + resource "aws_rds_cluster_instance" "db" {
      + apply_immediately                     = true
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + cluster_identifier                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_parameter_group_name               = (known after apply)
      + db_subnet_group_name                  = (known after apply)
      + dbi_resource_id                       = (known after apply)
      + endpoint                              = (known after apply)
      + engine                                = "aurora-postgresql"
      + engine_version                        = "11.9"
      + engine_version_actual                 = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = "myservice-0"
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t4g.medium"
      + kms_key_id                            = (known after apply)
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + network_type                          = (known after apply)
      + performance_insights_enabled          = (known after apply)
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = (known after apply)
      + preferred_backup_window               = (known after apply)
      + preferred_maintenance_window          = (known after apply)
      + promotion_tier                        = 0
      + publicly_accessible                   = (known after apply)
      + storage_encrypted                     = (known after apply)
      + tags_all                              = (known after apply)
      + writer                                = (known after apply)
    }

  # aws_rds_cluster_instance.db[1] will be created
  + resource "aws_rds_cluster_instance" "db" {
      + apply_immediately                     = true
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + cluster_identifier                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_parameter_group_name               = (known after apply)
      + db_subnet_group_name                  = (known after apply)
      + dbi_resource_id                       = (known after apply)
      + endpoint                              = (known after apply)
      + engine                                = "aurora-postgresql"
      + engine_version                        = "11.9"
      + engine_version_actual                 = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = "myservice-1"
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t4g.medium"
      + kms_key_id                            = (known after apply)
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + network_type                          = (known after apply)
      + performance_insights_enabled          = (known after apply)
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = (known after apply)
      + preferred_backup_window               = (known after apply)
      + preferred_maintenance_window          = (known after apply)
      + promotion_tier                        = 0
      + publicly_accessible                   = (known after apply)
      + storage_encrypted                     = (known after apply)
      + tags_all                              = (known after apply)
      + writer                                = (known after apply)
    }

  # aws_rds_cluster_instance.db[2] will be created
  + resource "aws_rds_cluster_instance" "db" {
      + apply_immediately                     = true
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + cluster_identifier                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_parameter_group_name               = (known after apply)
      + db_subnet_group_name                  = (known after apply)
      + dbi_resource_id                       = (known after apply)
      + endpoint                              = (known after apply)
      + engine                                = "aurora-postgresql"
      + engine_version                        = "11.9"
      + engine_version_actual                 = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = "myservice-2"
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t4g.medium"
      + kms_key_id                            = (known after apply)
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + network_type                          = (known after apply)
      + performance_insights_enabled          = (known after apply)
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = (known after apply)
      + preferred_backup_window               = (known after apply)
      + preferred_maintenance_window          = (known after apply)
      + promotion_tier                        = 0
      + publicly_accessible                   = (known after apply)
      + storage_encrypted                     = (known after apply)
      + tags_all                              = (known after apply)
      + writer                                = (known after apply)
    }

  # aws_rds_cluster_parameter_group.db will be created
  + resource "aws_rds_cluster_parameter_group" "db" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + family      = "aurora-postgresql11"
      + id          = (known after apply)
      + name        = "myservice"
      + name_prefix = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_route53_record.acm["myservice.mydomain.io"] will be created
  + resource "aws_route53_record" "acm" {
      + allow_overwrite = true
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = (known after apply)
      + records         = (known after apply)
      + ttl             = 300
      + type            = (known after apply)
      + zone_id         = "Z420696969"
    }

  # aws_route53_record.myservice will be created
  + resource "aws_route53_record" "myservice" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "myservice"
      + type            = "A"
      + zone_id         = "Z420696969"

      + alias {
          + evaluate_target_health = false
          + name                   = (known after apply)
          + zone_id                = (known after apply)
        }
    }

  # aws_route53_record.myservice_db will be created
  + resource "aws_route53_record" "myservice_db" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "myservice-db"
      + records         = (known after apply)
      + ttl             = 300
      + type            = "CNAME"
      + zone_id         = "Z420696969"
    }

  # aws_route53_record.myservice_db_reader will be created
  + resource "aws_route53_record" "myservice_db_reader" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "myservice-db-reader"
      + records         = (known after apply)
      + ttl             = 300
      + type            = "CNAME"
      + zone_id         = "Z420696969"
    }

  # aws_route53_record.myservice_ec2 will be created
  + resource "aws_route53_record" "myservice_ec2" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "myservice-ec2"
      + records         = (known after apply)
      + ttl             = 300
      + type            = "A"
      + zone_id         = "Z420696969"
    }

  # aws_security_group.alb_pub will be created
  + resource "aws_security_group" "alb_pub" {
      + arn                    = (known after apply)
      + description            = "myservice-alb-pub"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
        ]
      + name                   = "myservice-alb-pub"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "myservice-alb-pub"
        }
      + tags_all               = {
          + "Name" = "myservice-alb-pub"
        }
      + vpc_id                 = "vpc-00e246a40bce74dd8"
    }

  # aws_security_group.db will be created
  + resource "aws_security_group" "db" {
      + arn                    = (known after apply)
      + description            = "myservice-db"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "10.0.0.0/8",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + name                   = "myservice-db"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "myservice-db"
        }
      + tags_all               = {
          + "Name" = "myservice-db"
        }
      + vpc_id                 = "vpc-00e246a40bce74dd8"
    }

  # aws_security_group.myservice will be created
  + resource "aws_security_group" "myservice" {
      + arn                    = (known after apply)
      + description            = "myservice"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "10.0.0.0/8",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
          + {
              + cidr_blocks      = [
                  + "174.25.79.99/32",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + name                   = "myservice"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "myservice"
        }
      + tags_all               = {
          + "Name" = "myservice"
        }
      + vpc_id                 = "vpc-00e246a40bce74dd8"
    }

  # random_string.rds_password will be created
  + resource "random_string" "rds_password" {
      + id          = (known after apply)
      + length      = 16
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

Plan: 30 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + myservice             = (known after apply)
  + myservice_db          = (known after apply)
  + myservice_db_name     = "myservice"
  + myservice_db_password = (known after apply)
  + myservice_db_reader   = (known after apply)
  + myservice_db_username = "myservice"
  + myservice_ec2         = (known after apply)

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

random_string.rds_password: Creating...
random_string.rds_password: Creation complete after 0s [id=OYW81KGJPyJRfnvz]
aws_key_pair.myservice: Creating...
aws_rds_cluster_parameter_group.db: Creating...
aws_db_subnet_group.db: Creating...
aws_iam_role.myservice: Creating...
aws_acm_certificate.acm: Creating...
aws_db_parameter_group.db: Creating...
aws_security_group.db: Creating...
aws_alb_target_group.myservice: Creating...
aws_security_group.alb_pub: Creating...
aws_security_group.myservice: Creating...
aws_key_pair.myservice: Creation complete after 0s [id=myservice]
aws_db_parameter_group.db: Creation complete after 0s [id=myservice]
aws_iam_role.myservice: Creation complete after 0s [id=myservice]
aws_iam_role_policy_attachment.myservice_s3: Creating...
aws_iam_instance_profile.myservice: Creating...
aws_alb_target_group.myservice: Creation complete after 0s [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448]
aws_db_subnet_group.db: Creation complete after 1s [id=myservice]
aws_rds_cluster_parameter_group.db: Creation complete after 1s [id=myservice]
aws_iam_role_policy_attachment.myservice_s3: Creation complete after 1s [id=myservice-20240317134536547700000002]
aws_iam_instance_profile.myservice: Creation complete after 1s [id=myservice]
aws_security_group.myservice: Creation complete after 2s [id=sg-0c493078a0e5e352e]
aws_security_group.alb_pub: Creation complete after 2s [id=sg-07c2efe5ed7e04199]
aws_instance.myservice: Creating...
aws_alb.alb_pub: Creating...
aws_security_group.db: Creation complete after 2s [id=sg-08bc83b69d3282783]
aws_rds_cluster.db: Creating...
aws_acm_certificate.acm: Creation complete after 5s [id=arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57]
aws_route53_record.acm["myservice.mydomain.io"]: Creating...
aws_instance.myservice: Still creating... [10s elapsed]
aws_alb.alb_pub: Still creating... [10s elapsed]
aws_rds_cluster.db: Still creating... [10s elapsed]
aws_route53_record.acm["myservice.mydomain.io"]: Still creating... [10s elapsed]
aws_instance.myservice: Still creating... [20s elapsed]
aws_alb.alb_pub: Still creating... [20s elapsed]
aws_rds_cluster.db: Still creating... [20s elapsed]
aws_instance.myservice: Creation complete after 22s [id=i-07791e678df153e86]
aws_alb_target_group_attachment.myservice: Creating...
aws_route53_record.myservice_ec2: Creating...
aws_alb_target_group_attachment.myservice: Creation complete after 0s [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:targetgroup/myservice/3ebdb431db91c448-20240317134559915600000004]
aws_route53_record.acm["myservice.mydomain.io"]: Still creating... [20s elapsed]
aws_alb.alb_pub: Still creating... [30s elapsed]
aws_rds_cluster.db: Still creating... [30s elapsed]
aws_route53_record.myservice_ec2: Still creating... [10s elapsed]
aws_route53_record.acm["myservice.mydomain.io"]: Still creating... [30s elapsed]
aws_alb.alb_pub: Still creating... [40s elapsed]
aws_rds_cluster.db: Still creating... [40s elapsed]
aws_route53_record.myservice_ec2: Still creating... [20s elapsed]
aws_route53_record.acm["myservice.mydomain.io"]: Still creating... [40s elapsed]
aws_route53_record.acm["myservice.mydomain.io"]: Creation complete after 45s [id=Z420696969__7f796e8e33a4fb74f3f91048e0939503.myservice.mydomain.io._CNAME]
aws_acm_certificate_validation.acm: Creating...
aws_acm_certificate_validation.acm: Creation complete after 0s [id=2024-03-17 13:45:49.634 +0000 UTC]
aws_alb.alb_pub: Still creating... [50s elapsed]
aws_rds_cluster.db: Still creating... [50s elapsed]
aws_route53_record.myservice_ec2: Still creating... [30s elapsed]
aws_route53_record.myservice_ec2: Creation complete after 36s [id=Z420696969_myservice-ec2_A]
aws_alb.alb_pub: Still creating... [1m0s elapsed]
aws_rds_cluster.db: Still creating... [1m0s elapsed]
aws_rds_cluster.db: Creation complete after 1m1s [id=myservice]
aws_rds_cluster_instance.db[0]: Creating...
aws_route53_record.myservice_db_reader: Creating...
aws_route53_record.myservice_db: Creating...
aws_rds_cluster_instance.db[2]: Creating...
aws_rds_cluster_instance.db[1]: Creating...
aws_alb.alb_pub: Still creating... [1m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [10s elapsed]
aws_route53_record.myservice_db: Still creating... [10s elapsed]
aws_route53_record.myservice_db_reader: Still creating... [10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [10s elapsed]
aws_alb.alb_pub: Still creating... [1m20s elapsed]
aws_route53_record.myservice_db_reader: Still creating... [20s elapsed]
aws_route53_record.myservice_db: Still creating... [20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [20s elapsed]
aws_alb.alb_pub: Still creating... [1m30s elapsed]
aws_route53_record.myservice_db: Still creating... [30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [30s elapsed]
aws_route53_record.myservice_db_reader: Still creating... [30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [30s elapsed]
aws_alb.alb_pub: Still creating... [1m40s elapsed]
aws_route53_record.myservice_db: Creation complete after 39s [id=Z420696969_myservice-db_CNAME]
aws_route53_record.myservice_db_reader: Still creating... [40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [40s elapsed]
aws_alb.alb_pub: Still creating... [1m50s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [50s elapsed]
aws_route53_record.myservice_db_reader: Still creating... [50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [50s elapsed]
aws_route53_record.myservice_db_reader: Creation complete after 57s [id=Z420696969_myservice-db-reader_CNAME]
aws_alb.alb_pub: Still creating... [2m0s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [1m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [1m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [1m0s elapsed]
aws_alb.alb_pub: Still creating... [2m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [1m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [1m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [1m10s elapsed]
aws_alb.alb_pub: Still creating... [2m20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [1m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [1m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [1m20s elapsed]
aws_alb.alb_pub: Still creating... [2m30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [1m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [1m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [1m30s elapsed]
aws_alb.alb_pub: Still creating... [2m40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [1m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [1m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [1m40s elapsed]
aws_alb.alb_pub: Creation complete after 2m42s [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:loadbalancer/app/myservice-pub/6f90586e614a1eca]
aws_route53_record.myservice: Creating...
aws_alb_listener.alb_pub_https: Creating...
aws_alb_listener.alb_pub_http: Creating...
aws_alb_listener.alb_pub_http: Creation complete after 0s [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/4c51557166dc2469]
aws_alb_listener.alb_pub_https: Creation complete after 0s [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e]
aws_alb_listener_certificate.myservice: Creating...
aws_alb_listener_rule.myservice: Creating...
aws_alb_listener_certificate.myservice: Creation complete after 0s [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener/app/myservice-pub/6f90586e614a1eca/b0840678603db37e_arn:aws:acm:us-west-2:4206942069:certificate/7b3b6efc-b4d7-41ee-b0cf-4fff12a6df57]
aws_alb_listener_rule.myservice: Creation complete after 0s [id=arn:aws:elasticloadbalancing:us-west-2:4206942069:listener-rule/app/myservice-pub/6f90586e614a1eca/b0840678603db37e/b9f58463ce1b971f]
aws_rds_cluster_instance.db[0]: Still creating... [1m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [1m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [1m50s elapsed]
aws_route53_record.myservice: Still creating... [10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [2m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [2m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [2m0s elapsed]
aws_route53_record.myservice: Still creating... [20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [2m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [2m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [2m10s elapsed]
aws_route53_record.myservice: Still creating... [30s elapsed]
aws_route53_record.myservice: Creation complete after 35s [id=Z420696969_myservice_A]
aws_rds_cluster_instance.db[0]: Still creating... [2m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [2m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [2m20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [2m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [2m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [2m30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [2m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [2m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [2m40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [2m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [2m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [2m50s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [3m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [3m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [3m0s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [3m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [3m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [3m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [3m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [3m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [3m20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [3m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [3m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [3m30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [3m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [3m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [3m40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [3m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [3m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [3m50s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [4m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [4m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [4m0s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [4m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [4m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [4m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [4m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [4m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [4m20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [4m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [4m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [4m30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [4m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [4m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [4m40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [4m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [4m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [4m50s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [5m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [5m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [5m0s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [5m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [5m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [5m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [5m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [5m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [5m20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [5m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [5m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [5m30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [5m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [5m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [5m40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [5m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [5m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [5m50s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [6m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [6m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [6m0s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [6m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [6m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [6m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [6m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [6m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [6m20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [6m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [6m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [6m30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [6m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [6m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [6m40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [6m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [6m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [6m50s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [7m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [7m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [7m0s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [7m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [7m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [7m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [7m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [7m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [7m20s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [7m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [7m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [7m30s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [7m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [7m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [7m40s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [7m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [7m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [7m50s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [8m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [8m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [8m0s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [8m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [8m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [8m10s elapsed]
aws_rds_cluster_instance.db[0]: Still creating... [8m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [8m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [8m20s elapsed]
aws_rds_cluster_instance.db[0]: Creation complete after 8m29s [id=myservice-0]
aws_rds_cluster_instance.db[2]: Still creating... [8m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [8m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [8m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [8m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [8m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [8m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [9m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [9m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [9m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [9m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [9m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [9m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [9m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [9m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [9m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [9m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [9m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [9m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [10m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [10m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [10m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [10m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [10m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [10m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [10m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [10m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [10m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [10m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [10m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [10m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [11m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [11m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [11m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [11m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [11m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [11m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [11m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [11m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [11m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [11m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [11m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [11m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [12m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [12m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [12m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [12m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [12m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [12m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [12m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [12m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [12m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [12m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [12m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [12m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [13m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [13m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [13m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [13m10s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [13m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [13m20s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [13m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [13m30s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [13m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [13m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [13m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [13m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [14m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [14m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [14m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [14m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [14m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [14m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [14m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [14m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [14m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [14m40s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [14m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [14m50s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [15m0s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [15m0s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [15m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [15m10s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [15m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [15m20s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [15m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [15m30s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [15m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [15m40s elapsed]
aws_rds_cluster_instance.db[2]: Still creating... [15m50s elapsed]
aws_rds_cluster_instance.db[1]: Still creating... [15m50s elapsed]
aws_rds_cluster_instance.db[2]: Creation complete after 15m54s [id=myservice-2]
aws_rds_cluster_instance.db[1]: Creation complete after 15m55s [id=myservice-1]

Apply complete! Resources: 30 added, 0 changed, 0 destroyed.

Outputs:

myservice = "myservice.mydomain.io"
myservice_db = "myservice-db.mydomain.io"
myservice_db_name = "myservice"
myservice_db_password = "4208magicJRfnvz"
myservice_db_reader = "myservice-db-reader.mydomain.io"
myservice_db_username = "myservice"
myservice_ec2 = "myservice-ec2.mydomain.io"
```
