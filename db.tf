# Create DB Password
#
resource "random_string" "rds_password" {
  length  = "16"
  special = "false"
}

# Create DB Security Group
#
resource "aws_security_group" "db" {
  name        = "myservice-db"
  description = "myservice-db"
  vpc_id      = local.vpc_id

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
    Name = "myservice-db"
  }
}

# Create DB Subnet Group
#
resource "aws_db_subnet_group" "db" {
  name        = "myservice"
  description = "myservice"
  subnet_ids  = local.internal_subnet_ids

  tags = {
    Name = "myservice"
  }
}

# Create DB Parameter Groups
#
resource "aws_rds_cluster_parameter_group" "db" {
  name   = "myservice"
  family = "aurora-postgresql11"
}

resource "aws_db_parameter_group" "db" {
  name   = "myservice"
  family = "aurora-postgresql11"
}

# Create DB Cluster
#
resource "aws_rds_cluster" "db" {
  engine                          = "aurora-postgresql"
  engine_version                  = "11.9"
  cluster_identifier              = "myservice"
  master_username                 = replace("myservice", "-", "")
  master_password                 = random_string.rds_password.result
  database_name                   = replace("myservice", "-", "")
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.db.id
  vpc_security_group_ids          = [aws_security_group.db.id]
  db_subnet_group_name            = aws_db_subnet_group.db.id
  backup_retention_period         = 7
  skip_final_snapshot             = true

  tags = {
    Name = "myservice"
  }
}

# Create DB Instances
#
resource "aws_rds_cluster_instance" "db" {
  count                   = local.myservice_db_instance_count
  identifier              = "myservice-${count.index}"
  cluster_identifier      = aws_rds_cluster.db.id
  db_subnet_group_name    = aws_db_subnet_group.db.id
  db_parameter_group_name = aws_db_parameter_group.db.id
  instance_class          = local.myservice_db_instance_class
  engine                  = "aurora-postgresql"
  engine_version          = "11.9"
  apply_immediately       = true
}

# Create DB DNS Entries
#
resource "aws_route53_record" "myservice_db" {
  zone_id = local.zone_id
  name    = "myservice-db"
  type    = "CNAME"
  ttl     = 300

  records = [aws_rds_cluster.db.endpoint]
}

resource "aws_route53_record" "myservice_db_reader" {
  zone_id = local.zone_id
  name    = "myservice-db-reader"
  type    = "CNAME"
  ttl     = 300

  records = [aws_rds_cluster.db.reader_endpoint]
}