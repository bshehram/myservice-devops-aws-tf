output "myservice" {
  value = aws_route53_record.myservice.fqdn
}

output "myservice_ec2" {
  value = aws_route53_record.myservice_ec2.fqdn
}

output "myservice_db" {
  value = aws_route53_record.myservice_db.fqdn
}

output "myservice_db_name" {
  value = aws_rds_cluster.db.database_name
}

output "myservice_db_password" {
  value = random_string.rds_password.result
}

output "myservice_db_reader" {
  value = aws_route53_record.myservice_db_reader.fqdn
}

output "myservice_db_username" {
  value = aws_rds_cluster.db.master_username
}
