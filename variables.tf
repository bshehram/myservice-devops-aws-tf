locals {
  vpc_id  = "vpc-42069a"     # The ID of the VPC to provision the resources in 
  domain  = "example.com"    # The domain name in Route 53 to use for myservice endpoints
  zone_id = "HZ420696969"    # The hosted zone ID for the domain in Route 53
  my_ip   = "192.168.0.0/32" # Your local public IP address

  public_subnet_ids   = ["subnet-42069a", "subnet-456def", "subnet-101112", "subnet-131415"] # The IDs of the public subnets in the vpc
  private_subnet_ids  = ["subnet-789ghi", "subnet-012jkl", "subnet-161718", "subnet-192021"] # The IDs of the private subnets in the vpc
  internal_subnet_ids = ["subnet-345mno", "subnet-678pqr", "subnet-222324", "subnet-252627"] # The IDs of the internal subnets in the vpc

  myservice_key_name          = "myservice"     # The key name used for the myservice instance
  myservice_instance_type     = "t4g.medium"    # The instance type used for the myservice instance
  myservice_db_instance_class = "db.t4g.medium" # The instance class used for the myservice database instance
  myservice_db_instance_count = "3"             # The number of database instances for myservice
}
