# MyService Terraform configuration for an AWS account that provisions an EC2 instance, a Public and Private ALB, an Aurora RDS cluster and all related security groups, AMIs and an ACM Certificate

## Local required variables in variables.tf

- **`vpc_id`**: The ID of the VPC where resources will be provisioned.

- **`domain`**: The domain name for myservice endpoints within Route 53.

- **`zone_id`**: The Hosted Zone ID for the specified domain in Route 53, used for DNS record management.

- **Public Subnets**: A list of subnet IDs for public-facing resources within the VPC.

- **Private Subnets**: A list of subnet IDs for private resources without direct internet access.

- **Internal Subnets**: Subnets typically used for backend services or management layers within the VPC.

- **`myservice_key_name`**: The key pair name for SSH access to the myservice instance.

- **`myservice_instance_type`**: The EC2 instance type for the myservice application.

- **`myservice_db_instance_class`**: The database instance class for the myservice database.

- **`myservice_db_instance_count`**: The number of database instances for myservice.

