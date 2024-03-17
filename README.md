# MyService Terraform configuration that deploys an EC2 instance, ALB load balancer, Aurora RDS database, security groups, builds AMIs and provisions an ACM Certificate

## Local required variables in variables.tf

- **`vpc_id`**: The ID of the VPC where resources will be provisioned.
- **`domain`**: The domain name for myservice endpoints within Route 53.
- **`zone_id`**: The Hosted Zone ID for the specified domain in Route 53, used for DNS record management.
- **`public_subnet_ids`**: A list of subnet IDs for public-facing resources within the VPC.
- **`private_subnet_ids`**: A list of subnet IDs for private resources without direct internet access.
- **`internal_subnet_ids`**: Subnets typically used for backend services or management layers within the VPC.
- **`myservice_key_name`**: The key pair name for SSH access to the myservice instance.
- **`myservice_instance_type`**: The EC2 instance type for the myservice application.
- **`myservice_db_instance_class`**: The database instance class for the myservice database.
- **`myservice_db_instance_count`**: The number of database instances for myservice.

## Building the MyService AMI

### In the images folder there is a script to build an AMI using the Packer json configuration, example: `./bin/build-image myservice 20240316.01`
