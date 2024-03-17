# MyService Terraform 
### A Terraform configuration set that deploys an EC2 instance, ALB load balancer, Aurora RDS database, security groups, builds AMIs and provisions an ACM Certificate.

## Required local variables in variables.tf

- **`vpc_id`**: The ID of the VPC where resources will be provisioned.
- **`domain`**: The domain name for myservice endpoints within Route 53.
- **`zone_id`**: The Hosted Zone ID for the specified domain in Route 53, used for DNS record management.
- **`my_ip`**: Your local outbound public IP to add to security groups.

- **`public_subnet_ids`**: A list of subnet IDs for public-facing resources within the VPC.
- **`private_subnet_ids`**: A list of subnet IDs for private resources without direct internet access.
- **`internal_subnet_ids`**: A list of subnet IDs for internal resources accessible from the private subnets.

- **`myservice_key_name`**: The key pair name already in AWS for SSH access to the myservice instance (optional unless enabled in ec2.tf).
- **`myservice_key_pub`**: The key pair public key to create in AWS for SSH access to the myservice instance (default setting in ec2.tf).
- **`myservice_instance_type`**: The EC2 instance type for the myservice application.
- **`myservice_db_instance_class`**: The database instance class for the myservice database.
- **`myservice_db_instance_count`**: The number of database instances for myservice.

## Building the MyService AMI

### To build the MyService AMI using the `myservice.pkr.hcl` file run (v1.10.2): 
```
./bin/build-image myservice 20240316.01
```

## Usage

- 1. Update the variables.tf file with correct and valid values (see list above).
- 2. Determine if you need either/both pub and priv ALBs and adjust alb.tf and ec2.tf accordingly (including DNS at bottom).
- 3. Update ec2.tf with your actual AWS account on line 151 and confirm you want to create new or use existing key.
- 4. Update myservice.pkr.hcl with a public subnet on line 44 and with any commands needed
- 5. Run the `./bin/build-image myservice 20240317.01` command to create a new AMI with Packer
- 6. Run `terraform apply` and it should end up creating 30 resources (as currently configured).

## Compatibility

| Name | Version |
|------|---------|
| terraform | >= 1.7.5 |
| packer | >= 1.10.2 |
| aws | >= 5.41.0 |

## Sample `terraform apply` and `terraform destroy` Output with 30 total resources

| Command | Sample Output |
|---------|---------------|
| apply   | [SAMPLE_TF_APPLY.md](SAMPLE_TF_APPLY.md) |
| destroy | [SAMPLE_TF_DESTROY.md](SAMPLE_TF_DESTROY.md) |