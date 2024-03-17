terraform {
  required_version = ">= 1.7.5"

  #   backend "s3" {
  #     bucket         = "your-terraform-state-bucket" # Replace with your S3 bucket name
  #     key            = "path/to/your/state/file"     # Path within the bucket to your state file
  #     region         = "us-west-2"                   # AWS region for the S3 bucket
  #     encrypt        = true                          # Enable encryption at rest
  #     dynamodb_table = "your-lock-table"             # DynamoDB table for state locking, replace with your table name
  #   }

  backend "local" {
    path = "./terraform.tfstate" # Path to your local state file
  }

}

provider "aws" {
  region = "us-west-2" # Your preferred AWS region
}
