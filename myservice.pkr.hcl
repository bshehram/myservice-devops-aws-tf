packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "~> 1"
    }
  }
}

variable "source_ip" {
  type = string
}

variable "version" {
  type = string
}

data "amazon-ami" "myservice" {
  filters = {
    name = "amzn2-ami-hvm-*-arm64-gp2"
  }

  most_recent = true
  owners      = ["amazon"]
  region      = "us-west-2"
}

source "amazon-ebs" "myservice" {
  ami_description = "myservice-${var.version}"
  ami_name        = "myservice-${var.version}"
  instance_type   = "t4g.medium"

  launch_block_device_mappings {
    delete_on_termination = true
    device_name           = "/dev/xvda"
    volume_size           = 10
    volume_type           = "gp2"
  }

  region        = "us-west-2"
  source_ami    = "${data.amazon-ami.myservice.id}"
  ssh_interface = "public_ip"
  ssh_username  = "ec2-user"
  subnet_id     = "subnet-4206942069"

  tags = {
    Name = "myservice-${var.version}"
  }

  temporary_security_group_source_cidrs = ["${var.source_ip}/32"]
}

build {
  sources = ["source.amazon-ebs.myservice"]

  provisioner "shell" {
    inline = ["sudo bash -c \"echo -e '* soft nofile 65535\n* hard nofile 65535' > /etc/security/limits.d/21-nofile.conf\"", "sudo yum groupinstall -y 'Development Tools'", "sudo amazon-linux-extras install -y epel nginx1", "sudo yum upgrade -y", "sudo systemctl enable nginx"]
  }
}


