variable "aws_region" {
  description = "AWS region for every resource in the lab."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "Named AWS CLI profile used for authentication (no keys in code)."
  type        = string
  default     = "cspm-lab"
}

variable "project_name" {
  description = "Prefix used in resource names and the Project tag."
  type        = string
  default     = "cspm-lab"
}

variable "vpc_cidr" {
  description = "Address range of the lab VPC."
  type        = string
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  description = "Address range of the single public subnet."
  type        = string
  default     = "10.20.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance size. t3.micro is free-tier eligible."
  type        = string
  default     = "t3.micro"
}

variable "assign_public_ip" {
  description = <<-EOT
    Give the EC2 instance a public IPv4 address. Default false because AWS
    bills public IPv4 addresses. Without one the instance has no internet
    access, which is fine: nobody needs to log in to it for this project.
  EOT
  type        = bool
  default     = false
}

variable "use_emulator" {
  description = <<-EOT
    true = deploy into the local AWS emulator (moto) instead of real AWS.
    Used because the lab AWS account is restricted by an AWS Organizations
    service control policy. The same code deploys to real AWS when false.
  EOT
  type        = bool
  default     = false
}

variable "emulator_endpoint" {
  description = "URL of the local AWS emulator (moto_server)."
  type        = string
  default     = "http://127.0.0.1:5001"
}
