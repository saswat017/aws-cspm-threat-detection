# -----------------------------------------------------------------------------
# Network: one VPC with one public subnet. No NAT Gateway (it costs money).
# The internet gateway itself is free and only matters if assign_public_ip is
# switched on.
# -----------------------------------------------------------------------------

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name}-vpc" }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-igw" }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidr
  availability_zone = "${var.aws_region}a"

  # Secure default: instances do NOT get a public IP automatically.
  map_public_ip_on_launch = false

  tags = { Name = "${local.name}-public-subnet" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "${local.name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# CIS AWS Foundations 5.4: the VPC's default security group must allow no
# traffic. Terraform "adopts" the default group and removes all its rules.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-default-sg-locked" }
}

# Security group for the workload instance.
# No inbound rules at all: nothing on the internet can connect to it.
# Outbound is limited to HTTPS (for OS updates, if a public IP is added).
resource "aws_security_group" "app" {
  name        = "${local.name}-app-sg"
  description = "Lab app server: no inbound, HTTPS outbound only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-app-sg" }
}

resource "aws_vpc_security_group_egress_rule" "https_out" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS outbound for package updates"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}
