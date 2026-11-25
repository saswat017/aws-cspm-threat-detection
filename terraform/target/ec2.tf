# -----------------------------------------------------------------------------
# One small Linux server (Amazon Linux 2023, t3.micro, free tier).
# -----------------------------------------------------------------------------

# Look up the latest Amazon Linux 2023 image ID from AWS's public SSM
# parameter, so no hard-coded AMI ID goes out of date.
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_instance" "app" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  # Off by default: public IPv4 addresses are billed.
  associate_public_ip_address = var.assign_public_ip

  # t3 instances are EBS-optimized at no extra cost; stated explicitly.
  ebs_optimized = true

  # Detailed (1-minute) monitoring is a paid feature; basic is free.
  monitoring = false

  # IMDSv2 only. Blocks the SSRF-style credential theft that IMDSv1 allows.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # Encrypted root disk using the free AWS-managed key (aws/ebs).
  # 8 GiB gp3 stays well inside the 30 GiB free-tier allowance.
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 8
    encrypted             = true
    delete_on_termination = true
  }

  tags = { Name = "${local.name}-app-server" }
}
