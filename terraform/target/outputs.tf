# Names and IDs used by the scanner, simulation scripts and monitoring module.

output "aws_region" {
  value = var.aws_region
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "subnet_id" {
  value = aws_subnet.public.id
}

output "app_security_group_id" {
  value = aws_security_group.app.id
}

output "instance_id" {
  value = aws_instance.app.id
}

output "instance_public_ip" {
  description = "Empty unless assign_public_ip = true."
  value       = aws_instance.app.public_ip
}

output "bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "instance_role_name" {
  value = aws_iam_role.app.name
}

output "secret_parameter_name" {
  value = aws_ssm_parameter.db_password.name
}
