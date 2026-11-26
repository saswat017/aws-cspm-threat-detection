"""Registry of every custom check. Add a new module's CHECKS list here."""
from scanner.checks import ec2, iam, kms_secrets, s3, security_groups, services

ALL_CHECKS = (s3.CHECKS + security_groups.CHECKS + ec2.CHECKS
              + kms_secrets.CHECKS + iam.CHECKS + services.CHECKS)
