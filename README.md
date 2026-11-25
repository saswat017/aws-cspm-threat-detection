# Continuous Security Posture Assessment and Threat Detection for AWS

Runtime security for live AWS infrastructure: assess posture, detect drift and threats, alert and
report. There is **no auto-remediation**.

> Work in progress. Modules are added one at a time: 1 target environment, 2 monitoring,
> 3 posture scanner, 4 threat detection, 5 attack simulation, 6 dashboard and reports.

## Prerequisites

- AWS account (free tier), AWS CLI v2, Terraform >= 1.6, Python 3.11+
- A named profile: `aws configure --profile cspm-lab` (or `aws configure sso`)

## Module 1: target environment

See [docs/target-environment.md](docs/target-environment.md) for what gets built and why.

```bash
cp terraform/target/terraform.tfvars.example terraform/target/terraform.tfvars
make init STACK=target
make plan STACK=target                       # read-only preview
terraform -chdir=terraform/target apply tfplan  # creates resources (run on purpose)
```

Tear down when not in use: `terraform -chdir=terraform/target destroy`.
