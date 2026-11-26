# Running on an AWS emulator (demo mode)

## Why
The project's AWS account is a member of an AWS Organization whose **service control
policies** (SCPs) deny EC2, SSM, CloudTrail, SNS, EventBridge, Lambda, Config, GuardDuty,
Security Hub and Access Analyzer, even read-only, for every user including root. Only the
organization's management account can change that. So the lab runs on
[moto](https://github.com/getmoto/moto), an open-source emulator of the AWS APIs that runs
on your own computer.

## What is real and what is emulated

| Part | In demo mode |
|---|---|
| Terraform (`terraform/target`, `terraform/monitoring`) | **The same code** that deploys to real AWS, applied to the emulator with `use_emulator=true` (68 resources, incl. 11 detection rules as EventBridge rules / metric filters / alarms) |
| Scanner checks (`scanner/`) | **The same boto3 code** as live mode; only the endpoint differs |
| Detection rules and engine (`detection/`) | Same rule files and engine. On real AWS the event/threshold rules also run natively in EventBridge and CloudWatch |
| CloudTrail records | **Simulated.** The emulator does not record API calls, so `simulation/` writes the record CloudTrail would have written for each action into `/cspm/cloudtrail`. Every such record has `"cspmSimulated": true` and the user agent `cspm-simulation` |
| VPC Flow Log records | **Simulated** by the `ssh_bruteforce` scenario (same format as real flow logs) |
| Attacker actions | Real API calls against the emulator (security group really opened, bucket really made public, user really created) |
| Prowler | Not run (it needs real AWS) |

## Emulator limitations found (and how they are handled)

| Limitation | Handling |
|---|---|
| CloudTrail `CreateTrail` from Terraform's Go SDK fails in moto | `aws_cloudtrail` has `count = 0` in emulator mode; `python -m lab up` creates the identical trail with boto3 |
| Budgets notification APIs not implemented | Budget skipped in emulator mode (an emulator has no bill) |
| Security Hub `UpdateSecurityHubConfiguration` not implemented | Security Hub stays off (it is also off by default on real AWS) |
| AWS-managed KMS key `aws/ebs` reported as customer-managed | KMS-001 also treats keys behind `alias/aws/*` as AWS-managed (correct on real AWS too) |
| Account ID is always `123456789012`, root MFA always "off" | Expected scanner findings in demo mode; documented |
| State is in memory | `python -m lab up` after a restart redeploys everything (~2 min) |

## Switching to real AWS
Set `CSPM_MODE=live` in `.env`, configure the `cspm-lab` profile, and run Terraform yourself
(`terraform plan`, then `apply` on purpose). The scanner, detection engine and simulation
work unchanged; the simulator no longer writes CloudTrail records because real CloudTrail does.
