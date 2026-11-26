# Project plan and decisions

**Project:** Continuous Security Posture Assessment and Threat Detection for AWS Cloud Infrastructure.
Runtime security of live AWS infrastructure (drift, console changes). **No auto-remediation**:
assess, detect, alert and report only.

## Ground rules
- Personal AWS account, **free tier only** (target: $0). Region `us-east-1`.
- Python 3.11+, boto3 with the named profile `cspm-lab`. No secrets in the repo.
- Terraform (aws provider ~> 6.0). Local state per folder, gitignored.
- **Never run `terraform apply`, `terraform destroy`, simulations, or anything that changes AWS
  without asking the owner first.** Read-only commands (`plan`, `describe`, scans) are fine.
- Build one module at a time (1 -> 6). After each: what was built, what to run, how to verify.
- Simple, well-commented code: it is explained in a viva.

## Modules and status
| # | Module | Folder | Status |
|---|---|---|---|
| 1 | Target environment | `terraform/target/` | Done, deployed to emulator |
| 2 | Monitoring foundation | `terraform/monitoring/` | Done, deployed to emulator |
| 3 | Posture scanner | `scanner/` | Done (24 checks, score, diff, Prowler in live mode) |
| 4 | Threat detection | `detection/` + `terraform/monitoring/detections.tf` | Done (11 rules, engine) |
| 5 | Attack simulation | `simulation/` | Done (9 scenarios, revert, MTTD) |
| 6 | Dashboard and reports | `dashboard/` + `scanner report` | Next: Streamlit dashboard with controls, HTML report |

## Decisions made
0. **Emulator (demo mode).** The real AWS accounts are blocked by AWS Organizations SCPs, so the
   lab runs on moto (`python -m lab up`), with `CSPM_MODE=demo|live`. Same Terraform and Python
   code in both modes; in demo mode the simulator writes marked CloudTrail/flow-log records.
   Details: `docs/emulator.md`. Simulations are Python (boto3), not AWS CLI scripts, so they run
   on Windows and in both modes.
1. **Free substitutions:** no KMS customer key (AWS-managed keys), no Secrets Manager (SSM
   Parameter Store SecureString), no public IPv4 (`assign_public_ip = false`). See
   `docs/target-environment.md`.
2. **Instance access:** no inbound rules at all; nobody needs to log in.
3. **Module 2:** CloudWatch log group (14-day retention), CloudTrail (multi-region, management
   events) to S3 + CloudWatch Logs, VPC Flow Logs (reads the VPC ID via `terraform_remote_state`
   from `terraform/target`), SNS email topic, AWS Budget alert at **$1**. GuardDuty and Security
   Hub behind variables `enable_guardduty` / `enable_securityhub`, **default false** (Security Hub
   CIS needs AWS Config, which costs money).
4. **Detection rules (Module 4):** one folder per rule in `detection/rules/<name>/` with
   `rule.yaml` (name, severity, description, MITRE ATT&CK ID, frequency, `type`) plus either
   `pattern.json` (EventBridge) or `filter.txt` (CloudWatch metric filter + alarm). Logs Insights
   `query.sql` files are for hunting and the dashboard. Terraform loads rules with `fileset()` +
   `yamldecode()`, so adding a folder adds a detection.
5. **MTTD:** every detection also writes to the log group `/security/alerts` (EventBridge target;
   alarm state changes routed via EventBridge). The dashboard matches `simulation/log.json`
   timestamps to the first alert per rule.
6. **Posture score:** checks emit PASS and FAIL. Weights critical 10, high 5, medium 2, low 1.
   `score = 100 * (1 - failed_weight / evaluated_weight)`.
7. **Drift:** `scanner diff` keys findings by `check_id + resource_id` and lists new vs. resolved
   between the last two scans in `results/`.
8. **Expected scanner findings by design:** "user with AdministratorAccess" / "user without MFA"
   for the lab admin user `cspm-admin` (accepted risk for a solo lab account), and "no customer
   KMS keys to check".

## Owner's setup
- Windows laptop, VS Code. AWS CLI profile `cspm-lab` (account blocked by SCPs, see above).
- Demo: `python -m lab up`, then the demo script in README.md.
