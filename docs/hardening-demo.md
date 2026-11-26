# Demo: fix findings by hand and watch the score go up

The system never fixes anything itself (no auto-remediation). Here **you**, the defender,
act on the scanner's recommendations with the AWS CLI, and each new scan shows the score rising.
Tested in the emulator: **85.2 -> 88.2 -> 91.1 -> 92.3 -> 93.5 -> 94.1**.

## 0. Setup (Windows PowerShell, lab running with `python -m lab up`)

```powershell
# Dummy keys for the emulator. If you forget --endpoint-url, real AWS rejects these keys,
# so nothing can reach a real account by accident.
$env:AWS_ACCESS_KEY_ID = "testing"
$env:AWS_SECRET_ACCESS_KEY = "testing"
$env:AWS_DEFAULT_REGION = "us-east-1"

# Shortcut: "awslab" = the AWS CLI pointed at the local emulator
function awslab { aws --endpoint-url http://127.0.0.1:5001 @args }

python -m scanner scan          # baseline: 85.2, 6 findings
```

## 1. IAM-003 (high): the admin user should not have AdministratorAccess

```powershell
awslab iam detach-user-policy --user-name cspm-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
awslab iam attach-user-policy --user-name cspm-admin --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
python -m scanner scan          # 88.2
```

## 2. SVC-002 (high): turn on GuardDuty

```powershell
awslab guardduty create-detector --enable
python -m scanner scan          # 91.1
```
*Infrastructure-as-code alternative:* `enable_guardduty = true` in `terraform/monitoring`.

## 3. SVC-003 (medium): turn on Security Hub

```powershell
awslab securityhub enable-security-hub
python -m scanner scan          # 92.3
```

## 4. SVC-004 (medium): flow logs for the default VPC

```powershell
$vpc = awslab ec2 describe-vpcs --filters Name=is-default,Values=true --query "Vpcs[0].VpcId" --output text
awslab ec2 create-flow-logs --resource-type VPC --resource-ids $vpc --traffic-type ALL `
  --log-destination-type cloud-watch-logs --log-group-name /cspm/vpc-flow-logs `
  --deliver-logs-permission-arn arn:aws:iam::123456789012:role/cspm-lab-flow-logs
python -m scanner scan          # 93.5
```

## 5. SG-005 (low): the default security group should allow nothing

```powershell
$sg = awslab ec2 describe-security-groups --filters Name=vpc-id,Values=$vpc Name=group-name,Values=default --query "SecurityGroups[0].GroupId" --output text
awslab ec2 revoke-security-group-egress --group-id $sg --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
python -m scanner scan          # 94.1
```

## 6. Show the result

```powershell
python -m scanner diff --back 5   # baseline vs now: 5 RESOLVED, score +8.9
python -m scanner report          # HTML report with the trend
```
In the dashboard: the Overview chart shows the score climbing; on the **Drift** tab choose
the baseline scan in "Compare the latest scan with".

## What cannot be fixed in the emulator

**IAM-001 root MFA (critical):** the emulator has no real root user, so it always reports
root MFA as off. On a real account this is fixed in the console (Security credentials ->
Assign MFA device); the project owner did this on the real account (screenshot).

## Notes

- `python -m lab reset` (or restarting the emulator) rebuilds the lab and undoes these fixes.
- In the emulator, the AWS CLI changes do not create CloudTrail records (only the simulator
  writes those), so these fixes show up in the scanner, not as alerts.
