# Module 1: Target environment

The "company" environment that the rest of the project protects. Everything is free-tier.

| Resource | Secure-by-default setting |
|---|---|
| VPC + 1 public subnet | No automatic public IPs; default security group has no rules (CIS 5.4) |
| Security group `cspm-lab-app-sg` | **No inbound rules**; outbound HTTPS only |
| EC2 `cspm-lab-app-server` (t3.micro, Amazon Linux 2023) | No public IP, IMDSv2 required, encrypted 8 GiB gp3 root disk |
| S3 bucket `cspm-lab-data-<random>` | All 4 Block Public Access settings, ACLs disabled, SSE-S3 encryption, versioning, HTTPS-only policy, 30-day old-version expiry |
| IAM role `cspm-lab-app-role` | Least privilege: only the lab bucket and the lab parameter |
| SSM parameter `/cspm-lab/db-password` | SecureString encrypted with the AWS-managed `aws/ssm` key |

## Free-tier substitutions

| Original idea | Free replacement | Effect on the project |
|---|---|---|
| KMS customer-managed key (~$1/month) | AWS-managed keys (`aws/ebs`, SSE-S3, `aws/ssm`) | Data is still encrypted at rest. The scanner's KMS-rotation check reports that there are no customer keys to check. |
| Secrets Manager secret (~$0.40/month) | SSM Parameter Store SecureString (standard tier) | Still encrypted, and every read is logged in CloudTrail, so access-spike detection works. |
| Public IPv4 address (~$3.60/month) | No public IP (`assign_public_ip = false`) | The instance cannot be reached from, or reach, the internet. Switch it on for a few hours only if you need real SSH traffic for a demo. |

## Accepted risks (pre-deployment Checkov results)

Checkov on this folder: **75 passed, 7 failed**. The failures are deliberate:

| Check | Why it is accepted |
|---|---|
| CKV2_AWS_11 VPC flow logs | Added by the monitoring module (Module 2), not here |
| CKV_AWS_126 EC2 detailed monitoring | Paid feature; basic 5-minute metrics are enough for a lab |
| CKV_AWS_337 SSM parameter with KMS CMK | A customer-managed key costs ~$1/month; the AWS-managed key still encrypts it |
| CKV_AWS_145 S3 encrypted with KMS | Same reason; SSE-S3 (AES-256) is used instead |
| CKV_AWS_18 S3 access logging | Needs a second bucket and adds storage; CloudTrail already records management events |
| CKV2_AWS_62 S3 event notifications | Not needed for this project's use case |
| CKV_AWS_144 S3 cross-region replication | Doubles storage cost; not needed for lab data |

These pre-deployment results are a baseline. The point of this project is what happens **after** deployment, when someone changes these settings by hand in the console.
