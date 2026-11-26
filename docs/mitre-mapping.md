# Detection rules mapped to MITRE ATT&CK (Cloud)

Generated from `detection/rules/*/rule.yaml` by `python -m detection mitre-doc`.

| Rule | Name | Severity | Type | MITRE technique | Tactic | Frequency |
|---|---|---|---|---|---|---|
| DET-010 | Bulk resource deletion | high | threshold | [T1485](https://attack.mitre.org/techniques/T1485) Data Destruction | Impact | every 5 minutes (CloudWatch metric filter + alarm) |
| DET-006 | Console login without MFA | high | event | [T1078.004](https://attack.mitre.org/techniques/T1078/004) Valid Accounts: Cloud Accounts | Initial Access | real-time (EventBridge) |
| DET-007 | Repeated failed console logins | high | threshold | [T1110](https://attack.mitre.org/techniques/T1110) Brute Force | Credential Access | every 5 minutes (CloudWatch metric filter + alarm) |
| DET-003 | AdministratorAccess granted | critical | event | [T1098.003](https://attack.mitre.org/techniques/T1098/003) Account Manipulation: Additional Cloud Roles | Persistence, Privilege Escalation | real-time (EventBridge) |
| DET-004 | New IAM user or access key created | medium | event | [T1136.003](https://attack.mitre.org/techniques/T1136/003) Create Account: Cloud Account (and T1098.001 Additional Cloud Credentials) | Persistence | real-time (EventBridge) |
| DET-005 | Root account used | critical | event | [T1078.004](https://attack.mitre.org/techniques/T1078/004) Valid Accounts: Cloud Accounts | Initial Access, Persistence | real-time (EventBridge) |
| DET-002 | S3 bucket public access protection changed | critical | event | [T1530](https://attack.mitre.org/techniques/T1530) Data from Cloud Storage | Collection | real-time (EventBridge) |
| DET-009 | Secret read from a new IP address | medium | new_value | [T1555.006](https://attack.mitre.org/techniques/T1555/006) Credentials from Password Stores: Cloud Secrets Management Stores | Credential Access | on each engine run (Python engine only; CloudWatch has no first-seen logic) |
| DET-008 | Spike in secret reads | high | threshold | [T1555.006](https://attack.mitre.org/techniques/T1555/006) Credentials from Password Stores: Cloud Secrets Management Stores | Credential Access | every 5 minutes (CloudWatch metric filter + alarm) |
| DET-001 | Security group opened to the internet | high | event | [T1562.007](https://attack.mitre.org/techniques/T1562/007) Impair Defenses: Disable or Modify Cloud Firewall | Defense Evasion | real-time (EventBridge) |
| DET-011 | SSH brute-force attempt | high | flowlog_threshold | [T1110.001](https://attack.mitre.org/techniques/T1110/001) Brute Force: Password Guessing | Credential Access | every 5 minutes (CloudWatch metric filter + alarm) |
