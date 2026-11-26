"""Key management and secrets checks."""
import re

from scanner.checks.base import Check

SECRET_NAME = re.compile(r"pass(word)?|secret|token|api[-_]?key|credential", re.IGNORECASE)


class KmsKeyRotation(Check):
    id = "KMS-001"
    title = "KMS customer-managed key does not rotate automatically"
    severity = "medium"
    service = "kms"
    cis_ref = "CIS 3.6"
    description = ("Automatic rotation limits how much data one key version protects and how "
                   "long a leaked key stays useful. Applies to customer-managed symmetric keys; "
                   "AWS-managed keys rotate automatically.")
    recommendation = "Enable automatic key rotation on the key."

    def evaluate(self):
        kms = self.aws.client("kms")
        # Keys behind an "alias/aws/..." alias are AWS-managed by definition (the
        # emulator sometimes reports them as CUSTOMER, so check both).
        aws_managed = {a.get("TargetKeyId") for page in kms.get_paginator("list_aliases").paginate()
                       for a in page["Aliases"] if a["AliasName"].startswith("alias/aws/")}
        for page in kms.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                if key["KeyId"] in aws_managed:
                    continue
                meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if (meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled"
                        or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"):
                    continue  # rotation only applies to enabled customer symmetric keys
                if kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]:
                    yield self.passed(key["KeyId"], "AWS::KMS::Key", "Rotation enabled")
                else:
                    yield self.failed(key["KeyId"], "AWS::KMS::Key", "Rotation disabled")


class SecretsManagerRotation(Check):
    id = "SEC-001"
    title = "Secrets Manager secret has no automatic rotation"
    severity = "medium"
    service = "secretsmanager"
    cis_ref = "n/a (AWS FSBP SecretsManager.1)"
    description = "A secret that never changes stays valid forever if it leaks."
    recommendation = "Configure automatic rotation with a rotation Lambda function."

    def evaluate(self):
        sm = self.aws.client("secretsmanager")
        for page in sm.get_paginator("list_secrets").paginate():
            for secret in page["SecretList"]:
                if secret.get("RotationEnabled"):
                    yield self.passed(secret["Name"], "AWS::SecretsManager::Secret", "Rotation enabled")
                else:
                    yield self.failed(secret["Name"], "AWS::SecretsManager::Secret", "Rotation disabled")


class PlaintextSecretParameter(Check):
    id = "SSM-001"
    title = "Secret-looking SSM parameter is stored as plain text"
    severity = "high"
    service = "ssm"
    cis_ref = "n/a (custom)"
    description = ("Parameters whose names look like passwords, tokens or keys should be "
                   "SecureString (encrypted with KMS). A plain String is readable by anyone "
                   "with ssm:GetParameter and shows up in console screens.")
    recommendation = "Recreate the parameter as type SecureString and rotate the value."

    def evaluate(self):
        ssm = self.aws.client("ssm")
        for page in ssm.get_paginator("describe_parameters").paginate():
            for param in page["Parameters"]:
                if not SECRET_NAME.search(param["Name"]):
                    continue
                if param.get("Type") == "SecureString":
                    yield self.passed(param["Name"], "AWS::SSM::Parameter", "SecureString")
                else:
                    yield self.failed(param["Name"], "AWS::SSM::Parameter", f"Type {param.get('Type')}")


CHECKS = [KmsKeyRotation, SecretsManagerRotation, PlaintextSecretParameter]
