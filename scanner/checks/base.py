"""Base class for every custom check.

A check is a small class with its metadata (id, title, severity, CIS
reference, description, recommendation) and an `evaluate()` method that
inspects AWS and yields findings. It only reads: List/Get/Describe calls.
"""
from botocore.exceptions import ClientError

from scanner.models import Finding


class Check:
    id = ""
    title = ""
    severity = "medium"
    service = ""
    cis_ref = "n/a"
    description = ""
    recommendation = ""

    def __init__(self, aws):
        self.aws = aws              # common.aws.AwsContext
        self.region = aws.region

    # --- helpers used by subclasses -----------------------------------
    def finding(self, status, resource_id, resource_type, evidence=""):
        return Finding(
            check_id=self.id, title=self.title, severity=self.severity,
            status=status, resource_id=resource_id, resource_type=resource_type,
            region=self.region, service=self.service, cis_ref=self.cis_ref,
            description=self.description, recommendation=self.recommendation,
            evidence=evidence)

    def passed(self, resource_id, resource_type, evidence=""):
        return self.finding("PASS", resource_id, resource_type, evidence)

    def failed(self, resource_id, resource_type, evidence=""):
        return self.finding("FAIL", resource_id, resource_type, evidence)

    # --- entry point ----------------------------------------------------
    def evaluate(self):
        """Yield findings. Implemented by each check."""
        raise NotImplementedError

    def run(self):
        """Run the check; turn AWS errors into an ERROR finding, never a crash."""
        try:
            return list(self.evaluate())
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            return [self.finding("ERROR", "n/a", self.service,
                                 f"Could not evaluate: {code}. "
                                 "Check the scanner's IAM permissions.")]
        except Exception as e:  # emulator gaps, network problems, ...
            return [self.finding("ERROR", "n/a", self.service,
                                 f"Could not evaluate: {type(e).__name__}: {e}")]
